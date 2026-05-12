// Platform-controlled release pipeline. Teams trigger this but cannot modify it.
// Pure verify + apply — no re-rendering, no re-planning.
//
// Prerequisites:
//   1. Build pipeline completed with tests/v1 and build/v1 attestations on the image.
//   2. Scan pipeline ran with ENVIRONMENT=<target> and produced a scan/v1 attestation
//      containing pre-rendered manifests / terraform plan pushed to Harbor OCI.
//      If scan/v1 with the requested environment is absent, release fails with instructions.
//
// Parameters:
//   UPSTREAM_JOB   — full Jenkins path of the build job that produced artifacts.json
//   UPSTREAM_BUILD — build number, or 'lastSuccessful'
//   ENVIRONMENT    — target environment (must match scan/v1 predicate environment field)

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'deploy-sec-base'
        }
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
    }

    parameters {
        string(name: 'UPSTREAM_JOB',   description: 'Build job path that produced artifacts.json')
        string(name: 'UPSTREAM_BUILD', defaultValue: 'lastSuccessful', description: 'Build number or lastSuccessful')
        string(name: 'ENVIRONMENT',    description: 'Target environment (must match scan/v1 predicate environment field)')
    }

    stages {
        stage('Fetch') {
            steps {
                script {
                    validateJobScope(params.UPSTREAM_JOB)
                    copyArtifacts(
                        projectName:          params.UPSTREAM_JOB,
                        selector:             params.UPSTREAM_BUILD == 'lastSuccessful'
                                                  ? lastSuccessful()
                                                  : specific(params.UPSTREAM_BUILD),
                        filter:               'artifacts.json',
                        fingerprintArtifacts: true
                    )
                }
            }
        }

        stage('Attest Check') {
            steps {
                script { waitForBuildAttestations() }
            }
        }

        stage('Extract Predicate') {
            steps {
                script { extractScanPredicate(params.ENVIRONMENT) }
            }
        }

        stage('Cedar Gate') {
            steps {
                script { checkCedarPromote(params.ENVIRONMENT) }
            }
        }

        stage('Pull and Verify') {
            steps {
                script { pullAndVerifyArtifacts() }
            }
        }

        stage('Sign') {
            steps {
                script { signImages() }
            }
        }

        stage('Deploy') {
            steps {
                script { deploy(params.ENVIRONMENT) }
            }
        }
    }
}

// ---------------------------------------------------------------------------

// Calls Cedar Promote action and fails the build on an explicit DENY.
// Collects attestation types present on the image and scan age from scan-predicate.json,
// then asks Cedar whether promoting to this environment is permitted.
// Hard failure if the Cedar sidecar is unreachable or returns DENY.
private void checkCedarPromote(String environment) {
    def log = { String msg -> echo "[Platform:cedar] ${msg}" }

    def images   = readJSON(file: 'artifacts.json').builds
    if (!images) error('artifacts.json contains no builds')
    def imageRef = images[0].tag

    // Determine which attestation types are present on the image.
    def knownTypes = [
        'https://tuxgrid.com/attestation/build/v1',
        'https://tuxgrid.com/attestation/tests/v1',
        'https://tuxgrid.com/attestation/scan/v1',
        'https://tuxgrid.com/attestation/pipeline/v1',
    ]
    def presentTypes = []
    withCredentials([
        string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY'),
        usernamePassword(credentialsId: 'harbor-robot-platform', usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS'),
    ]) {
        container('deploy-sec-base') {
            sh "printf '%s' \"\$COSIGN_PUBLIC_KEY\" > /tmp/cosign.pub"
            sh '''
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p ~/.docker
                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
            '''
            knownTypes.each { t ->
                def rc = sh(script: "cosign verify-attestation --key /tmp/cosign.pub --type '${t}' '${imageRef}' > /dev/null 2>&1 && echo ok || echo fail", returnStdout: true).trim()
                if (rc == 'ok') presentTypes << t
            }
            sh 'rm -f /tmp/cosign.pub ~/.docker/config.json'
        }
    }
    log("Attestation types present: ${presentTypes}")

    // Calculate scan age in seconds from scan-predicate.json timestamp.
    def scanAgeSeconds = 0L
    if (fileExists('scan-predicate.json')) {
        try {
            def predicate  = readJSON(file: 'scan-predicate.json')
            def scanTs     = java.time.Instant.parse(predicate.timestamp as String).toEpochMilli()
            scanAgeSeconds = (System.currentTimeMillis() - scanTs) / 1000L
        } catch (ignored) {}
    }

    // Call Cedar sidecar.
    def cedarUrl = 'http://platform-cedar-sidecar.platform.svc.cluster.local/authorize'
    def payload  = groovy.json.JsonOutput.toJson([
        principal: "TuxGrid::Pipeline::\"${env.TUXGRID_TEAM_SLUG}/${env.JOB_BASE_NAME}\"",
        action:    'TuxGrid::Action::"Promote"',
        resource:  "TuxGrid::Image::\"${imageRef}\"",
        entities:  [],
        context: [
            targetTier:       environment,
            attestationTypes: presentTypes,
            scanAgeSeconds:   scanAgeSeconds,
        ],
    ])

    try {
        def response = new URL(cedarUrl).openConnection().with {
            requestMethod = 'POST'
            doOutput      = true
            connectTimeout = 5000
            readTimeout    = 5000
            setRequestProperty('Content-Type', 'application/json')
            outputStream.write(payload.bytes)
            def code = responseCode
            def body = (code < 400 ? inputStream : errorStream)?.text ?: ''
            [code: code, body: body]
        }
        if (response.code == 200) {
            def result = readJSON(text: response.body)
            if (result.decision == 'DENY') {
                def reasons = result.reasons ? result.reasons.join('; ') : 'policy denied'
                error("[Platform:cedar] Promote to '${environment}' denied: ${reasons}")
            }
            log("Promote to '${environment}' allowed")
        } else {
            error("[Platform:cedar] Cedar sidecar returned HTTP ${response.code} — promote blocked")
        }
    } catch (java.net.ConnectException e) {
        error("[Platform:cedar] Cedar sidecar unreachable — promote blocked")
    }
}

private void validateJobScope(String upstreamJob) {
    def allowedRoot = "teams/${env.TUXGRID_TEAM_SLUG}/"
    if (!upstreamJob.startsWith(allowedRoot)) {
        error("Release refused: '${upstreamJob}' is not within this team's folder '${allowedRoot}'")
    }
}

// Poll until tests/v1 and build/v1 attestations are present and valid.
// scan/v1 is NOT checked here — it is verified in extractScanPredicate() below.
private void waitForBuildAttestations() {
    def images      = readJSON(file: 'artifacts.json').builds
    if (!images) error('artifacts.json contains no builds')

    def imageRef    = images[0].tag
    def pollSecs    = 30
    def timeoutMins = 10
    def deadline    = System.currentTimeMillis() + (timeoutMins * 60 * 1000)
    def types       = [
        'https://tuxgrid.com/attestation/tests/v1',
        'https://tuxgrid.com/attestation/build/v1',
    ]

    echo "Waiting for build attestations on ${imageRef} (timeout: ${timeoutMins} min)..."

    withCredentials([
        string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY'),
        usernamePassword(
            credentialsId:    'harbor-robot-platform',
            usernameVariable: 'HARBOR_USER',
            passwordVariable: 'HARBOR_PASS',
        ),
    ]) {
        container('deploy-sec-base') {
            sh "printf '%s' \"\$COSIGN_PUBLIC_KEY\" > /tmp/cosign.pub"
            sh '''
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p ~/.docker
                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
            '''

            try {
                while (System.currentTimeMillis() < deadline) {
                    def verified = true
                    for (int i = 0; i < types.size(); i++) {
                        def t = types[i]
                        def result = sh(
                            script: "cosign verify-attestation --key /tmp/cosign.pub --type '${t}' '${imageRef}' > /dev/null 2>&1 && echo ok || echo fail",
                            returnStdout: true
                        ).trim()
                        if (result != 'ok') {
                            verified = false
                            break
                        }
                    }

                    if (verified) {
                        echo "tests/v1 and build/v1 attestations verified ✓"
                        return
                    }

                    echo "Attestations not yet present — retrying in ${pollSecs}s..."
                    sleep(pollSecs)
                }
                error("Timed out after ${timeoutMins} minutes waiting for build attestations on ${imageRef}")
            } finally {
                sh 'rm -f /tmp/cosign.pub ~/.docker/config.json'
            }
        }
    }
}

// Verify-download the scan/v1 attestation for the requested environment and write
// the predicate to scan-predicate.json. Fails with actionable instructions if absent.
private void extractScanPredicate(String environment) {
    if (!environment?.trim()) error('ENVIRONMENT parameter is required for release')

    def images   = readJSON(file: 'artifacts.json').builds
    def imageRef = images[0].tag

    echo "Extracting scan/v1 predicate with environment='${environment}' from ${imageRef}..."

    // Write the predicate-finder to the workspace so it is available in all containers.
    writeFile file: 'find_predicate.py', text: '''\
import json, base64, sys

env_arg = sys.argv[1]
data = sys.stdin.read().strip()
if not data:
    print("[Platform] No scan/v1 attestations found on this image", file=sys.stderr)
    sys.exit(1)
for line in data.splitlines():
    if not line.strip():
        continue
    try:
        envelope  = json.loads(line)
        statement = json.loads(base64.b64decode(envelope["payload"] + "=="))
        predicate = statement.get("predicate", {})
        if predicate.get("environment", "") == env_arg:
            with open("scan-predicate.json", "w") as f:
                json.dump(predicate, f)
            print(f"[Platform] Found scan/v1 predicate for environment={env_arg}")
            sys.exit(0)
    except Exception as e:
        print(f"[Platform] Skipping malformed attestation: {e}", file=sys.stderr)
print(f"[Platform] No scan/v1 predicate matched environment={env_arg}", file=sys.stderr)
sys.exit(1)
'''

    withCredentials([
        string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY'),
        usernamePassword(
            credentialsId:    'harbor-robot-platform',
            usernameVariable: 'HARBOR_USER',
            passwordVariable: 'HARBOR_PASS',
        ),
    ]) {
        container('deploy-sec-base') {
            sh "printf '%s' \"\$COSIGN_PUBLIC_KEY\" > /tmp/cosign.pub"
            sh '''
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p ~/.docker
                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
            '''

            def exitCode = sh(
                script: "cosign verify-attestation --key /tmp/cosign.pub --type 'https://tuxgrid.com/attestation/scan/v1' '${imageRef}' 2>/dev/null | python3 find_predicate.py '${environment}'",
                returnStatus: true
            )

            sh 'rm -f /tmp/cosign.pub ~/.docker/config.json find_predicate.py'

            if (exitCode != 0) {
                error("No scan/v1 attestation with environment='${environment}' found on ${imageRef}. " +
                      "Run: platform scan job with ENVIRONMENT=${environment} before releasing.")
            }
        }
    }
}

// Pull pre-rendered artifacts from Harbor OCI refs recorded in scan-predicate.json
// and verify their sha256 digests against the attested values.
private void pullAndVerifyArtifacts() {
    def predicate = readJSON(file: 'scan-predicate.json')

    withCredentials([usernamePassword(
        credentialsId:    'harbor-robot-platform',
        usernameVariable: 'HARBOR_USER',
        passwordVariable: 'HARBOR_PASS',
    )]) {
        container('deploy-sec-base') {
            sh '''
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p ~/.docker
                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
            '''

            try {
                def renderedRef = predicate.render?.rendered_manifest_ref    ?: ''
                def renderedSha = predicate.render?.rendered_manifest_sha256  ?: ''
                if (renderedRef && renderedSha) {
                    withEnv(["RENDERED_REF=${renderedRef}", "EXPECTED_SHA=${renderedSha}"]) {
                        sh '''
                            cosign download blob "$RENDERED_REF" > rendered.yaml
                            ACTUAL=$(sha256sum rendered.yaml | awk '{print $1}')
                            if [ "$ACTUAL" != "$EXPECTED_SHA" ]; then
                                printf "[Platform] FATAL: rendered.yaml sha256 mismatch\\n  expected: %s\\n  actual:   %s\\n" "$EXPECTED_SHA" "$ACTUAL" >&2
                                exit 1
                            fi
                            echo "[Platform] rendered.yaml verified: sha256=${EXPECTED_SHA}"
                        '''
                    }
                }

                def tfplanRef = predicate.plan?.terraform_plan_ref    ?: ''
                def tfplanSha = predicate.plan?.terraform_plan_sha256  ?: ''
                if (tfplanRef && tfplanSha) {
                    withEnv(["TFPLAN_REF=${tfplanRef}", "EXPECTED_SHA=${tfplanSha}"]) {
                        sh '''
                            cosign download blob "$TFPLAN_REF" > tfplan
                            ACTUAL=$(sha256sum tfplan | awk '{print $1}')
                            if [ "$ACTUAL" != "$EXPECTED_SHA" ]; then
                                printf "[Platform] FATAL: tfplan sha256 mismatch\\n  expected: %s\\n  actual:   %s\\n" "$EXPECTED_SHA" "$ACTUAL" >&2
                                exit 1
                            fi
                            echo "[Platform] tfplan verified: sha256=${EXPECTED_SHA}"
                        '''
                    }
                }

                if (!renderedRef && !tfplanRef) {
                    error("scan-predicate.json has no artifact refs — " +
                          "scan pipeline must run with ENVIRONMENT set to produce pre-rendered artifacts")
                }
            } finally {
                sh 'rm -f ~/.docker/config.json'
            }
        }
    }
}

private List getImages() {
    def artifacts = readJSON(file: 'artifacts.json')
    if (!artifacts.builds) error('artifacts.json contains no builds')
    return artifacts.builds
}

private void signImages() {
    def images = getImages()
    withCredentials([
        string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY'),
        usernamePassword(
            credentialsId:    'harbor-robot-platform',
            usernameVariable: 'HARBOR_USER',
            passwordVariable: 'HARBOR_PASS',
        ),
    ]) {
        container('deploy-sec-base') {
            sh '''
                printf '%s' "$COSIGN_PRIVATE_KEY" > /tmp/cosign.key && chmod 600 /tmp/cosign.key
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p ~/.docker
                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
            '''
            for (int i = 0; i < images.size(); i++) {
                withEnv(["IMAGE_REF=${images[i].tag}"]) {
                    sh 'COSIGN_PASSWORD="" cosign sign --key /tmp/cosign.key --yes "$IMAGE_REF"'
                }
            }
            sh 'rm -f /tmp/cosign.key ~/.docker/config.json'
        }
    }
}

private void deploy(String environment) {
    def upper   = environment.toUpperCase()
    def envType = env["TUXGRID_ENV_${upper}_TYPE"] ?: 'kubernetes'

    if (envType == 'aws') {
        deployTerraform(environment)
    } else {
        deployKubernetes(environment)
    }
}

private void deployKubernetes(String environment) {
    def upper     = environment.toUpperCase()
    def cloud     = env["TUXGRID_ENV_${upper}_CLOUD"]
    def namespace = env["TUXGRID_ENV_${upper}_NAMESPACE"]

    if (!cloud) error("No cloud configured for environment '${environment}'. Check team YAML.")
    if (!fileExists('rendered.yaml')) {
        error("rendered.yaml not found — run scan with ENVIRONMENT=${environment} to produce pre-rendered manifests")
    }

    echo "Deploying to '${environment}' — cloud: ${cloud}${namespace ? ", namespace: ${namespace}" : ''}"

    withCredentials([file(credentialsId: "kubeconfig-${cloud}", variable: 'KUBECONFIG')]) {
        container('deploy-sec-base') {
            sh "skaffold apply rendered.yaml${namespace ? " --namespace=${namespace}" : ''}"
        }
    }
}

private void deployTerraform(String environment) {
    def upper   = environment.toUpperCase()
    def roleArn = env["TUXGRID_ENV_${upper}_ROLE_ARN"]

    if (!roleArn) error("No role_arn configured for environment '${environment}'. Check team YAML.")
    if (!fileExists('tfplan')) {
        error("tfplan not found — run scan with ENVIRONMENT=${environment} to produce a pre-approved plan")
    }

    echo "Deploying to AWS '${environment}' via Token Service → terraform apply (pre-approved plan)"

    def payload = groovy.json.JsonOutput.toJson([
        environment: environment,
        role_arn:    roleArn,
    ])

    def credsJson = ''
    container('deploy-sec-base') {
        withEnv(["TOKEN_PAYLOAD=${payload}"]) {
            credsJson = sh(
                script: '''
                    curl -sf -X POST https://token-service.platform.svc.cluster.local/token \
                        -H "Authorization: Bearer $(cat /run/secrets/oidc/token)" \
                        -H "X-K8s-Token: $(cat /run/secrets/kubernetes/token)" \
                        -H 'Content-Type: application/json' \
                        -d "$TOKEN_PAYLOAD"
                ''',
                returnStdout: true
            ).trim()
        }
    }

    def credsMap = readJSON(text: credsJson)
    withEnv([
        "AWS_ACCESS_KEY_ID=${credsMap.AccessKeyId}",
        "AWS_SECRET_ACCESS_KEY=${credsMap.SecretAccessKey}",
        "AWS_SESSION_TOKEN=${credsMap.SessionToken}",
    ]) {
        container('deploy-sec-base') {
            sh """
                set -e
                terraform init -backend-config="key=${env.TUXGRID_TEAM_SLUG}/${environment}/terraform.tfstate"
                terraform apply -auto-approve tfplan
            """
        }
    }
}
