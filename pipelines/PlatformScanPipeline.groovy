// Platform-controlled scan pipeline.
// Gates that must pass before a scan/v1 attestation is created:
//
//   1. Verify        — cosign signature verification (gate — aborts if image is unsigned)
//   2. Trivy Image   — container vulnerability + secret scanning per image in artifacts.json
//   3. Trivy Repo    — IaC misconfiguration + secret scanning of the source repository
//   4. Checkov       — IaC policy checks (terraform, dockerfile, kubernetes, helm, kustomize, github_actions, secrets)
//   5. Render        — skaffold render for ENVIRONMENT (kubernetes envs only; skipped if ENVIRONMENT empty)
//   6. Checkov Rendered — Checkov on the rendered manifest (skipped if no rendered.yaml)
//   7. Terraform Plan — terraform plan for ENVIRONMENT (aws envs only; skipped if no .tf files)
//   8. Checkov Plan  — Checkov on tfplan.json (skipped if no plan)
//   9. Push Artifacts — sha256 + cosign upload blob for rendered.yaml + tfplan.json to Harbor
//  10. SBOM          — SPDX-JSON per image (informational, not a gate)
//
// ENVIRONMENT is optional. Without it, steps 5–9 are skipped and the predicate
// records empty render/plan fields. The build listener triggers this without
// ENVIRONMENT; the release pipeline triggers it with ENVIRONMENT set.
//
// The source repo is cloned once in Fetch and reused by Trivy Repo, Checkov, and Render.

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'deploy-sec-base'
        }
    }

    options {
        timeout(time: 45, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'UPSTREAM_JOB',   description: 'Full job path of the build that produced artifacts.json')
        string(name: 'UPSTREAM_BUILD', description: 'Build number')
        string(name: 'GIT_URL',        description: 'Repository URL for source/IaC scanning')
        string(name: 'GIT_COMMIT',     description: 'Exact commit SHA to scan')
        string(name: 'ENVIRONMENT',    defaultValue: '', description: 'Target environment for render + plan (optional — skips steps 5–9 if empty)')
    }

    stages {
        stage('Fetch') {
            steps {
                script {
                    copyArtifacts(
                        projectName:          params.UPSTREAM_JOB,
                        selector:             specific(params.UPSTREAM_BUILD),
                        filter:               'artifacts.json',
                        fingerprintArtifacts: true
                    )
                    def images = readJSON(file: 'artifacts.json').builds
                    if (!images) error('artifacts.json contains no builds')

                    // Clone once — shared workspace means Trivy Repo and Checkov both
                    // read from scan-src/ without a second clone.
                    if (!(params.GIT_COMMIT ==~ /^[0-9a-f]{40}$/)) {
                        error("GIT_COMMIT is not a valid 40-char SHA: '${params.GIT_COMMIT}'")
                    }
                    withEnv(["GIT_REPO_URL=${params.GIT_URL}", "GIT_REPO_SHA=${params.GIT_COMMIT}"]) {
                        sh '''
                            git clone --depth 1 "$GIT_REPO_URL" scan-src
                            cd scan-src && git checkout "$GIT_REPO_SHA"
                            git verify-commit "$GIT_REPO_SHA" || {
                                echo "[Platform] FATAL: commit $GIT_REPO_SHA has no valid GPG/SSH signature — scan refused"
                                exit 1
                            }
                        '''
                    }
                }
            }
        }

        stage('Verify') {
            steps {
                script {
                    def images = readJSON(file: 'artifacts.json').builds

                    withCredentials([
                        string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY'),
                        usernamePassword(credentialsId: 'harbor-robot-platform',
                                         usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS'),
                    ]) {
                        container('deploy-sec-base') {
                            sh '''
                                printf '%s' "$COSIGN_PUBLIC_KEY" > /tmp/cosign.pub
                                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                                mkdir -p ~/.docker
                                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
                            '''
                            images.each { image ->
                                withEnv(["IMAGE_REF=${image.tag}"]) {
                                    sh 'cosign verify --key /tmp/cosign.pub "$IMAGE_REF"'
                                }
                            }
                            sh 'rm -f /tmp/cosign.pub ~/.docker/config.json'
                        }
                    }

                    echo "Signature verified for ${images.size()} image(s)"
                }
            }
        }

        stage('Trivy Image') {
            steps {
                script {
                    def images = readJSON(file: 'artifacts.json').builds
                    env.TRIVY_IMG_CRITICAL = '0'
                    env.TRIVY_IMG_HIGH     = '0'
                    env.TRIVY_IMG_SECRETS  = '0'

                    container('deploy-sec-base') {
                        images.each { image ->
                            def outFile = "trivy-image-${image.tag.replaceAll('[/:@]', '-')}.json"

                            // --scanners vuln,secret: CVEs + secrets embedded in image layers
                            // --ignore-unfixed: skip CVEs with no available fix (reduces noise)
                            def exitCode = withEnv(["IMAGE_REF=${image.tag}", "OUT_FILE=${outFile}"]) {
                                sh(
                                    script: '''
                                        trivy image \
                                            --exit-code 1 \
                                            --severity HIGH,CRITICAL \
                                            --scanners vuln,secret \
                                            --ignore-unfixed \
                                            --no-progress \
                                            --format json \
                                            --output "$OUT_FILE" \
                                            "$IMAGE_REF"
                                    ''',
                                    returnStatus: true
                                )
                            }

                            if (fileExists(outFile)) {
                                def result = readJSON(file: outFile)
                                result.Results?.each { r ->
                                    r.Vulnerabilities?.each { v ->
                                        if (v.Severity == 'CRITICAL') env.TRIVY_IMG_CRITICAL = (env.TRIVY_IMG_CRITICAL.toInteger() + 1).toString()
                                        if (v.Severity == 'HIGH')     env.TRIVY_IMG_HIGH     = (env.TRIVY_IMG_HIGH.toInteger()     + 1).toString()
                                    }
                                    r.Secrets?.each {
                                        env.TRIVY_IMG_SECRETS = (env.TRIVY_IMG_SECRETS.toInteger() + 1).toString()
                                    }
                                }
                            }

                            if (exitCode != 0) {
                                error("Trivy image scan failed for '${image.tag}': CRITICAL=${env.TRIVY_IMG_CRITICAL}, HIGH=${env.TRIVY_IMG_HIGH}, Secrets=${env.TRIVY_IMG_SECRETS}")
                            }
                        }
                    }

                    echo "Trivy Image: CRITICAL=${env.TRIVY_IMG_CRITICAL}, HIGH=${env.TRIVY_IMG_HIGH}, Secrets=${env.TRIVY_IMG_SECRETS}"
                }
            }
        }

        stage('Trivy Repo') {
            steps {
                script {
                    env.TRIVY_REPO_MISCONFIG_CRITICAL = '0'
                    env.TRIVY_REPO_MISCONFIG_HIGH     = '0'
                    env.TRIVY_REPO_SECRETS            = '0'

                    container('deploy-sec-base') {
                        // Scan source repository for IaC misconfigurations and hardcoded secrets.
                        // misconfig covers: Dockerfile, Terraform, K8s manifests, Helm charts.
                        // secret covers: plaintext credentials committed in any file.
                        def exitCode = sh(
                            script: """
                                trivy fs \
                                    --exit-code 1 \
                                    --severity HIGH,CRITICAL \
                                    --scanners misconfig,secret \
                                    --no-progress \
                                    --format json \
                                    --output trivy-repo-result.json \
                                    scan-src/
                            """,
                            returnStatus: true
                        )

                        if (fileExists('trivy-repo-result.json')) {
                            def result = readJSON(file: 'trivy-repo-result.json')
                            result.Results?.each { r ->
                                r.Misconfigurations?.each { m ->
                                    if (m.Severity == 'CRITICAL') env.TRIVY_REPO_MISCONFIG_CRITICAL = (env.TRIVY_REPO_MISCONFIG_CRITICAL.toInteger() + 1).toString()
                                    if (m.Severity == 'HIGH')     env.TRIVY_REPO_MISCONFIG_HIGH     = (env.TRIVY_REPO_MISCONFIG_HIGH.toInteger()     + 1).toString()
                                }
                                r.Secrets?.each {
                                    env.TRIVY_REPO_SECRETS = (env.TRIVY_REPO_SECRETS.toInteger() + 1).toString()
                                }
                            }
                        }

                        echo "Trivy Repo: MisconfigCRITICAL=${env.TRIVY_REPO_MISCONFIG_CRITICAL}, MisconfigHIGH=${env.TRIVY_REPO_MISCONFIG_HIGH}, Secrets=${env.TRIVY_REPO_SECRETS}"

                        if (exitCode != 0) {
                            error("Trivy repo scan found HIGH/CRITICAL findings: ${env.TRIVY_REPO_MISCONFIG_CRITICAL} critical misconfigs, ${env.TRIVY_REPO_MISCONFIG_HIGH} high misconfigs, ${env.TRIVY_REPO_SECRETS} secrets")
                        }
                    }
                }
            }
        }

        stage('Checkov') {
            steps {
                script {
                    env.CHECKOV_FAILED       = '0'
                    env.CHECKOV_PASSED       = '0'
                    env.CHECKOV_BY_FRAMEWORK = '{}'

                    container('deploy-sec-base') {
                        // Frameworks:
                        //   terraform      — Terraform modules (CIS benchmarks, provider misconfigs)
                        //   dockerfile     — Dockerfile best practices and security
                        //   kubernetes     — raw Kubernetes manifests (RBAC, privileged, securityContext)
                        //   helm           — Helm chart templates and values (scanned without rendering)
                        //   kustomize      — Kustomize overlays (scanned without rendering)
                        //   github_actions — GitHub Actions workflow files (injection, permissions)
                        //   secrets        — hardcoded credentials in any source file
                        //
                        // --quiet suppresses stdout progress so the redirect captures clean JSON.
                        def exitCode = sh(
                            script: """
                                checkov -d scan-src/ \
                                    --framework terraform,dockerfile,kubernetes,helm,kustomize,github_actions,secrets \
                                    --hard-fail-on HIGH,CRITICAL \
                                    --compact \
                                    --quiet \
                                    --output json \
                                    > checkov-result.json
                            """,
                            returnStatus: true
                        )

                        if (fileExists('checkov-result.json')) {
                            def raw = readFile('checkov-result.json').trim()
                            if (raw && raw.startsWith('[') || raw.startsWith('{')) {
                                def parsed     = readJSON(text: raw)
                                def allResults = parsed instanceof List ? parsed : [parsed]
                                def totalFailed = 0
                                def totalPassed = 0
                                def byFramework = [:]

                                allResults.each { r ->
                                    def fw   = r.check_type ?: 'unknown'
                                    def fail = (r.summary?.failed ?: 0) as int
                                    def pass = (r.summary?.passed ?: 0) as int
                                    totalFailed += fail
                                    totalPassed += pass
                                    byFramework[fw] = [passed: pass, failed: fail]
                                }

                                env.CHECKOV_FAILED       = totalFailed.toString()
                                env.CHECKOV_PASSED       = totalPassed.toString()
                                env.CHECKOV_BY_FRAMEWORK = groovy.json.JsonOutput.toJson(byFramework)

                                echo "Checkov: ${totalPassed} passed, ${totalFailed} failed"
                                byFramework.each { fw, counts ->
                                    if (counts.failed > 0) echo "  ${fw}: ${counts.failed} failed, ${counts.passed} passed"
                                }
                            }
                        }

                        if (exitCode != 0) {
                            error("Checkov found HIGH/CRITICAL failures: ${env.CHECKOV_FAILED} failed checks")
                        }
                    }
                }
            }
        }

        stage('Render') {
            when { expression { return params.ENVIRONMENT?.trim() } }
            steps {
                script {
                    env.RENDERED_MANIFEST_SHA256 = ''
                    env.RENDERED_OCI_REF         = ''

                    def envType = env["TUXGRID_ENV_${params.ENVIRONMENT.toUpperCase()}_TYPE"] ?: 'kubernetes'
                    if (envType == 'aws') {
                        echo "Environment '${params.ENVIRONMENT}' is type 'aws' — skipping render (terraform plan handles IaC)"
                        return
                    }

                    def hasSkaffold = fileExists('scan-src/skaffold.yaml') || fileExists('scan-src/skaffold.yml')
                    if (!hasSkaffold) {
                        echo "No skaffold.yaml found in source — skipping render"
                        return
                    }

                    container('deploy-sec-base') {
                        withEnv(["DEPLOY_ENV=${params.ENVIRONMENT}"]) {
                            sh '''
                                cd scan-src
                                skaffold render \
                                    --profile="$DEPLOY_ENV" \
                                    --build-artifacts=../artifacts.json \
                                    --output=../rendered.yaml
                            '''
                        }
                    }

                    if (fileExists('rendered.yaml')) {
                        env.RENDERED_MANIFEST_SHA256 = sh(
                            script: "sha256sum rendered.yaml | awk '{print \$1}'",
                            returnStdout: true
                        ).trim()
                        echo "Rendered manifest SHA-256: ${env.RENDERED_MANIFEST_SHA256}"
                    }
                }
            }
        }

        stage('Checkov Rendered') {
            when { expression { return fileExists('rendered.yaml') } }
            steps {
                script {
                    env.CHECKOV_RENDERED_FAILED = '0'
                    env.CHECKOV_RENDERED_PASSED = '0'

                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: '''
                                checkov -f rendered.yaml \
                                    --framework kubernetes \
                                    --hard-fail-on HIGH,CRITICAL \
                                    --compact \
                                    --quiet \
                                    --output json \
                                    > checkov-rendered-result.json
                            ''',
                            returnStatus: true
                        )

                        if (fileExists('checkov-rendered-result.json')) {
                            def raw = readFile('checkov-rendered-result.json').trim()
                            if (raw && (raw.startsWith('[') || raw.startsWith('{'))) {
                                def parsed     = readJSON(text: raw)
                                def allResults = parsed instanceof List ? parsed : [parsed]
                                def totalFailed = 0
                                def totalPassed = 0
                                allResults.each { r ->
                                    totalFailed += (r.summary?.failed ?: 0) as int
                                    totalPassed += (r.summary?.passed ?: 0) as int
                                }
                                env.CHECKOV_RENDERED_FAILED = totalFailed.toString()
                                env.CHECKOV_RENDERED_PASSED = totalPassed.toString()
                                echo "Checkov Rendered: ${totalPassed} passed, ${totalFailed} failed"
                            }
                        }

                        if (exitCode != 0) {
                            error("Checkov found HIGH/CRITICAL failures in rendered manifest: ${env.CHECKOV_RENDERED_FAILED} failed checks")
                        }
                    }
                }
            }
        }

        stage('Terraform Plan') {
            when { expression { return params.ENVIRONMENT?.trim() } }
            steps {
                script {
                    env.TFPLAN_SHA256  = ''
                    env.TFPLAN_OCI_REF = ''
                    env.CHECKOV_PLAN_FAILED = '0'
                    env.CHECKOV_PLAN_PASSED = '0'

                    def envType = env["TUXGRID_ENV_${params.ENVIRONMENT.toUpperCase()}_TYPE"] ?: 'kubernetes'
                    if (envType != 'aws') {
                        echo "Environment '${params.ENVIRONMENT}' is type '${envType}' — skipping Terraform plan"
                        return
                    }

                    def hasTf = sh(
                        script: 'find scan-src/ -maxdepth 4 -name "*.tf" | head -1',
                        returnStdout: true
                    ).trim()
                    if (!hasTf) {
                        echo "No .tf files found in source — skipping Terraform plan"
                        return
                    }

                    def roleArn = env["TUXGRID_ENV_${params.ENVIRONMENT.toUpperCase()}_ROLE_ARN"]
                    if (!roleArn) {
                        echo "WARNING: no ROLE_ARN for environment '${params.ENVIRONMENT}' — skipping Terraform plan"
                        return
                    }

                    def teamSlug = params.UPSTREAM_JOB.split('/')[1]
                    def payload  = groovy.json.JsonOutput.toJson([
                        image_ref:   readJSON(file: 'artifacts.json').builds[0].tag,
                        environment: params.ENVIRONMENT,
                        role_arn:    roleArn,
                    ])

                    def credsJson
                    container('awscli') {
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

                    def creds = readJSON(text: credsJson)
                    withEnv([
                        "AWS_ACCESS_KEY_ID=${creds.AccessKeyId}",
                        "AWS_SECRET_ACCESS_KEY=${creds.SecretAccessKey}",
                        "AWS_SESSION_TOKEN=${creds.SessionToken}",
                        "DEPLOY_ENV=${params.ENVIRONMENT}",
                        "TEAM_SLUG=${teamSlug}",
                    ]) {
                        container('deploy-sec-base') {
                            sh '''
                                cd scan-src
                                terraform init \
                                    -backend-config="key=${TEAM_SLUG}/${DEPLOY_ENV}/terraform.tfstate"
                                terraform plan \
                                    -var-file=environments/${DEPLOY_ENV}.tfvars \
                                    -out=../tfplan
                                terraform show -json ../tfplan > ../tfplan.json
                            '''
                        }
                    }

                    if (fileExists('tfplan')) {
                        env.TFPLAN_SHA256 = sh(
                            script: "sha256sum tfplan | awk '{print \$1}'",
                            returnStdout: true
                        ).trim()
                        echo "Terraform plan SHA-256: ${env.TFPLAN_SHA256}"
                    }
                }
            }
        }

        stage('Checkov Plan') {
            when { expression { return fileExists('tfplan.json') } }
            steps {
                script {
                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: '''
                                checkov -f tfplan.json \
                                    --framework terraform_plan \
                                    --hard-fail-on HIGH,CRITICAL \
                                    --compact \
                                    --quiet \
                                    --output json \
                                    > checkov-plan-result.json
                            ''',
                            returnStatus: true
                        )

                        if (fileExists('checkov-plan-result.json')) {
                            def raw = readFile('checkov-plan-result.json').trim()
                            if (raw && (raw.startsWith('[') || raw.startsWith('{'))) {
                                def parsed     = readJSON(text: raw)
                                def allResults = parsed instanceof List ? parsed : [parsed]
                                def totalFailed = 0
                                def totalPassed = 0
                                allResults.each { r ->
                                    totalFailed += (r.summary?.failed ?: 0) as int
                                    totalPassed += (r.summary?.passed ?: 0) as int
                                }
                                env.CHECKOV_PLAN_FAILED = totalFailed.toString()
                                env.CHECKOV_PLAN_PASSED = totalPassed.toString()
                                echo "Checkov Plan: ${totalPassed} passed, ${totalFailed} failed"
                            }
                        }

                        if (exitCode != 0) {
                            error("Checkov found HIGH/CRITICAL failures in Terraform plan: ${env.CHECKOV_PLAN_FAILED} failed checks")
                        }
                    }
                }
            }
        }

        stage('Push Artifacts') {
            when { expression { return params.ENVIRONMENT?.trim() && (fileExists('rendered.yaml') || fileExists('tfplan')) } }
            steps {
                script {
                    def parts    = params.UPSTREAM_JOB.split('/')
                    def teamSlug = parts[1]
                    def repoName = parts[2]
                    def gitShort = params.GIT_COMMIT.take(7)
                    def envSlug  = params.ENVIRONMENT

                    withCredentials([usernamePassword(
                        credentialsId: 'harbor-robot-platform',
                        usernameVariable: 'HARBOR_USER',
                        passwordVariable: 'HARBOR_PASS',
                    )]) {
                        container('deploy-sec-base') {
                            sh '''
                                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                                mkdir -p ~/.docker
                                printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > ~/.docker/config.json
                            '''

                            if (fileExists('rendered.yaml')) {
                                def tag = "harbor.tuxgrid.com/platform/scan-artifacts:${teamSlug}-${repoName}-${gitShort}-${envSlug}-rendered"
                                withEnv(["ARTIFACT_TAG=${tag}"]) {
                                    sh '''
                                        cosign upload blob \
                                            -f rendered.yaml \
                                            --ct 'application/vnd.tuxgrid.rendered-manifest.v1+yaml' \
                                            "$ARTIFACT_TAG"
                                    '''
                                }
                                env.RENDERED_OCI_REF = tag
                                echo "Pushed rendered.yaml → ${tag}"
                            }

                            if (fileExists('tfplan')) {
                                def tag = "harbor.tuxgrid.com/platform/scan-artifacts:${teamSlug}-${repoName}-${gitShort}-${envSlug}-tfplan"
                                withEnv(["ARTIFACT_TAG=${tag}"]) {
                                    sh '''
                                        cosign upload blob \
                                            -f tfplan \
                                            --ct 'application/vnd.tuxgrid.terraform-plan.v1+binary' \
                                            "$ARTIFACT_TAG"
                                    '''
                                }
                                env.TFPLAN_OCI_REF = tag
                                echo "Pushed tfplan → ${tag}"
                            }

                            sh 'rm -f ~/.docker/config.json'
                        }
                    }
                }
            }
        }

        stage('SBOM') {
            steps {
                script {
                    def images = readJSON(file: 'artifacts.json').builds
                    env.SBOM_PACKAGE_COUNT = '0'

                    container('deploy-sec-base') {
                        images.each { image ->
                            def sbomFile = "sbom-${image.tag.replaceAll('[/:@]', '-')}.json"
                            // Separate invocation from the vuln scan — no --exit-code, no severity
                            // filter. Goal is a complete package inventory, not a pass/fail gate.
                            withEnv(["IMAGE_REF=${image.tag}", "SBOM_FILE=${sbomFile}"]) {
                                sh '''
                                    trivy image \
                                        --format spdx-json \
                                        --output "$SBOM_FILE" \
                                        --no-progress \
                                        "$IMAGE_REF"
                                '''
                            }
                            if (fileExists(sbomFile)) {
                                def sbom    = readJSON(file: sbomFile)
                                def pkgCount = (sbom.packages?.size() ?: 0) as int
                                env.SBOM_PACKAGE_COUNT = (env.SBOM_PACKAGE_COUNT.toInteger() + pkgCount).toString()
                                echo "SBOM: ${pkgCount} packages in ${image.tag}"
                            }
                        }
                    }

                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
                        container('deploy-sec-base') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                def sbomFile = "sbom-${image.tag.replaceAll('[/:@]', '-')}.json"
                                withEnv(["IMAGE_REF=${image.tag}", "SBOM_FILE=${sbomFile}"]) {
                                    sh '''
                                        COSIGN_PASSWORD="" cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate "$SBOM_FILE" \
                                            --type spdxjson \
                                            --tlog-upload=false \
                                            --yes "$IMAGE_REF"
                                    '''
                                }
                            }

                            sh 'rm -f /tmp/cosign.key'
                        }
                    }

                    echo "SBOM attestations created for ${images.size()} image(s) — ${env.SBOM_PACKAGE_COUNT} total packages"
                }
            }
        }

        stage('Attest') {
            steps {
                script {
                    def images    = readJSON(file: 'artifacts.json').builds
                    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
                    def trivyImage   = 'harbor.tuxgrid.com/platform/trivy:0.60.0'
                    def checkovImage = 'harbor.tuxgrid.com/platform/checkov:3.2.285'

                    writeJSON(file: 'predicate-scan.json', json: [
                        job:         params.UPSTREAM_JOB,
                        build:       params.UPSTREAM_BUILD,
                        timestamp:   timestamp,
                        git_url:     params.GIT_URL,
                        git_commit:  params.GIT_COMMIT,
                        environment: params.ENVIRONMENT ?: '',
                        trivy_image: [
                            passed:         true,
                            critical:       env.TRIVY_IMG_CRITICAL.toInteger(),
                            high:           env.TRIVY_IMG_HIGH.toInteger(),
                            secrets_found:  env.TRIVY_IMG_SECRETS.toInteger(),
                            scanners:       ['vuln', 'secret'],
                            ignore_unfixed: true,
                            scanner_image:  trivyImage,
                        ],
                        trivy_repo: [
                            passed:             true,
                            misconfig_critical: env.TRIVY_REPO_MISCONFIG_CRITICAL.toInteger(),
                            misconfig_high:     env.TRIVY_REPO_MISCONFIG_HIGH.toInteger(),
                            secrets_found:      env.TRIVY_REPO_SECRETS.toInteger(),
                            scanners:           ['misconfig', 'secret'],
                            scanner_image:      trivyImage,
                        ],
                        checkov: [
                            passed:        true,
                            failed:        env.CHECKOV_FAILED.toInteger(),
                            passed_checks: env.CHECKOV_PASSED.toInteger(),
                            frameworks:    ['terraform', 'dockerfile', 'kubernetes', 'helm', 'kustomize', 'github_actions', 'secrets'],
                            by_framework:  new groovy.json.JsonSlurper().parseText(env.CHECKOV_BY_FRAMEWORK),
                            scanner_image: checkovImage,
                        ],
                        render: [
                            rendered_manifest_sha256: env.RENDERED_MANIFEST_SHA256 ?: '',
                            rendered_manifest_ref:    env.RENDERED_OCI_REF ?: '',
                            checkov_passed:  (env.CHECKOV_RENDERED_FAILED ?: '0').toInteger() == 0,
                            checkov_failed:  (env.CHECKOV_RENDERED_FAILED ?: '0').toInteger(),
                            checkov_passed_checks: (env.CHECKOV_RENDERED_PASSED ?: '0').toInteger(),
                        ],
                        plan: [
                            terraform_plan_sha256: env.TFPLAN_SHA256 ?: '',
                            terraform_plan_ref:    env.TFPLAN_OCI_REF ?: '',
                            checkov_passed:  (env.CHECKOV_PLAN_FAILED ?: '0').toInteger() == 0,
                            checkov_failed:  (env.CHECKOV_PLAN_FAILED ?: '0').toInteger(),
                            checkov_passed_checks: (env.CHECKOV_PLAN_PASSED ?: '0').toInteger(),
                        ],
                        sbom: [
                            attested:      true,
                            format:        'spdx-json',
                            package_count: env.SBOM_PACKAGE_COUNT.toInteger(),
                            scanner_image: trivyImage,
                        ],
                    ])

                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
                        container('deploy-sec-base') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                withEnv(["IMAGE_REF=${image.tag}"]) {
                                    sh '''
                                        COSIGN_PASSWORD="" cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate predicate-scan.json \
                                            --type 'https://tuxgrid.com/attestation/scan/v1' \
                                            --tlog-upload=false \
                                            --yes "$IMAGE_REF"
                                    '''
                                }
                            }

                            sh 'rm -f /tmp/cosign.key'
                        }
                    }

                    echo "Scan attestations created for ${images.size()} image(s)"
                }
            }
        }
    }

    post {
        failure {
            script {
                echo "[Platform] Scan FAILED for ${params.UPSTREAM_JOB} #${params.UPSTREAM_BUILD} — no scan/v1 attestation will be created"
            }
        }
    }
}
