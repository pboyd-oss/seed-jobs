// Platform-controlled scan pipeline.
// Four gates must all pass before a scan/v1 attestation is created:
//
//   1. Trivy Image — container vulnerability + secret scanning per image in artifacts.json
//                    (--scanners vuln,secret --ignore-unfixed --severity HIGH,CRITICAL)
//   2. Trivy Repo  — IaC misconfiguration + secret scanning of the source repository
//                    (trivy fs --scanners misconfig,secret --severity HIGH,CRITICAL)
//   3. Checkov     — IaC policy checks across terraform, dockerfile, kubernetes,
//                    helm, kustomize, github_actions, and secrets frameworks
//   4. SBOM        — SPDX-JSON Software Bill of Materials attested separately as
//                    https://spdx.dev/Document for each image (informational, not a pass/fail gate)
//
// Triggered by microservicePipeline() — runs on platform infrastructure,
// NOT the team's build cloud. Teams cannot forge the scan/v1 attestation:
// they do not hold the cosign-key credential.
//
// The source repo is cloned once in Fetch and reused by both Trivy Repo and
// Checkov, avoiding a double clone.

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'build-sec-base'
        }
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'UPSTREAM_JOB',   description: 'Full job path of the build that produced artifacts.json')
        string(name: 'UPSTREAM_BUILD', description: 'Build number')
        string(name: 'GIT_URL',        description: 'Repository URL for source/IaC scanning')
        string(name: 'GIT_COMMIT',     description: 'Exact commit SHA to scan')
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
                        '''
                    }
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

                    container('build-sec-base') {
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

                    container('build-sec-base') {
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

                    container('build-sec-base') {
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

        stage('SBOM') {
            steps {
                script {
                    def images = readJSON(file: 'artifacts.json').builds
                    env.SBOM_PACKAGE_COUNT = '0'

                    container('build-sec-base') {
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
                        container('build-sec-base') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                def sbomFile = "sbom-${image.tag.replaceAll('[/:@]', '-')}.json"
                                withEnv(["IMAGE_REF=${image.tag}", "SBOM_FILE=${sbomFile}"]) {
                                    sh '''
                                        COSIGN_PASSWORD="" cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate "$SBOM_FILE" \
                                            --type spdxjson \
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
                        job:        params.UPSTREAM_JOB,
                        build:      params.UPSTREAM_BUILD,
                        timestamp:  timestamp,
                        git_url:    params.GIT_URL,
                        git_commit: params.GIT_COMMIT,
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
                        sbom: [
                            attested:      true,
                            format:        'spdx-json',
                            package_count: env.SBOM_PACKAGE_COUNT.toInteger(),
                            scanner_image: trivyImage,
                        ],
                    ])

                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
                        container('build-sec-base') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                withEnv(["IMAGE_REF=${image.tag}"]) {
                                    sh '''
                                        COSIGN_PASSWORD="" cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate predicate-scan.json \
                                            --type 'https://tuxgrid.com/attestation/scan/v1' \
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
