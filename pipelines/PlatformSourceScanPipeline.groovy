// Platform-controlled source scan pipeline.
// Runs before the build stage in the team's Jenkinsfile — no image exists yet.
// Teams call this as a blocking step and wait for PASS before proceeding to build:
//
//   stage('Source Scan') {
//       steps {
//           build job: "platform/${TUXGRID_TEAM_SLUG}/${env.JOB_BASE_NAME}/source-scan",
//                 parameters: [string(name: 'GIT_COMMIT', value: env.GIT_COMMIT)],
//                 wait: true
//       }
//   }
//
// Three scanners run against the source at the exact pinned commit:
//   1. Trivy fs (secrets)      — hardcoded credentials, API keys, tokens
//   2. tfsec                   — Terraform HIGH/CRITICAL misconfigurations
//   3. Checkov                 — Dockerfile, Terraform, K8s, Helm, Kustomize, GitHub Actions, secrets
//
// Build listener Standard 7 checks that this pipeline succeeded for the exact
// GIT_COMMIT before triggering scan/attest. Teams cannot forge or bypass the result.

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'deploy-sec-base'
        }
    }

    options {
        timeout(time: 20, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'GIT_URL',    description: 'Repository URL to scan (pre-populated from job config)')
        string(name: 'GIT_COMMIT', description: 'Exact 40-char commit SHA to scan')
    }

    stages {
        stage('Clone') {
            steps {
                script {
                    if (!(params.GIT_COMMIT ==~ /^[0-9a-f]{40}$/)) {
                        error("GIT_COMMIT is not a valid 40-char SHA: '${params.GIT_COMMIT}'")
                    }
                    withEnv(["GIT_REPO_URL=${params.GIT_URL}", "GIT_REPO_SHA=${params.GIT_COMMIT}"]) {
                        sh '''
                            git clone --depth 1 "$GIT_REPO_URL" scan-src
                            cd scan-src && git fetch --depth 1 origin "$GIT_REPO_SHA" && git checkout "$GIT_REPO_SHA"
                        '''
                    }
                }
            }
        }

        stage('Trivy Secrets') {
            steps {
                script {
                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: '''
                                trivy fs \
                                    --exit-code 1 \
                                    --scanners secret \
                                    --no-progress \
                                    --format json \
                                    --output trivy-secrets-result.json \
                                    scan-src/
                            ''',
                            returnStatus: true
                        )

                        def secretCount = 0
                        if (fileExists('trivy-secrets-result.json')) {
                            def result = readJSON(file: 'trivy-secrets-result.json')
                            result.Results?.each { r -> secretCount += (r.Secrets?.size() ?: 0) }
                        }

                        echo "Trivy Secrets: ${secretCount} secret(s) found"
                        if (exitCode != 0) {
                            error("Trivy found ${secretCount} hardcoded secret(s) — commit must not contain credentials")
                        }
                    }
                }
            }
        }

        stage('tfsec') {
            steps {
                script {
                    container('deploy-sec-base') {
                        // tfsec exits 1 when HIGH/CRITICAL findings exist, 0 when clean.
                        // If no Terraform files are present, tfsec exits 0 cleanly.
                        def exitCode = sh(
                            script: '''
                                tfsec scan-src/ \
                                    --minimum-severity HIGH \
                                    --format json \
                                    --out tfsec-result.json \
                                    --no-colour 2>/dev/null || true
                                tfsec scan-src/ \
                                    --minimum-severity HIGH \
                                    --format text \
                                    --no-colour
                            ''',
                            returnStatus: true
                        )

                        def issueCount = 0
                        if (fileExists('tfsec-result.json')) {
                            try {
                                def result = readJSON(file: 'tfsec-result.json')
                                issueCount = result.results?.findAll {
                                    it.severity in ['HIGH', 'CRITICAL']
                                }?.size() ?: 0
                            } catch (ignored) {}
                        }

                        echo "tfsec: ${issueCount} HIGH/CRITICAL Terraform issue(s)"
                        if (exitCode != 0) {
                            error("tfsec found ${issueCount} HIGH/CRITICAL Terraform issue(s)")
                        }
                    }
                }
            }
        }

        stage('Checkov') {
            steps {
                script {
                    env.CHECKOV_FAILED = '0'
                    env.CHECKOV_PASSED = '0'

                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: '''
                                checkov -d scan-src/ \
                                    --framework terraform,dockerfile,kubernetes,helm,kustomize,github_actions,secrets \
                                    --hard-fail-on HIGH,CRITICAL \
                                    --compact \
                                    --quiet \
                                    --output json \
                                    > checkov-result.json
                            ''',
                            returnStatus: true
                        )

                        if (fileExists('checkov-result.json')) {
                            def raw = readFile('checkov-result.json').trim()
                            if (raw && (raw.startsWith('[') || raw.startsWith('{'))) {
                                def parsed     = readJSON(text: raw)
                                def allResults = parsed instanceof List ? parsed : [parsed]
                                def totalFailed = 0
                                def totalPassed = 0
                                allResults.each { r ->
                                    totalFailed += (r.summary?.failed ?: 0) as int
                                    totalPassed += (r.summary?.passed ?: 0) as int
                                }
                                env.CHECKOV_FAILED = totalFailed.toString()
                                env.CHECKOV_PASSED = totalPassed.toString()
                                echo "Checkov: ${totalPassed} passed, ${totalFailed} failed"
                            }
                        }

                        if (exitCode != 0) {
                            error("Checkov found HIGH/CRITICAL failures: ${env.CHECKOV_FAILED} failed checks")
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            script {
                echo "[Platform] Source scan PASSED for ${params.GIT_URL}@${params.GIT_COMMIT?.take(7)} — build may proceed"
            }
        }
        failure {
            script {
                echo "[Platform] Source scan FAILED for ${params.GIT_URL}@${params.GIT_COMMIT?.take(7)} — build listener will refuse attestation for this commit"
            }
        }
    }
}
