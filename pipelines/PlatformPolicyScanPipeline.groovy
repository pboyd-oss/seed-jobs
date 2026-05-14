// Platform infrastructure policy scan.
// Validates the platform's own IAM and Kubernetes policy code using the same
// scanner stack used for team builds — Trivy + Checkov on platform infrastructure.
//
// Scans the full platform repo clone (platform-src/) so new Terraform modules,
// K8s manifests, and Dockerfiles are picked up automatically without config changes.
//
// Triggered by changes to the platform repo (https://github.com/pboyd-oss/talos-argocd-proxmox.git).
// Runs on deploy-sec-base infrastructure — same pod template as PlatformScanPipeline.

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
        buildDiscarder(logRotator(numToKeepStr: '50'))
    }

    parameters {
        string(name: 'GIT_URL',    defaultValue: 'https://github.com/pboyd-oss/talos-argocd-proxmox.git',
               description: 'Platform infrastructure repo')
        string(name: 'GIT_COMMIT', defaultValue: 'HEAD',
               description: 'Commit SHA or branch ref to scan')
    }

    stages {
        stage('Fetch') {
            steps {
                script {
                    sh """
                        git clone --depth 1 '${params.GIT_URL}' platform-src
                        cd platform-src && git checkout '${params.GIT_COMMIT}'
                    """
                }
            }
        }

        stage('Trivy') {
            steps {
                script {
                    env.TRIVY_MISCONFIG_CRITICAL = '0'
                    env.TRIVY_MISCONFIG_HIGH     = '0'
                    env.TRIVY_SECRETS            = '0'

                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: '''
                                cd platform-src && trivy fs \
                                    --exit-code 1 \
                                    --severity HIGH,CRITICAL \
                                    --scanners misconfig,secret \
                                    --no-progress \
                                    --skip-policy-update \
                                    --timeout 15m \
                                    --format json \
                                    --output ../trivy-result.json \
                                    .
                            ''',
                            returnStatus: true
                        )

                        if (fileExists('trivy-result.json')) {
                            def result = readJSON(file: 'trivy-result.json')
                            result.Results?.each { r ->
                                r.Misconfigurations?.each { m ->
                                    if (m.Severity == 'CRITICAL') env.TRIVY_MISCONFIG_CRITICAL = (env.TRIVY_MISCONFIG_CRITICAL.toInteger() + 1).toString()
                                    if (m.Severity == 'HIGH')     env.TRIVY_MISCONFIG_HIGH     = (env.TRIVY_MISCONFIG_HIGH.toInteger()     + 1).toString()
                                }
                                r.Secrets?.each { env.TRIVY_SECRETS = (env.TRIVY_SECRETS.toInteger() + 1).toString() }
                            }

                            sh(script: '''
                                trivy convert \
                                    --format template \
                                    --template "@/contrib/junit.tpl" \
                                    --output trivy-junit.xml \
                                    trivy-result.json
                            ''', returnStatus: true)
                        }

                        echo "Trivy: MisconfigCRITICAL=${env.TRIVY_MISCONFIG_CRITICAL}, MisconfigHIGH=${env.TRIVY_MISCONFIG_HIGH}, Secrets=${env.TRIVY_SECRETS}"

                        if (exitCode != 0) {
                            error("Trivy found HIGH/CRITICAL findings in platform policy code: ${env.TRIVY_MISCONFIG_CRITICAL} critical, ${env.TRIVY_MISCONFIG_HIGH} high misconfigs, ${env.TRIVY_SECRETS} secrets")
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
                        def exitCode = sh(
                            script: '''
                                cd platform-src && checkov \
                                    -d . \
                                    --framework terraform,kubernetes,secrets \
                                    --hard-fail-on HIGH,CRITICAL \
                                    --compact \
                                    --quiet \
                                    --output json \
                                    --output junitxml \
                                    --output-file-path ../checkov-out/
                            ''',
                            returnStatus: true
                        )

                        if (fileExists('checkov-out/results_json.json')) {
                            def raw = readFile('checkov-out/results_json.json').trim()
                            if (raw && (raw.startsWith('[') || raw.startsWith('{'))) {
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
                            error("Checkov found HIGH/CRITICAL failures in platform policy code: ${env.CHECKOV_FAILED} failed checks")
                        }
                    }
                }
            }
        }

        stage('tfsec') {
            steps {
                script {
                    env.TFSEC_FAILED = '0'

                    container('deploy-sec-base') {
                        def exitCode = sh(
                            script: """
                                tfsec platform-src/terraform/modules \
                                    --minimum-severity HIGH \
                                    --format json \
                                    --out tfsec-result.json \
                                    --no-color
                            """,
                            returnStatus: true
                        )

                        if (fileExists('tfsec-result.json')) {
                            def result = readJSON(file: 'tfsec-result.json')
                            env.TFSEC_FAILED = (result.results?.size() ?: 0).toString()
                            echo "tfsec: ${env.TFSEC_FAILED} HIGH/CRITICAL finding(s)"
                        }

                        if (exitCode != 0) {
                            error("tfsec found HIGH/CRITICAL issues in Terraform modules: ${env.TFSEC_FAILED} finding(s)")
                        }
                    }
                }
            }
        }

        stage('Infracost') {
            steps {
                script {
                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                        withCredentials([string(credentialsId: 'infracost-api-key', variable: 'INFRACOST_API_KEY')]) {
                            container('deploy-sec-base') {
                                sh """
                                    infracost breakdown \
                                        --path platform-src/terraform/modules \
                                        --format json \
                                        --out-file infracost-result.json
                                """

                                if (fileExists('infracost-result.json')) {
                                    def result    = readJSON(file: 'infracost-result.json')
                                    def totalCost = result.totalMonthlyCost ?: '0'
                                    echo "Infracost: estimated monthly cost \$${totalCost}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true,
                  skipMarkingBuildUnstable: true,
                  testResults: 'trivy-junit.xml,checkov-out/results_junitxml.xml'
        }
        failure {
            echo "[Platform] Policy scan FAILED — platform infrastructure code has HIGH/CRITICAL security findings. Merge blocked."
        }
        success {
            echo "[Platform] Policy scan passed — ${env.CHECKOV_PASSED} Checkov checks, 0 Trivy findings, 0 tfsec findings."
        }
    }
}
