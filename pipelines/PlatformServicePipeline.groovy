// Wrapper pipeline for platform services.
// Chains build → scan → deploy → release via build job: calls.
// Each stage is individually selectable via RUN_* parameters.
//
// The build stage captures the exact build number and passes it to all downstream
// stages so they all operate on the same artifact regardless of concurrent builds.
//
// Environment variables (injected by seed DSL):
//   SERVICE_BUILD_JOB   — e.g. platform/services/audit-service/build
//   SERVICE_SCAN_JOB    — e.g. platform/services/audit-service/scan
//   SERVICE_DEPLOY_JOB  — e.g. platform/services/audit-service/deploy
//   SERVICE_RELEASE_JOB — e.g. platform/services/audit-service/release

pipeline {
    agent none

    options {
        disableConcurrentBuilds()
        timeout(time: 90, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    parameters {
        booleanParam(name: 'RUN_BUILD',   defaultValue: true,  description: 'Run the build pipeline')
        booleanParam(name: 'RUN_SCAN',    defaultValue: true,  description: 'Run the scan pipeline (required before release)')
        booleanParam(name: 'RUN_DEPLOY',  defaultValue: true,  description: 'Deploy to cluster (sig + provenance verification)')
        booleanParam(name: 'RUN_RELEASE', defaultValue: false, description: 'Run full release (scan/v1 + Cedar gate + sha256 verify)')
        string(name: 'UPSTREAM_BUILD', defaultValue: 'lastSuccessful', description: 'Build number to use when RUN_BUILD=false')
        string(name: 'ENVIRONMENT',    defaultValue: 'dev',             description: 'Target environment for scan and release')
    }

    stages {
        stage('Build') {
            when { expression { params.RUN_BUILD } }
            steps {
                script {
                    def result = build(
                        job:       env.SERVICE_BUILD_JOB,
                        wait:      true,
                        propagate: true
                    )
                    env.BUILT_BUILD_NUMBER = result.number as String
                }
            }
        }

        stage('Scan') {
            when { expression { params.RUN_SCAN } }
            steps {
                script {
                    def upstream = env.BUILT_BUILD_NUMBER ?: params.UPSTREAM_BUILD
                    build(
                        job:       env.SERVICE_SCAN_JOB,
                        wait:      true,
                        propagate: true,
                        parameters: [
                            string(name: 'UPSTREAM_JOB',   value: env.SERVICE_BUILD_JOB),
                            string(name: 'UPSTREAM_BUILD', value: upstream),
                            string(name: 'GIT_URL',        value: ''),
                            string(name: 'GIT_COMMIT',     value: ''),
                            string(name: 'ENVIRONMENT',    value: params.ENVIRONMENT),
                        ]
                    )
                }
            }
        }

        stage('Deploy') {
            when { expression { params.RUN_DEPLOY } }
            steps {
                script {
                    def upstream = env.BUILT_BUILD_NUMBER ?: params.UPSTREAM_BUILD
                    build(
                        job:       env.SERVICE_DEPLOY_JOB,
                        wait:      true,
                        propagate: true,
                        parameters: [
                            string(name: 'UPSTREAM_JOB',   value: env.SERVICE_BUILD_JOB),
                            string(name: 'UPSTREAM_BUILD', value: upstream),
                        ]
                    )
                }
            }
        }

        stage('Release') {
            when { expression { params.RUN_RELEASE } }
            steps {
                script {
                    def upstream = env.BUILT_BUILD_NUMBER ?: params.UPSTREAM_BUILD
                    build(
                        job:       env.SERVICE_RELEASE_JOB,
                        wait:      true,
                        propagate: true,
                        parameters: [
                            string(name: 'UPSTREAM_JOB',   value: env.SERVICE_BUILD_JOB),
                            string(name: 'UPSTREAM_BUILD', value: upstream),
                            string(name: 'ENVIRONMENT',    value: params.ENVIRONMENT),
                        ]
                    )
                }
            }
        }
    }
}
