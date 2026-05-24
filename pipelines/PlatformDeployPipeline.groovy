// Platform-controlled deploy pipeline for platform services.
// Verifies cosign signature and slsaprovenance1 attestation before applying.
// Does NOT require scan/v1 — use the release pipeline for production.
//
// Environment variables (injected by seed DSL):
//   SERVICE_BUILD_JOB — full path of the build job, used as UPSTREAM_JOB default
//   SERVICE_WORKLOAD  — workload name for rollout watch
//   SERVICE_NAMESPACE — target namespace
//   SERVICE_KIND      — resource kind (deployment, daemonset, etc.)
//   SERVICE_PROFILE   — skaffold profile (optional)
//
// Parameters:
//   UPSTREAM_JOB   — build job path (defaults to SERVICE_BUILD_JOB)
//   UPSTREAM_BUILD — build number or 'lastSuccessful'

@Library('jenkins-library') _

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'platform-deploy-base'
            yaml '''
spec:
  containers:
  - name: deploy-sec-base
    image: harbor.tuxgrid.com/platform/deploy-sec-base:latest
    command: ["cat"]
    tty: true
    resources:
      requests:
        cpu: "100m"
        memory: "256Mi"
      limits:
        cpu: "1"
        memory: "2Gi"
'''
        }
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 20, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    parameters {
        string(name: 'UPSTREAM_JOB',   defaultValue: '', description: 'Build job path (defaults to SERVICE_BUILD_JOB env var)')
        string(name: 'UPSTREAM_BUILD', defaultValue: 'lastSuccessful', description: 'Build number or lastSuccessful')
    }

    stages {
        stage('Deploy') {
            steps {
                script {
                    platformDeploy(
                        upstreamJob:   params.UPSTREAM_JOB ?: env.SERVICE_BUILD_JOB,
                        upstreamBuild: params.UPSTREAM_BUILD,
                    )
                }
            }
        }
    }
}
