// Platform-controlled release pipeline. Teams trigger this but cannot modify it.
// Scan → sign → deploy. cosign-key is scoped to platform/ — inaccessible to team jobs.
//
// Parameters:
//   UPSTREAM_JOB   — full Jenkins path of the build job that produced artifacts.json
//   UPSTREAM_BUILD — build number, or 'lastSuccessful'
//   ENVIRONMENT    — target environment name (must match team YAML)

pipeline {
    agent {
        kubernetes {
            cloud env.TUXGRID_BUILD_CLOUD
            inheritFrom 'base'
        }
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
    }

    parameters {
        string(name: 'UPSTREAM_JOB',   description: 'Build job path that produced artifacts.json')
        string(name: 'UPSTREAM_BUILD', defaultValue: 'lastSuccessful', description: 'Build number or lastSuccessful')
        string(name: 'ENVIRONMENT',    description: 'Target environment (must match team YAML)')
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

        stage('Verify Attestations') {
            steps {
                script { pollForAttestations() }
            }
        }

        stage('Scan') {
            steps {
                script { scanImages() }
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

private void validateJobScope(String upstreamJob) {
    def allowedRoot = "teams/${env.TUXGRID_TEAM_SLUG}/"
    if (!upstreamJob.startsWith(allowedRoot)) {
        error("Release refused: '${upstreamJob}' is not within this team's folder '${allowedRoot}'")
    }
}

private void pollForAttestations() {
    def images           = readJSON(file: 'artifacts.json').builds
    if (!images) error('artifacts.json contains no builds')

    def imageRef         = images[0].tag
    def pollSecs         = 30
    def timeoutMins      = 10
    def deadline         = System.currentTimeMillis() + (timeoutMins * 60 * 1000)
    def attestationTypes = [
        'https://tuxgrid.com/attestation/tests/v1',
        'https://tuxgrid.com/attestation/build/v1',
    ]

    echo "Waiting for attestations on ${imageRef} (timeout: ${timeoutMins} min)..."

    withCredentials([string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY')]) {
        sh "printf '%s' \"\$COSIGN_PUBLIC_KEY\" > /tmp/cosign.pub"

        try {
            while (System.currentTimeMillis() < deadline) {
                def verified = attestationTypes.every { type ->
                    def result = sh(
                        script: "cosign verify-attestation --key /tmp/cosign.pub --type '${type}' '${imageRef}' > /dev/null 2>&1 && echo ok || echo fail",
                        returnStdout: true
                    ).trim()
                    return result == 'ok'
                }

                if (verified) {
                    echo "All attestations verified ✓"
                    return
                }

                echo "Attestations not yet present — retrying in ${pollSecs}s..."
                sleep(pollSecs)
            }

            error("Timed out after ${timeoutMins} minutes waiting for attestations on ${imageRef}")
        } finally {
            sh 'rm -f /tmp/cosign.pub'
        }
    }
}

private List getImages() {
    def artifacts = readJSON(file: 'artifacts.json')
    if (!artifacts.builds) error('artifacts.json contains no builds')
    return artifacts.builds
}

private void scanImages() {
    container('skaffold') {
        getImages().each { image ->
            sh """
                trivy image \
                    --exit-code 1 \
                    --severity HIGH,CRITICAL \
                    --no-progress \
                    '${image.tag}'
            """
        }
    }
}

private void signImages() {
    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
        container('skaffold') {
            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"
            getImages().each { image ->
                sh "cosign sign --key /tmp/cosign.key --yes '${image.tag}'"
            }
            sh 'rm -f /tmp/cosign.key'
        }
    }
}

private void deploy(String environment) {
    def upper     = environment.toUpperCase()
    def cloud     = env["TUXGRID_ENV_${upper}_CLOUD"]
    def namespace = env["TUXGRID_ENV_${upper}_NAMESPACE"]

    if (!cloud) error("No cloud configured for environment '${environment}'. Check team YAML.")

    echo "Deploying to '${environment}' — cloud: ${cloud}${namespace ? ", namespace: ${namespace}" : ''}"

    withCredentials([file(credentialsId: "kubeconfig-${cloud}", variable: 'KUBECONFIG')]) {
        container('skaffold') {
            sh """
                skaffold render \
                    --profile=${environment} \
                    --build-artifacts=artifacts.json \
                    --output=rendered.yaml

                skaffold apply rendered.yaml ${namespace ? "--namespace=${namespace}" : ''}
            """
        }
    }
}
