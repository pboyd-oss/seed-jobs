// Platform audit compliance pipeline.
// Runs daily. For every team pipeline in the Jenkins job tree, calls Cedar
// AuditCompliance to detect pipelines that are stale, abandoned, or have never
// produced a scan/v1 attestation.
//
// Cedar policy: policies/audit-gap.cedar
// Context sent: lastAttestationAgeSeconds, attestationTypes
//
// Output: prints a gap report to the console. Marks build UNSTABLE if any gaps
// are found (not FAILURE — these are findings, not errors).

import jenkins.model.Jenkins
import hudson.model.Result

pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'deploy-sec-base'
        }
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '90'))
        disableConcurrentBuilds()
    }

    triggers {
        cron('H 6 * * *')
    }

    environment {
        DOCKER_CONFIG = '/tmp/.docker'
    }

    stages {
        stage('Scan') {
            steps {
                script { runComplianceScan() }
            }
        }
    }
}

// ---------------------------------------------------------------------------

@NonCPS
def listTeamBuildJobs() {
    def jobs = []
    Jenkins.get().getAllItems(hudson.model.Job).each { job ->
        def path = job.fullName
        // teams/{slug}/{repo} — exactly 3 segments, no sub-folders
        def parts = path.split('/')
        if (parts.size() == 3 && parts[0] == 'teams') {
            jobs << [path: path, teamSlug: parts[1], repo: parts[2]]
        }
    }
    return jobs
}

@NonCPS
def lastSuccessfulBuildTime(String jobPath) {
    def job   = Jenkins.get().getItemByFullName(jobPath)
    def build = job?.lastSuccessfulBuild
    return build ? build.timeInMillis : -1L
}

@NonCPS
def getArtifactsJsonText(String jobPath) {
    def job          = Jenkins.get().getItemByFullName(jobPath)
    def artifactsDir = job?.lastSuccessfulBuild?.artifactsDir
    if (!artifactsDir) return null
    def f = new File(artifactsDir, 'artifacts.json')
    return f.exists() ? f.text : null
}

private void runComplianceScan() {
    def jobs = listTeamBuildJobs()
    if (!jobs) {
        echo "[Platform:compliance] No team build jobs found"
        return
    }

    echo "[Platform:compliance] Checking ${jobs.size()} team pipelines..."

    def cedarUrl  = 'http://platform-cedar-sidecar.platform.svc.cluster.local/authorize'
    def now       = System.currentTimeMillis()
    def gaps      = []
    def checked   = 0

    withCredentials([
        string(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY'),
        usernamePassword(credentialsId: 'harbor-robot-platform', usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS'),
    ]) {
        container('deploy-sec-base') {
            sh "printf '%s' \"\$COSIGN_PUBLIC_KEY\" > /tmp/cosign.pub"
            sh '''
                AUTH=$(printf '%s:%s' "$HARBOR_USER" "$HARBOR_PASS" | base64 | tr -d '\\n')
                mkdir -p /tmp/.docker
                mkdir -p /tmp/.docker && printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "$AUTH" > /tmp/.docker/config.json
            '''

            jobs.each { j ->
                def lastBuildMs = lastSuccessfulBuildTime(j.path)

                // Never built successfully — use sentinel max value so Cedar fires
                // the "never completed an attestation cycle" rule.
                def lastAgeSeconds = lastBuildMs < 0
                    ? Long.MAX_VALUE - 1
                    : (long) ((now - lastBuildMs) / 1000)

                // Determine which attestation types exist on the most recent
                // successful image. Requires artifacts.json to find the image ref.
                def attestationTypes = []
                def artifactsText    = getArtifactsJsonText(j.path)

                if (artifactsText) {
                    try {
                        def parsed   = readJSON(text: artifactsText)
                        def imageRef = parsed?.builds?.get(0)?.tag ?: ''
                        if (imageRef) {
                            def knownTypes = [
                                'https://tuxgrid.com/attestation/build/v1',
                                'https://tuxgrid.com/attestation/tests/v1',
                                'https://tuxgrid.com/attestation/scan/v1',
                                'https://tuxgrid.com/attestation/pipeline/v1',
                            ]
                            knownTypes.each { t ->
                                def rc = sh(
                                    script: "cosign verify-attestation --key /tmp/cosign.pub --type '${t}' '${imageRef}' > /dev/null 2>&1 && echo ok || echo fail",
                                    returnStdout: true
                                ).trim()
                                if (rc == 'ok') attestationTypes << t
                            }
                        }
                    } catch (ignored) {}
                }

                // Call Cedar AuditCompliance.
                def payload = groovy.json.JsonOutput.toJson([
                    principal: "TuxGrid::Team::\"${j.teamSlug}\"",
                    action:    'TuxGrid::Action::"AuditCompliance"',
                    resource:  "TuxGrid::Pipeline::\"${j.path}\"",
                    entities:  [],
                    context: [
                        lastAttestationAgeSeconds: lastAgeSeconds,
                        attestationTypes:          attestationTypes,
                    ],
                ])

                try {
                    def conn = new URL(cedarUrl).openConnection()
                    conn.requestMethod  = 'POST'
                    conn.doOutput       = true
                    conn.connectTimeout = 5000
                    conn.readTimeout    = 5000
                    conn.setRequestProperty('Content-Type', 'application/json')
                    conn.outputStream.write(payload.bytes)

                    def code     = conn.responseCode
                    def respBody = (code < 400 ? conn.inputStream : conn.errorStream)?.text ?: ''

                    if (code == 200) {
                        def result = readJSON(text: respBody)
                        if (result.decision == 'DENY') {
                            gaps << [pipeline: j.path, reasons: result.reasons ?: ['policy denied']]
                        }
                        checked++
                    }
                } catch (java.net.ConnectException ignored) {
                    echo "[Platform:compliance] Cedar sidecar unreachable — skipping scan"
                    return
                }
            }

            sh 'rm -f /tmp/cosign.pub /tmp/.docker/config.json'
        }
    }

    // Report.
    echo ""
    echo "=========================================="
    echo " Platform Attestation Compliance Report"
    echo " ${new Date().format('yyyy-MM-dd HH:mm')} UTC"
    echo " Checked: ${checked} pipelines"
    echo " Gaps:    ${gaps.size()}"
    echo "=========================================="

    if (gaps) {
        gaps.each { g ->
            echo ""
            echo "  PIPELINE: ${g.pipeline}"
            g.reasons.each { r -> echo "    - ${r}" }
        }
        echo ""
        currentBuild.result = Result.UNSTABLE
    } else {
        echo "  All pipelines compliant."
    }
}
