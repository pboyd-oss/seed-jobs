// Platform attestation pipeline.
// Triggered exclusively by the RunListener on the Jenkins controller —
// not directly triggerable by team members (no Build permission in their folder).
//
// Reads Jenkins' internal test result records (not workspace files),
// then creates cosign attestations against every image in artifacts.json.
//
// Three attestations are created per image:
//   tests/v1    — proves tests ran and passed according to Jenkins
//   build/v1    — proves the image came from a successful Jenkins build
//   pipeline/v1 — proves which stages ran and which platform standards were verified

pipeline {
    agent {
        kubernetes {
            cloud env.TUXGRID_BUILD_CLOUD
            inheritFrom 'base'
        }
    }

    options {
        timeout(time: 15, unit: 'MINUTES')
    }

    parameters {
        string(name: 'UPSTREAM_JOB',             description: 'Full job path of the completed build')
        string(name: 'UPSTREAM_BUILD',           description: 'Build number')
        string(name: 'PLATFORM_TESTS_COUNT',     defaultValue: '0')
        string(name: 'PLATFORM_TESTS_FAILURES',  defaultValue: '0')
        string(name: 'PLATFORM_COVERAGE_PCT',    defaultValue: '0')
        string(name: 'PLATFORM_COVERAGE_THRESH', defaultValue: '0')
        string(name: 'PLATFORM_SCAN_JOB_REF',    defaultValue: '')
        string(name: 'PLATFORM_STAGES_JSON',     defaultValue: '[]')
        string(name: 'PLATFORM_LIBRARY_SHA',     defaultValue: 'unknown')
    }

    stages {
        stage('Read Results') {
            steps {
                script {
                    def buildNum = params.UPSTREAM_BUILD.toInteger()
                    def job      = Jenkins.get().getItemByFullName(params.UPSTREAM_JOB)
                    if (!job) error("Job not found: ${params.UPSTREAM_JOB}")

                    def build = job.getBuildByNumber(buildNum)
                    if (!build) error("Build #${buildNum} not found in ${params.UPSTREAM_JOB}")
                    if (build.result != hudson.model.Result.SUCCESS) {
                        error("Build #${buildNum} result is ${build.result} — attestation refused")
                    }

                    def testAction = build.getAction(hudson.tasks.junit.TestResultAction)
                    if (!testAction) error("No JUnit test results recorded for ${params.UPSTREAM_JOB} #${buildNum}")
                    if (testAction.failCount > 0) error("${testAction.failCount} test failure(s) — attestation refused")

                    env.ATTESTED_TESTS_RUN    = testAction.totalCount.toString()
                    env.ATTESTED_TESTS_FAILED = testAction.failCount.toString()
                    env.ATTESTED_TESTS_SKIP   = testAction.skipCount.toString()

                    echo "Tests: ${testAction.totalCount} run, ${testAction.failCount} failed, ${testAction.skipCount} skipped"
                }
            }
        }

        stage('Fetch Artifacts') {
            steps {
                script {
                    copyArtifacts(
                        projectName:          params.UPSTREAM_JOB,
                        selector:             specific(params.UPSTREAM_BUILD),
                        filter:               'artifacts.json',
                        fingerprintArtifacts: true
                    )
                }
            }
        }

        stage('Attest') {
            steps {
                script {
                    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))

                    writeJSON(file: 'predicate-tests.json', json: [
                        job:          params.UPSTREAM_JOB,
                        build:        params.UPSTREAM_BUILD,
                        tests_run:    env.ATTESTED_TESTS_RUN.toInteger(),
                        tests_failed: env.ATTESTED_TESTS_FAILED.toInteger(),
                        tests_skip:   env.ATTESTED_TESTS_SKIP.toInteger(),
                        timestamp:    timestamp,
                    ])

                    writeJSON(file: 'predicate-build.json', json: [
                        job:       params.UPSTREAM_JOB,
                        build:     params.UPSTREAM_BUILD,
                        timestamp: timestamp,
                    ])

                    def images = readJSON(file: 'artifacts.json').builds
                    if (!images) error('artifacts.json contains no builds')

                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
                        container('skaffold') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                withEnv(["IMAGE_REF=${image.tag}"]) {
                                    sh '''
                                        cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate predicate-tests.json \
                                            --type 'https://tuxgrid.com/attestation/tests/v1' \
                                            --yes "$IMAGE_REF"

                                        cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate predicate-build.json \
                                            --type 'https://tuxgrid.com/attestation/build/v1' \
                                            --yes "$IMAGE_REF"
                                    '''
                                }
                            }

                            sh 'rm -f /tmp/cosign.key'
                        }
                    }

                    echo "Attestations created for ${images.size()} image(s)"
                }
            }
        }

        stage('Attest Pipeline') {
            steps {
                script {
                    def timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
                    def stages    = readJSON(text: params.PLATFORM_STAGES_JSON)

                    writeJSON(file: 'predicate-pipeline.json', json: [
                        job:       params.UPSTREAM_JOB,
                        build:     params.UPSTREAM_BUILD,
                        timestamp: timestamp,
                        library: [
                            name: 'jenkins-library',
                            sha:  params.PLATFORM_LIBRARY_SHA,
                        ],
                        platform_verified: [
                            tests_passed:               params.PLATFORM_TESTS_FAILURES.toInteger() == 0,
                            test_count:                 params.PLATFORM_TESTS_COUNT.toInteger(),
                            test_failures:              params.PLATFORM_TESTS_FAILURES.toInteger(),
                            line_coverage_pct:          params.PLATFORM_COVERAGE_PCT.toFloat(),
                            coverage_threshold_pct:     params.PLATFORM_COVERAGE_THRESH.toInteger(),
                            scan_passed:                params.PLATFORM_SCAN_JOB_REF != '',
                            scan_job:                   params.PLATFORM_SCAN_JOB_REF,
                            scan_triggered_by_pipeline: params.PLATFORM_SCAN_JOB_REF != '',
                            artifacts_produced:         true,
                            scm_triggered:              true,
                        ],
                        stages: stages,
                    ])

                    def images = readJSON(file: 'artifacts.json').builds

                    withCredentials([string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY')]) {
                        container('skaffold') {
                            sh "printf '%s' \"\$COSIGN_PRIVATE_KEY\" > /tmp/cosign.key && chmod 600 /tmp/cosign.key"

                            images.each { image ->
                                withEnv(["IMAGE_REF=${image.tag}"]) {
                                    sh '''
                                        cosign attest \
                                            --key /tmp/cosign.key \
                                            --predicate predicate-pipeline.json \
                                            --type 'https://tuxgrid.com/attestation/pipeline/v1' \
                                            --yes "$IMAGE_REF"
                                    '''
                                }
                            }

                            sh 'rm -f /tmp/cosign.key'
                        }
                    }
                }
            }
        }
    }
}
