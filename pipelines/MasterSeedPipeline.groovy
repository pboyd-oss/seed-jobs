pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'base'
            idleMinutes 5
        }
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Validate') {
            steps {
                script {
                    def clouds    = readYaml(file: 'clouds/cloud-registry.yml')
                    def teamFiles = findFiles(glob: 'teams/*.yml')
                    if (!teamFiles) error('No team YAML files found under teams/')
                    teamFiles.each { f ->
                        def team = readYaml(file: f.path)
                        validateTeam(team, clouds, f.path)
                        echo "VALID: ${f.path}"
                    }
                }
            }
        }

        stage('Generate') {
            steps {
                script {
                    def clouds    = readYaml(file: 'clouds/cloud-registry.yml')
                    def teamFiles = findFiles(glob: 'teams/*.yml')
                    def allDsl    = new StringBuilder()

                    allDsl.append("folder('teams')    { description('Team workspaces') }\n\n")
                    allDsl.append("folder('platform') { description('Platform-controlled CD pipelines — do not modify') }\n\n")
                    allDsl.append(buildPlatformInfraDsl())

                    teamFiles.each { f ->
                        def team       = readYaml(file: f.path)
                        def t          = team.team
                        def buildCloud = clouds.clouds.find { it.name == t.build_cloud }
                        def envVars    = buildEnvVars(t, buildCloud)
                        allDsl.append(buildTeamDsl(t, envVars))
                        allDsl.append(buildPlatformReleaseDsl(t, envVars))
                    }

                    jobDsl(
                        scriptText:               allDsl.toString(),
                        sandbox:                  false,
                        removedJobAction:         'DELETE',
                        removedViewAction:        'DELETE',
                        removedConfigFilesAction: 'DELETE'
                    )
                }
            }
        }
    }
}

def validateTeam(Map team, Map clouds, String path) {
    def t          = team.team
    def cloudIndex = clouds.clouds.collectEntries { [(it.name): it] }

    assert t?.slug        : "${path}: team.slug is required"
    assert t?.name        : "${path}: team.name is required"
    assert t?.build_cloud : "${path}: team.build_cloud is required"
    assert t?.members     : "${path}: team.members must not be empty"
    assert t?.repositories: "${path}: team.repositories must not be empty"

    assert t.build_cloud in cloudIndex :
        "${path}: build_cloud '${t.build_cloud}' not defined in cloud-registry.yml"

    assert t.slug in (cloudIndex[t.build_cloud].allowed_teams ?: []) :
        "${path}: team '${t.slug}' is not in allowed_teams for cloud '${t.build_cloud}'"

    t.environments?.each { env ->
        assert env.cloud in cloudIndex :
            "${path}: environment '${env.name}' references unknown cloud '${env.cloud}'"

        assert t.slug in (cloudIndex[env.cloud].allowed_teams ?: []) :
            "${path}: environment '${env.name}' — team '${t.slug}' is not in allowed_teams for cloud '${env.cloud}'"
    }

    t.repositories.each { repo ->
        assert repo.name : "${path}: a repository entry is missing 'name'"
        assert repo.url  : "${path}: repository '${repo.name}' is missing 'url'"
        assert repo.jobs : "${path}: repository '${repo.name}' has no jobs defined"
        repo.jobs.each { job ->
            assert job.name                              : "${path}: a job in '${repo.name}' is missing 'name'"
            assert job.type in ['pipeline', 'multibranch'] :
                "${path}: job '${job.name}' type must be 'pipeline' or 'multibranch', got '${job.type}'"
            if (job.type == 'pipeline') {
                assert job.branch : "${path}: pipeline job '${job.name}' requires 'branch'"
            }
        }
    }
}

def buildEnvVars(Map t, Map buildCloud) {
    def vars = [
        TUXGRID_TEAM_SLUG:               t.slug,
        TUXGRID_BUILD_CLOUD:             t.build_cloud,
        TUXGRID_REGISTRY_URL:            buildCloud.registry.url,
        TUXGRID_REGISTRY_CREDENTIALS_ID: buildCloud.registry.credentials_id,
    ]
    t.environments?.each { env ->
        def upper = env.name.toUpperCase()
        vars["TUXGRID_ENV_${upper}_CLOUD"] = env.cloud
        if (env.namespace) vars["TUXGRID_ENV_${upper}_NAMESPACE"] = env.namespace
    }
    return vars
}

def buildTeamDsl(Map t, Map envVars) {
    def dsl = new StringBuilder()

    dsl.append("""
folder('teams/${t.slug}') {
    displayName('${t.name}')
    description('Build cloud: ${t.build_cloud}')
    authorization {
        ${permissionsBlock(t.members)}
    }
    properties {
        folderProperties {
            properties {
                ${folderEnvBlock(envVars)}
            }
        }
    }
}

""")
    t.repositories.each { repo ->
        def repoFolderExtra = ''
        if (repo.containsKey('coverage_threshold')) {
            repoFolderExtra = """
    properties {
        folderProperties {
            properties {
                stringProperty { key('TUXGRID_COVERAGE_THRESHOLD'); value('${repo.coverage_threshold}') }
            }
        }
    }"""
        }
        dsl.append("folder('teams/${t.slug}/${repo.name}') { displayName('${repo.name}')${repoFolderExtra} }\n\n")
        repo.jobs.each { job ->
            def jobPath = "teams/${t.slug}/${repo.name}/${job.name}"
            dsl.append(job.type == 'multibranch' ? multibranchBlock(jobPath, repo, job) : pipelineBlock(jobPath, repo, job, envVars))
        }
    }

    return dsl.toString()
}

def permissionsBlock(List members) {
    members.collect { m ->
        def lines = [
            "permission('hudson.model.Item.Read',   '${m.username}')",
            "permission('hudson.model.Item.Build',  '${m.username}')",
            "permission('hudson.model.Item.Cancel', '${m.username}')",
        ]
        if (m.role == 'admin') {
            lines << "permission('hudson.model.Item.Configure', '${m.username}')"
            lines << "permission('hudson.model.View.Read',      '${m.username}')"
        }
        lines
    }.flatten().join('\n        ')
}

def folderEnvBlock(Map envVars) {
    envVars.collect { k, v ->
        "                stringProperty { key('${k}'); value('${v}') }"
    }.join('\n')
}

def multibranchBlock(String jobPath, Map repo, Map job) {
    return """
multibranchPipelineJob('${jobPath}') {
    displayName('${job.name}')
    branchSources {
        git {
            id('${jobPath.replace('/', '-')}-source')
            remote('${repo.url}')
            credentialsId('git-deploy-key')
        }
    }
    factory {
        workflowBranchProjectFactory {
            scriptPath('${job.jenkinsfile ?: 'Jenkinsfile'}')
        }
    }
    triggers {
        periodicFolderTrigger { interval('300000') }
    }
    orphanedItemStrategy {
        discardOldItems { numToKeep(10) }
    }
}

"""
}

def pipelineBlock(String jobPath, Map repo, Map job, Map envVars) {
    def envLines     = envVars.collect { k, v -> "        env('${k}', '${v}')" }.join('\n')
    def triggerBlock = job.cron ? "\n    triggers { cron('${job.cron}') }" : "\n    triggers { scm('H/5 * * * *') }"

    return """
pipelineJob('${jobPath}') {
    displayName('${job.name}')
    environmentVariables {
${envLines}
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('${repo.url}')
                        credentials('git-deploy-key')
                    }
                    branch('${job.branch}')
                }
            }
            scriptPath('${job.jenkinsfile ?: 'Jenkinsfile'}')
        }
    }${triggerBlock}
    logRotator(-1, 30)
}

"""
}

// Platform-wide jobs — created once, not per-team.
def buildPlatformInfraDsl() {
    return """
folder('platform/bakery') {
    displayName('bakery')
    description('Platform base image build jobs — all images that form the platform image hierarchy.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

folder('platform/bakery/cosign') {
    displayName('cosign')
    description('Alpine + cosign sidecar image — used by deploy-sec-base-builder pod template')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/bakery/cosign/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/cosign:v2.5.2 using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-cosign.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/bakery/base') {
    displayName('base')
    description('Platform base image — ubuntu:24.04 + apt packages. Parent of deploy-base.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/bakery/base/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/base using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-base.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/bakery/build-base') {
    displayName('build-base')
    description('Platform build base image — make, gcc, build-essential, zip, unzip. For team build steps.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/bakery/build-base/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/build-base using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-build-base.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/bakery/deploy-base') {
    displayName('deploy-base')
    description('Platform deploy base image — cosign, skaffold, terraform. Parent of deploy-sec-base.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/bakery/deploy-base/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/deploy-base using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-deploy-base.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/bakery/deploy-sec-base') {
    displayName('deploy-sec-base')
    description('Platform deploy security image — trivy, tfsec, checkov on top of deploy-base.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/bakery/deploy-sec-base/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/deploy-sec-base using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/deploy-sec-base.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/audit-service') {
    displayName('audit-service')
    description('Platform audit service — build pipeline security event correlation')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/audit-service/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/audit-service using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-audit-service.git')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/tetragon-forwarder') {
    displayName('tetragon-forwarder')
    description('Platform Tetragon forwarder — forwards kernel exec/network events to audit service')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/tetragon-forwarder/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/tetragon-forwarder using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-tetragon-forwarder.git')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

folder('platform/token-service') {
    displayName('token-service')
    description('Platform token service — OIDC-gated STS credential vending')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
}

pipelineJob('platform/token-service/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/token-service using kaniko.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/platform-token-service.git')
                    }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 20)
}

pipelineJob('platform/policy-scan') {
    displayName('policy-scan')
    description('Scans platform IAM and Kubernetes policy code (deploy role boundary, SCP, IRSA, Token Service RBAC) with Trivy + Checkov. Trigger on commits to talos-argocd-proxmox.')
    authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
    parameters {
        stringParam('GIT_URL',    'https://github.com/pboyd-oss/talos-argocd-proxmox.git', 'Platform infrastructure repo')
        stringParam('GIT_COMMIT', 'HEAD', 'Commit SHA or branch ref to scan')
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/seed-jobs.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('pipelines/PlatformPolicyScanPipeline.groovy')
        }
    }
    triggers { scm('H/5 * * * *') }
    logRotator(-1, 50)
}

"""
}

def buildPlatformReleaseDsl(Map t, Map envVars) {
    def envLines = envVars.collect { k, v -> "        env('${k}', '${v}')" }.join('\n')

    // Teams can trigger release and read attest, but cannot configure either.
    // Attest has no Build permission for teams — triggered only by the RunListener.
    def teamReadBuild = t.members.collect { m -> [
        "permission('hudson.model.Item.Read',   '${m.username}')",
        "permission('hudson.model.Item.Build',  '${m.username}')",
        "permission('hudson.model.Item.Cancel', '${m.username}')",
    ]}.flatten().join('\n        ')

    def teamReadOnly = t.members.collect { m ->
        "permission('hudson.model.Item.Read', '${m.username}')"
    }.join('\n        ')

    return """
folder('platform/${t.slug}') {
    displayName('${t.name}')
    authorization {
        ${teamReadBuild}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
    }
}

pipelineJob('platform/${t.slug}/release') {
    displayName('release')
    description('Platform-controlled CD pipeline. Scans, signs, and deploys team artifacts.')
    parameters {
        stringParam('UPSTREAM_JOB',   '', 'Build job path that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', 'lastSuccessful', 'Build number or lastSuccessful')
        stringParam('ENVIRONMENT',    '', 'Target environment (must match team YAML)')
    }
    environmentVariables {
${envLines}
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/seed-jobs.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('pipelines/PlatformReleasePipeline.groovy')
        }
    }
    logRotator(-1, 30)
}

pipelineJob('platform/${t.slug}/attest') {
    displayName('attest')
    description('Triggered by RunListener only. Creates cosign attestations after verified build.')
    authorization {
        ${teamReadOnly}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
    }
    parameters {
        stringParam('UPSTREAM_JOB',              '', 'Full job path of the completed build')
        stringParam('UPSTREAM_BUILD',            '', 'Build number')
        stringParam('PLATFORM_AUDIT_ID',         '', 'Correlation ID from GraphListener')
        stringParam('PLATFORM_AUDIT_LOG_REF',    '', 'URL to audit-log.json artifact')
        stringParam('PLATFORM_TESTS_COUNT',      '0', '')
        stringParam('PLATFORM_TESTS_FAILURES',   '0', '')
        stringParam('PLATFORM_COVERAGE_PCT',     '0', '')
        stringParam('PLATFORM_COVERAGE_THRESH',  '0', '')
        stringParam('PLATFORM_SCAN_JOB_REF',     '', '')
        stringParam('PLATFORM_STAGES_JSON',      '[]', '')
        stringParam('PLATFORM_LIBRARIES_JSON',   '[]', '')
    }
    environmentVariables {
${envLines}
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/seed-jobs.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('pipelines/AttestBuildPipeline.groovy')
        }
    }
    logRotator(-1, 50)
}

pipelineJob('platform/${t.slug}/scan') {
    displayName('scan')
    description('Platform-controlled scan job. Runs Trivy + Checkov on digest-pinned platform images, then signs scan/v1 attestation. Triggered by team builds via the shared library.')
    authorization {
        ${teamReadBuild}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
    }
    parameters {
        stringParam('UPSTREAM_JOB',   '', 'Full job path of the build that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', '', 'Build number')
        stringParam('GIT_URL',        '', 'Repository URL for Checkov source scan')
        stringParam('GIT_COMMIT',     '', 'Exact commit SHA to check out for Checkov')
    }
    environmentVariables {
${envLines}
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('https://github.com/pboyd-oss/seed-jobs.git')
                        credentials('git-deploy-key')
                    }
                    branch('main')
                }
            }
            scriptPath('pipelines/PlatformScanPipeline.groovy')
        }
    }
    logRotator(-1, 50)
}

"""
}
