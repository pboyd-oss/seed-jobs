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
                    def clouds   = readYaml(file: 'clouds/cloud-registry.yml')
                    def versions = readYaml(file: 'config/platform-versions.yaml').tools
                    def allDsl   = new StringBuilder()

                    allDsl.append("folder('teams')    { description('Team workspaces') }\n\n")
                    allDsl.append("folder('platform') { description('Platform-controlled CD pipelines — do not modify') }\n\n")

                    allDsl.append(buildPlatformBakeryFolderDsl())
                    allDsl.append(buildPlatformInfraFolderDsl())
                    allDsl.append(buildPlatformServicesFolderDsl())

                    findFiles(glob: 'platform/bakery/*.yml').each     { f -> allDsl.append(buildBakeryDsl(readYaml(file: f.path).bakery, versions)) }
                    findFiles(glob: 'platform/infra/*.yml').each      { f -> allDsl.append(buildInfraDsl(readYaml(file: f.path).infra)) }
                    findFiles(glob: 'platform/services/*.yml').each   { f -> allDsl.append(buildPlatformServiceDsl(readYaml(file: f.path).service)) }
                    findFiles(glob: 'platform/compliance/*.yml').each { f -> allDsl.append(buildComplianceDsl(readYaml(file: f.path).compliance)) }

                    findFiles(glob: 'teams/*.yml').each { f ->
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
    def triggerBlock = job.cron
        ? "\n    properties { pipelineTriggers { triggers { cron { spec('${job.cron}') } } } }"
        : "\n    triggers { scm('H/5 * * * *') }"

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

private String buildPlatformBakeryFolderDsl() {
    return """
folder('platform/bakery') {
    displayName('bakery')
    description('Platform base image build jobs — all images that form the platform image hierarchy.')
    ${platformAuthBlock()}
}

"""
}

private String buildPlatformInfraFolderDsl() {
    return """
folder('platform/infra') {
    displayName('infra')
    description('Platform-controlled infrastructure pipelines — Terraform GitOps.')
    ${platformAuthBlock()}
}

"""
}

def buildBakeryDsl(Map bakery, Map versions) {
    def auth     = platformAuthBlock()
    def envLines = bakery.env_versions
        ? bakery.env_versions.collect { k ->
            "        env('${k.toUpperCase()}_VERSION', '${versions[k]}')"
          }.join('\n')
        : ''
    def envSection = envLines ? "\n    environmentVariables {\n${envLines}\n    }" : ''

    return """
folder('platform/bakery/${bakery.name}') {
    displayName('${bakery.name}')
    description('${bakery.description}')
    ${auth}
}

pipelineJob('platform/bakery/${bakery.name}/build') {
    displayName('build')
    description('Builds and pushes harbor.tuxgrid.com/platform/${bakery.name} using kaniko.')${envSection}
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('${bakery.git_url}')
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

"""
}

def buildInfraDsl(Map infra) {
    return """
multibranchPipelineJob('platform/infra/${infra.name}') {
    displayName('${infra.name}')
    description('${infra.description}')
    branchSources {
        github {
            id('platform-infra-${infra.name}')
            repoOwner('${infra.repo_owner}')
            repository('${infra.repository}')
            scanCredentialsId('${infra.credentials}')
            buildOriginBranch(true)
            buildOriginBranchWithPR(false)
            buildOriginPRMerge(true)
            buildOriginPRHead(false)
            buildForkPRMerge(false)
            buildForkPRHead(false)
        }
    }
    factory {
        workflowBranchProjectFactory {
            scriptPath('Jenkinsfile')
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

def buildComplianceDsl(Map comp) {
    def auth = comp.auth == 'admin_only'
        ? """authorization {
        permission('hudson.model.Item.Read',   'admin')
        permission('hudson.model.Item.Build',  'admin')
        permission('hudson.model.Item.Cancel', 'admin')
    }"""
        : platformAuthBlock()

    def paramsBlock = comp.params
        ? """    parameters {
${comp.params.collect { p -> "        stringParam('${p.name}', '${p['default']}', '${p.description}')" }.join('\n')}
    }
"""
        : ''

    def triggerBlock = comp.trigger == 'cron'
        ? "\n    properties { pipelineTriggers { triggers { cron { spec('${comp.cron_spec}') } } } }"
        : "\n    triggers { scm('H/5 * * * *') }"

    return """
pipelineJob('platform/${comp.name}') {
    displayName('${comp.name}')
    description('${comp.description}')
    ${auth}
${paramsBlock}    definition {
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
            scriptPath('${comp.script_path}')
        }
    }${triggerBlock}
    logRotator(-1, ${comp.log_keep ?: 50})
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

    def dsl = new StringBuilder()
    dsl.append("""
folder('platform/${t.slug}') {
    displayName('${t.name}')
    authorization {
        ${teamReadBuild}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Configure', 'jenkins-operator')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
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
        permission('hudson.model.Item.Configure', 'jenkins-operator')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'jenkins-operator')
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
        permission('hudson.model.Item.Configure', 'jenkins-operator')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'admin')
    }
    parameters {
        stringParam('UPSTREAM_JOB',   '', 'Full job path of the build that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', '', 'Build number')
        stringParam('GIT_URL',        '', 'Repository URL for Checkov source scan')
        stringParam('GIT_COMMIT',     '', 'Exact commit SHA to check out for Checkov')
        stringParam('ENVIRONMENT',    '', 'Target environment for render + plan (optional)')
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

""")

    t.repositories.each { repo ->
        def repoPath = "platform/${t.slug}/${repo.name}"
        dsl.append("""
folder('${repoPath}') {
    displayName('${repo.name}')
    authorization {
        ${teamReadBuild}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Configure', 'jenkins-operator')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
    }
}

pipelineJob('${repoPath}/source-scan') {
    displayName('source-scan')
    description('Platform source scan for ${repo.name}. Clones at HEAD, auto-detects commit SHA, runs Trivy secrets, tfsec, and Checkov. Call with no parameters before building.')
    authorization {
        ${teamReadBuild}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Configure', 'jenkins-operator')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'admin')
    }
    parameters {
        stringParam('GIT_URL', '${repo.url}', 'Repository URL to scan (pre-populated)')
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
            scriptPath('pipelines/PlatformSourceScanPipeline.groovy')
        }
    }
    logRotator(-1, 50)
}

""")
    }

    return dsl.toString()
}

private String platformAuthBlock() {
    return """authorization {
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Read',      'jenkins-operator')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Build',     'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'jenkins-operator')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Configure', 'jenkins-operator')
    }"""
}

private String buildPlatformServicesFolderDsl() {
    return """
folder('platform/services') {
    displayName('services')
    description('Platform service pipelines — build, scan, deploy, release.')
    ${platformAuthBlock()}
}

"""
}

private String buildPlatformServiceDsl(Map svc) {
    def auth           = platformAuthBlock()
    def buildJob       = "platform/services/${svc.slug}/build"
    def sourceScanJob  = "platform/services/${svc.slug}/source-scan"
    def scanJob        = "platform/services/${svc.slug}/scan"
    def attestJob      = "platform/services/${svc.slug}/attest"
    def deployJob      = "platform/services/${svc.slug}/deploy"
    def releaseJob     = "platform/services/${svc.slug}/release"
    def pipeJob        = "platform/services/${svc.slug}/pipeline"

    return """
folder('platform/services/${svc.slug}') {
    displayName('${svc.name}')
    description('${svc.desc}')
    ${auth}
}

pipelineJob('${buildJob}') {
    displayName('build')
    description('Builds and signs harbor.tuxgrid.com/platform/${svc.slug}.')
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('${svc.git_url}')
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

pipelineJob('${scanJob}') {
    displayName('scan')
    description('Trivy + Checkov + render + scan/v1 attestation for ${svc.slug}.')
    parameters {
        stringParam('UPSTREAM_JOB',   '${buildJob}', 'Build job path that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', 'lastSuccessful', 'Build number or lastSuccessful')
        stringParam('GIT_URL',        '', 'Override: git URL (read from build-info.json when empty)')
        stringParam('GIT_COMMIT',     '', 'Override: git commit SHA (read from build-info.json when empty)')
        stringParam('ENVIRONMENT',    '', 'Target environment for render + plan (optional)')
    }
    environmentVariables {
        env('SERVICE_BUILD_JOB', '${buildJob}')
        env('SERVICE_GIT_URL',   '${svc.git_url}')
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
    logRotator(-1, 30)
}

pipelineJob('${deployJob}') {
    displayName('deploy')
    description('Verify sig + provenance then apply to cluster for ${svc.slug}. No scan/v1 required.')
    parameters {
        stringParam('UPSTREAM_JOB',   '${buildJob}', 'Build job path that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', 'lastSuccessful', 'Build number or lastSuccessful')
    }
    environmentVariables {
        env('SERVICE_BUILD_JOB', '${buildJob}')
        env('SERVICE_WORKLOAD',  '${svc.workload}')
        env('SERVICE_NAMESPACE', '${svc.namespace}')
        env('SERVICE_KIND',      '${svc.kind}')
        env('SERVICE_GIT_URL',   '${svc.git_url}')
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
            scriptPath('pipelines/PlatformDeployPipeline.groovy')
        }
    }
    logRotator(-1, 30)
}

pipelineJob('${releaseJob}') {
    displayName('release')
    description('Full release gate for ${svc.slug}: scan/v1 + Cedar + sha256 verify + apply.')
    parameters {
        stringParam('UPSTREAM_JOB',   '${buildJob}', 'Build job path that produced artifacts.json')
        stringParam('UPSTREAM_BUILD', 'lastSuccessful', 'Build number or lastSuccessful')
        stringParam('ENVIRONMENT',    'dev', 'Target environment (must match scan/v1 predicate)')
    }
    environmentVariables {
        env('SERVICE_BUILD_JOB',          '${buildJob}')
        env('TUXGRID_ENV_DEV_CLOUD',      'kubernetes')
        env('TUXGRID_ENV_DEV_NAMESPACE',  '${svc.namespace}')
        env('TUXGRID_ENV_PROD_CLOUD',     'kubernetes')
        env('TUXGRID_ENV_PROD_NAMESPACE', '${svc.namespace}')
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

pipelineJob('${pipeJob}') {
    displayName('pipeline')
    description('Wrapper for ${svc.slug}: chains build → scan → deploy → release.')
    parameters {
        booleanParam('RUN_BUILD',   true,  'Run the build pipeline')
        booleanParam('RUN_SCAN',    true,  'Run the scan pipeline')
        booleanParam('RUN_DEPLOY',  true,  'Deploy to cluster')
        booleanParam('RUN_RELEASE', false, 'Run full release (scan/v1 + Cedar gate)')
        stringParam('UPSTREAM_BUILD', 'lastSuccessful', 'Build number when RUN_BUILD=false')
        stringParam('ENVIRONMENT',    'dev',             'Target environment for scan and release')
    }
    environmentVariables {
        env('SERVICE_BUILD_JOB',   '${buildJob}')
        env('SERVICE_SCAN_JOB',    '${scanJob}')
        env('SERVICE_DEPLOY_JOB',  '${deployJob}')
        env('SERVICE_RELEASE_JOB', '${releaseJob}')
        env('SERVICE_GIT_URL',     '${svc.git_url}')
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
            scriptPath('pipelines/PlatformServicePipeline.groovy')
        }
    }
    logRotator(-1, 30)
}

pipelineJob('${sourceScanJob}') {
    displayName('source-scan')
    description('Source scan for ${svc.slug}. Clones at HEAD, auto-detects commit SHA, runs Trivy secrets, tfsec, and Checkov. Must pass before attestation is granted.')
    ${auth}
    parameters {
        stringParam('GIT_URL', '${svc.git_url}', 'Repository URL to scan (pre-populated)')
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
            scriptPath('pipelines/PlatformSourceScanPipeline.groovy')
        }
    }
    logRotator(-1, 50)
}

pipelineJob('${attestJob}') {
    displayName('attest')
    description('Triggered by RunListener only. Creates cosign attestations after verified build of ${svc.slug}.')
    ${auth}
    parameters {
        stringParam('UPSTREAM_JOB',              '${buildJob}', 'Full job path of the completed build')
        stringParam('UPSTREAM_BUILD',            '', 'Build number')
        stringParam('PLATFORM_TESTS_COUNT',      '0', '')
        stringParam('PLATFORM_TESTS_FAILURES',   '0', '')
        stringParam('PLATFORM_COVERAGE_PCT',     '0', '')
        stringParam('PLATFORM_COVERAGE_THRESH',  '0', '')
        stringParam('PLATFORM_SCAN_JOB_REF',     '', '')
        stringParam('PLATFORM_STAGES_JSON',      '[]', '')
        stringParam('PLATFORM_LIBRARIES_JSON',   '[]', '')
        stringParam('PLATFORM_AUDIT_ID',         '', '')
        stringParam('PLATFORM_AUDIT_LOG_REF',    '', '')
        stringParam('PLATFORM_AUDIT_LOG_DIGEST', '', '')
        stringParam('PLATFORM_GIT_COMMIT',       '', '')
        stringParam('PLATFORM_GIT_URL',          '', '')
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
    logRotator(-1, 30)
}

"""
}
