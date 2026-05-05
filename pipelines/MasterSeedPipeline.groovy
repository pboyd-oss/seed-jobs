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

                    allDsl << "folder('teams')    { description('Team workspaces') }\n\n"
                    allDsl << "folder('platform') { description('Platform-controlled CD pipelines — do not modify') }\n\n"
                    allDsl << buildPlatformInfraDsl()

                    teamFiles.each { f ->
                        def team       = readYaml(file: f.path)
                        def t          = team.team
                        def buildCloud = clouds.clouds.find { it.name == t.build_cloud }
                        def envVars    = buildEnvVars(t, buildCloud)
                        allDsl << buildTeamDsl(t, envVars)
                        allDsl << buildPlatformReleaseDsl(t, envVars)
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

    dsl << """
folder('teams/${t.slug}') {
    displayName('${t.name}')
    description('Build cloud: ${t.build_cloud}')
    authorization {
        blocksInheritance(true)
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

"""
    t.repositories.each { repo ->
        dsl << "folder('teams/${t.slug}/${repo.name}') { displayName('${repo.name}') }\n\n"
        repo.jobs.each { job ->
            def jobPath = "teams/${t.slug}/${repo.name}/${job.name}"
            dsl << (job.type == 'multibranch' ? multibranchBlock(jobPath, repo, job) : pipelineBlock(jobPath, repo, job, envVars))
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
pipelineJob('platform/policy-scan') {
    displayName('policy-scan')
    description('Scans platform IAM and Kubernetes policy code (deploy role boundary, SCP, IRSA, Token Service RBAC) with Trivy + Checkov. Trigger on commits to talos-argocd-proxmox.')
    authorization {
        blocksInheritance(true)
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
        permission('hudson.model.Item.Configure', 'admin')
    }
    parameters {
        stringParam('GIT_URL',    'git@git.tuxgrid.com:admin/talos-argocd-proxmox.git', 'Platform infrastructure repo')
        stringParam('GIT_COMMIT', 'HEAD', 'Commit SHA or branch ref to scan')
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('git@git.tuxgrid.com:admin/seed-jobs.git')
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
        blocksInheritance(true)
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
                        url('git@git.tuxgrid.com:admin/seed-jobs.git')
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
        blocksInheritance(true)
        ${teamReadOnly}
        permission('hudson.model.Item.Configure', 'admin')
        permission('hudson.model.Item.Read',      'admin')
        permission('hudson.model.Item.Build',     'admin')
        permission('hudson.model.Item.Cancel',    'admin')
    }
    parameters {
        stringParam('UPSTREAM_JOB',   '', 'Full job path of the completed build')
        stringParam('UPSTREAM_BUILD', '', 'Build number')
    }
    environmentVariables {
${envLines}
    }
    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url('git@git.tuxgrid.com:admin/seed-jobs.git')
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
        blocksInheritance(true)
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
                        url('git@git.tuxgrid.com:admin/seed-jobs.git')
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
