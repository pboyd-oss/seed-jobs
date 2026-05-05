// Bootstrap Job DSL script. Run this once (or via JCasC jobs: block) to plant
// the master seed pipeline. After that, the master seed drives everything else.

folder('seed') {
    description('Platform seed jobs — admin access only')
}

pipelineJob('seed/master-seed') {
    description('Validates and regenerates all team folders and jobs from teams/*.yml and cloud-registry.yml.')
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
            scriptPath('pipelines/MasterSeedPipeline.groovy')
        }
    }
    triggers {
        scm('H/5 * * * *')
    }
    logRotator(-1, 20)
}
