pipelineJob('deploy-dummy-nginx') {
    description('Deploy dummy nginx using Kaniko + Skaffold')
    definition {
        cpsScm {
            scm {
                git {
                    remote { url('https://github.com/pboyd-oss/nginx-pipeline.git') }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
}
