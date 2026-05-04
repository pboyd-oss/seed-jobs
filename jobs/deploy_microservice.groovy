pipelineJob('deploy-microservice') {
    description('Build, test and deploy auth-api + data-api')
    definition {
        cpsScm {
            scm {
                gitSource {
                    remote { url('https://github.com/pboyd-oss/microservice-pipeline.git') }
                    branch('main')
                }
            }
            scriptPath('Jenkinsfile')
        }
    }
}
