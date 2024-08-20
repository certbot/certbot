/* Requires the Docker Pipeline plugin */
pipeline {
    agent { docker { image 'python:3.12.5-alpine3.20' } }
    stages {
        stage('build') {
            steps {
                sh 'python --version'
            }
        }
    }
}