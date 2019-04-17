pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean verify'
            }
        }
        stage('Install') {
            steps {
                sh 'mvn install'
            }
        }
    }
}
