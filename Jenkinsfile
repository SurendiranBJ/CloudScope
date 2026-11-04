
pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install -r backend/requirements.txt -r backend/requirements-dev.txt
                    mkdir -p test-results
                '''
            }
        }

        stage('Check Versions') {
            steps {
                sh 'python3 --version'
                sh 'node --version'
                sh 'npm --version'
            }
        }

        stage('Run Backend Tests') {
            steps {
                sh '''
                    .venv/bin/python -m pytest backend/tests/ -v --tb=short --junitxml=test-results/backend-tests.xml
                '''
            }
        }

    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'test-results/*.xml'
        }

        success {
            echo 'CloudScope Backend CI Build Successful!'
        }

        failure {
            echo 'CloudScope Backend CI Build Failed!'
        }
    }
}
