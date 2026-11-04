
pipeline {
    agent any

    stages {
        stage('Check out') {
            steps {
                echo 'Checking teh code out'
                checkout scm
            }
        }

        stage('Setup Node') {
            steps {
                echo 'checking the result dir is available'
                echo 'Checking version'
                sh 'python3 --version'
                sh 'node --version'
                sh 'npm --version'
            }
        }

        stage('Requirement Install') {
            steps {
                echo 'pip the installs'
                sh '''
                    python3 -m venv .venv
                    .venv/bin/python -m pip install --upgrade pip
                    .venv/bin/python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
                    mkdir -p test-results
                '''
            }
        }

        stage('Run Core & Api tests') {
            steps {
                echo 'running all the cases like region phasees tests'
                script {
                    def key = sh(
                        script: '''
.venv/bin/python -m pytest \
backend/tests/test_api_endpoints.py \
backend/tests/test_aws_session.py \
backend/tests/test_region_cache.py \
backend/tests/test_phase2_audit_logging.py \
backend/tests/test_phase2_authentication_rbac.py \
backend/tests/test_phase2_distributed_lock.py \
backend/tests/test_phase2_durability_multi_instance.py \
backend/tests/test_phase2_health_endpoints.py \
backend/tests/test_phase2_rate_limiting.py \
-v --tb=short \
--junitxml=test-results/backend-core.xml
                        ''',
                        returnStatus: true
                    )

                    if (key == 0) {
                        echo 'all cases passes'
                    } else {
                        echo 'some cases failed in the RUN Core & api tests'
                        error('some cases failed in the RUN Core & api tests')
                    }
                }
            }
        }

        stage('run security engine tests') {
            steps {
                echo 'running the run security engine tests'
                script {
                    def found = sh(
                        script: '''
.venv/bin/python -m pytest \
backend/tests/test_policy_evaluator.py \
backend/tests/test_resource_boundary_and_conditions.py \
backend/tests/test_trust_assumption.py \
backend/tests/test_phase2_iam_hardening.py \
backend/tests/test_cloudtrail_correlation.py \
backend/tests/test_phase4_cloudtrail_correlation.py \
-v --tb=short \
--junitxml=test-results/backend-security-engines.xml
                        ''',
                        returnStatus: true
                    )

                    if (found == 0) {
                        echo 'all cases passes'
                    } else {
                        echo 'some cases failed in the run security engine tests'
                        error('some cases failed in the run security engine tests')
                    }
                }
            }
        }

        stage('run graph & attack path tests') {
            steps {
                echo 'the graph testing is running'
                script {
                    def op = sh(
                        script: '''
.venv/bin/python -m pytest \
backend/tests/test_graph_construction.py \
backend/tests/test_duplicate_nodes.py \
backend/tests/test_graph_reconciliation.py \
backend/tests/test_identity_graph_resources.py \
backend/tests/test_path_engine.py \
backend/tests/test_attack_path_grouping.py \
backend/tests/test_carol_lambda_effective_access.py \
backend/tests/test_effective_access_multihop.py \
backend/tests/test_role_target_downstream_assets.py \
backend/tests/test_phase3_provenance_attack_paths.py \
-v --tb=short \
--junitxml=test-results/backend-graph-and-attack-paths.xml
                        ''',
                        returnStatus: true
                    )

                    if (op == 0) {
                        echo 'all cases passes'
                    } else {
                        echo 'some cases failed in the run graph & attack path tests'
                        error('some cases failed in the run graph & attack path tests')
                    }
                }
            }
        }

        stage('Completion of the ci testing only backend testing') {
            steps {
                echo 'the ci of the backend is successfully '
                echo 'mission one success(vetri)'
            }
        }
    }
}
