# CloudScope Secret Management & Data Sanitization

## 1. Zero AWS Write & Remediation Guarantee
CloudScope is architected with a non-negotiable security invariant:
- **Strictly Read-Only AWS Role**: The AWS IAM principal used by the scanner possesses only `Get*`, `List*`, and `Describe*` permissions.
- **No Mutation Operations**: The scanner contains no code to create, update, delete, attach, or remediate resources in AWS.
- **What-If Simulation Isolation**: All policy modifications and remediations are executed exclusively in-memory within the simulation engine and graph data models. No changes are ever applied to AWS.

## 2. Centralized Secret Sanitization (`sanitizer.py`)
To prevent sensitive tokens, credentials, or private keys from leaking into log files, audit event records, metrics, or AI Copilot prompts, all data is filtered through `backend/app/utils/sanitizer.py`:

### Detected and Redacted Patterns:
- **AWS Access Key IDs**: `\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b` -> `AKIA****************`
- **AWS Secret Access Keys**: `(aws_secret_access_key|secret_key) = [A-Za-z0-9/+=]{40}` -> `[REDACTED]`
- **AWS Session Tokens**: `(aws_session_token|session_token) = [A-Za-z0-9/+=]{50,}` -> `[REDACTED]`
- **Google / Gemini API Keys**: `\bAIza[0-9A-Za-z_-]{30,40}\b` -> `[REDACTED_GEMINI_KEY]`
- **Private Keys**: `-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----` -> `[REDACTED_PRIVATE_KEY]`
- **Bearer Tokens**: `Bearer [A-Za-z0-9-_.]+\.[A-Za-z0-9-_.]+\.[A-Za-z0-9-_.]+` -> `Bearer [REDACTED_JWT]`
- **Dictionary Key Masking**: Any dict key containing `password`, `secret`, `private_key`, `token`, `credential`, `auth_key`, `api_key`, `apikey`, `access_key` is automatically masked as `[REDACTED]`.

## 3. Best Practices for Secret Injection
- **Docker Compose**: Never commit `.env` files with production secrets. Use `.env.example` as a template.
- **Kubernetes**: Inject secrets via Kubernetes Secret objects mounted as environment variables (`NEO4J_PASSWORD`, `JWT_SECRET`, `GEMINI_API_KEY`).
- **AWS IAM**: Prefer AWS IAM Roles for Service Accounts (IRSA) or IAM Instance Profiles over static `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
