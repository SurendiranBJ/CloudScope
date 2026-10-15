# CloudScope

CloudScope is an AWS cloud security posture and identity analysis application. It collects cloud configuration through AWS APIs, evaluates a supported subset of IAM policy semantics, builds an identity and resource graph, and presents findings, attack paths, and evidence in a React web interface.

> **Project status:** CloudScope is an actively developed academic and portfolio prototype. It is not currently certified or validated for production or shared multi-customer hosting. See Industry readiness and the current audit for verified capabilities and open work.

## What it does

- Scans selected AWS accounts and regions using local AWS credentials or a registered cross-account IAM role.
- Collects IAM identities, policies, and supported cloud resources; scan results include partial/failure information where available.
- Builds a graph of identities, policies, relationships, and reachable resources.
- Reports potential static attack paths separately from activity corroborated by CloudTrail data.
- Displays finding evidence, lifecycle status, remediation guidance, scan provenance, and risk summaries.
- Provides what-if IAM policy simulations. Drafts are stored in the application database, scoped to an analyst and project, and are never applied to AWS.
- Offers optional evidence-based AI explanations through the configured Gemini provider. Selected scan context is sent to this provider; use it only where your data policy permits.
- Stores scan snapshots and operational records in relational storage, uses Redis for coordination/cache, and uses Neo4j with NetworkX graph analysis.

## Architecture

AWS account and regions -> read-only collection -> inventory and scan evidence -> supported IAM/security analysis -> identity/resource graph -> attack paths and blast radius -> findings and API -> React dashboard and graph UI.

Relational storage holds snapshots and workflow records. Redis coordinates scans and caches data. Neo4j stores graph topology. The exact role of each store and its failure behavior should be validated for a target deployment.

## Technical overview

### Scan and analysis lifecycle

1. An administrator registers an AWS account project and configures its target role ARN. CloudScope creates a project-specific ExternalId; the target role trust policy must require that value and trust only the intended source principal.
2. An administrator verifies the role. The backend obtains source credentials from the configured AWS credential chain and calls STS `AssumeRole` for the registered target role.
3. A manual scan collects supported IAM and AWS resource metadata in the selected regions using AWS read APIs. Collection is best-effort: unavailable permissions or services may yield partial results and should be reviewed in scan status and diagnostics.
4. The scanner normalizes collected records, evaluates supported security checks and IAM relationships, persists a snapshot, and refreshes graph and finding views. Requests that load account data include the selected project scope.
5. Graph analysis models identity-to-policy-to-resource reachability. Attack paths are configuration-based possibilities; event-backed observations are distinct and depend on the CloudTrail event window and permissions.

Simulation is a local what-if workflow: analyst changes are saved as drafts and compared with the current analysis. It does not call AWS write APIs. Explain with AI is optional; the backend sends selected finding or path context to the configured Gemini provider and returns a generated explanation. Do not send data to an external provider unless permitted by your organization's data policy.

### Components and code map

| Area | Main implementation | Responsibility |
| --- | --- | --- |
| API and application lifecycle | `backend/app/main.py`, `backend/app/routers/` | FastAPI setup, lifecycle hooks, API route groups, health and readiness endpoints. |
| Authentication and roles | `backend/app/security/` | JWT/OIDC validation, principal construction, development identity mode, role dependencies. |
| AWS access | `backend/app/services/aws/session.py` | Source session resolution and project role assumption with ExternalId. |
| Collection and snapshots | `backend/app/services/scanner/` | Scan coordination, collection snapshots, current snapshot selection and cache invalidation. |
| Project scope | `backend/app/routers/projects.py`, `backend/app/services/project_context.py`, `backend/app/security/project_scope.py` | Project CRUD, access checks, selected-project resolution and request scoping. |
| Persistence | `backend/app/persistence/` | SQLAlchemy models, database initialization, project and scan repositories. |
| Graph analysis | `backend/app/tools/`, `backend/app/services/attack/` | Graph diagnostics, IAM trust and policy analysis, attack path generation. |
| Web interface | `frontend/src/pages/`, `frontend/src/components/` | Dashboard, project workflows, findings, graph exploration and reports. |
| API client | `frontend/src/api/` | Typed feature-level API wrappers on the shared Axios client. |

### API areas

The API is rooted at `/api/v1` (interactive local documentation at `/docs`). Route groups cover projects, scans, dashboard, resources, IAM users and roles, policies, relationships, graph, attack paths, findings, risks, alerts, reports, simulation, Copilot, audit, settings, operations, and health. Authentication and minimum role requirements vary by endpoint; see [RBAC](docs/rbac.md). Health/readiness probes are separate from authenticated operational diagnostics.

### Persistence and isolation model

SQL storage keeps project and scan metadata, snapshots, findings workflow state, audit records, and simulation drafts. Redis is used for coordination and cache functions; Neo4j stores graph topology. Local Compose defaults to SQLite for relational storage, which is suitable for development but does not establish a production database, backup, migration, or recovery strategy. Project-aware scan requests resolve the selected project, use its verified role, and filter project-bound data. The scheduler is not project-aware, and independent review of complete tenant isolation remains open.

### Trust and analysis boundaries

- The AWS role's IAM policy is the actual collection permission boundary. The sample policy has wildcard resources for AWS list/describe APIs; review it against the selected collectors and your own constraints.
- IAM semantics are implemented by CloudScope and do not represent every AWS policy layer, condition, resource policy, or service-specific rule. Treat unsupported semantics as uncertain.
- A graph edge records a modeled relationship; it is not proof of exploitation. A path is a possible sequence under the model, not a confirmed incident.
- Risk ranking is application-specific. AI explanations are generated content, not authoritative remediation instructions.
- Project scoping is an implementation foundation, not a guarantee of hosted multi-tenant readiness. See [industry readiness](docs/industry-readiness.md) for remaining operational and security work.

## Getting started

### Docker Compose development stack

1. Copy .env.example to .env.
2. Set a strong local NEO4J_PASSWORD and JWT_SECRET. For a local-only development stack, set ENVIRONMENT=development, AUTH_ENABLED=false, AUTH_REQUIRED=false, and DEV_AUTH_MODE=true. Never use development authentication settings in a deployed environment.
3. Configure AWS_PROFILE, AWS_DEFAULT_REGION, and AWS_CREDENTIALS_DIR for the read-only AWS principal/profile you want to use. Docker mounts the credentials directory read-only.
4. From the repository root, run: docker compose -f compose.yaml up --build
5. Open http://localhost:8080. The backend is at http://localhost:8000 and API docs are at http://localhost:8000/docs.

For frontend development with Vite, start the backend and its Neo4j/Redis dependencies first, then run npm install and npm run dev inside frontend. Vite uses http://localhost:8000/api/v1 unless VITE_API_BASE_URL is set.

### Register an AWS account project

In Projects, register an AWS account and the cross-account role ARN CloudScope should assume. Verify the role before scanning. CloudScope generates a per-project ExternalId; the AWS role trust policy must use it and grant only the collection permissions required by your environment.

The project selector scopes account data requests to the selected project. If an owner has multiple projects, select one before viewing account data. The scheduler is not yet project-aware; use a manual scan after selecting a verified project.

## Security and analysis boundaries

- Configure AWS IAM permissions as read-only. Application behavior is not a substitute for an AWS permission boundary.
- IAM evaluation is custom and does not reproduce every AWS authorization layer or condition-key behavior. Treat unsupported/incomplete cases as uncertain and validate important decisions in AWS.
- A potential attack path means the modeled configuration permits a graph transition; it does not prove an attacker used it. CloudTrail correlation depends on collected events and configured coverage.
- Risk scores are CloudScope model outputs, not AWS or regulatory verdicts.
- AI output is generated by an external model and may be incomplete. Validate recommendations against source evidence before acting.
- Simulation drafts and remediation guidance do not perform AWS changes.
- Project isolation has implementation and regression-test coverage, but has not received an independent security review or deployment-scale tenant-isolation audit.

## Technology

- Backend: Python, FastAPI, SQLAlchemy, Boto3, NetworkX, Neo4j driver, Redis, APScheduler.
- Frontend: React, TypeScript, Vite, TanStack Query, Cytoscape.js, Recharts, Tailwind CSS.
- Optional AI: Google Gemini through the server-side Google GenAI SDK.

## Verification commands

From the repository root:
- Backend: cd backend; python -m pytest -q
- Frontend tests: cd frontend; npm run test
- Frontend lint: cd frontend; npm run lint
- Frontend build: cd frontend; npm run build

See docs/final-verification.md for checks and limits from the latest local verification. Passing local tests does not certify production readiness.

## Documentation

- docs/industry-readiness.md - capabilities and open milestones
- docs/final-audit.md - current source review
- docs/release-readiness.md - release decision and evidence
- docs/deployment.md and docs/configuration-reference.md - setup
- docs/authentication.md, docs/rbac.md, docs/security.md, docs/secrets.md - security
- docs/operations.md, docs/observability.md, docs/audit-logging.md - operations
- docs/real-aws-validation.md - AWS validation record
