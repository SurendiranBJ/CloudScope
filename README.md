# CloudScope — AWS Cloud Security Posture Management & Identity Attack Path Analysis

[![CloudScope CI](https://github.com/SurendiranBJ/CloudScope/actions/workflows/ci.yml/badge.svg?branch=sura)](https://github.com/SurendiranBJ/CloudScope/actions/workflows/ci.yml)

CloudScope is a Cloud Security Posture Management (CSPM) and Cloud Infrastructure Entitlement Management (CIEM) platform built for Amazon Web Services (AWS). It evaluates effective permissions using Abstract Syntax Tree (AST) IAM policy document analysis, models multi-hop identity and resource relationships in **Neo4j** and **NetworkX**, identifies lateral movement and privilege escalation attack vectors, and delivers evidence-based security posture scores via an interactive **React** interface.

---

## 🏛️ Unified Architecture & Scanning Pipeline

CloudScope operates as a single, continuous, unified security analysis pipeline:

```
                      ┌────────────────────────────────────────┐
                      │              AWS Account               │
                      └───────────────────┬────────────────────┘
                                          │ Boto3 Read-Only Collectors
                                          ▼
                      ┌────────────────────────────────────────┐
                      │             AWS Inventory              │
                      │  (IAM, S3, EC2, Lambda, Secrets, RDS)  │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │    IAM / Security Policy Evaluator     │
                      │    (AST Statement Parser & Matcher)    │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │          Neo4j Graph Database          │
                      │  (Idempotent MERGE on Stable Node IDs) │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │        NetworkX Graph Analytics        │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │          Attack Path Engine            │
                      │   (Privilege Escalation & Lateral)     │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │          Blast Radius Engine           │
                      │  (Reachable Cloud Resources Isolation) │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │      Deterministic Risk Engine         │
                      │   (Factor-Based 0-100 & 5 Categories)  │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │     CloudTrail Activity Analysis       │
                      │  (AssumeRole, Policy Mod, Idempotency) │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │       Dynamic Graph Correlation        │
                      │    (Runtime Activity & Graph Edges)    │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │           FastAPI REST API             │
                      └───────────────────┬────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │         React / Cytoscape UI           │
                      │     (Consolidated DAG Path Cards)      │
                      └────────────────────────────────────────┘
```

---

## 🔑 Key Capabilities

1. **True AST IAM Policy Evaluation (Zero Name Heuristics)**:
   - Full statement evaluation of `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Principal`, and `Condition`.
   - Explicit `Deny` override logic.
   - Resource ARN matching for S3 buckets, Secrets Manager secrets (with random suffixes), RDS DB instances, DynamoDB tables, EC2 instances, and Lambda functions.
   - Never infers permissions or vulnerability from names (e.g. `"admin"` or `"secret"` in a role/policy name is ignored).

2. **AssumeRole Trust Policy Analysis**:
   - Structured parsing for wildcards (`*`), account root ARNs, specific IAM user/role ARNs, and AWS service principals.

3. **Idempotent Neo4j Topology**:
   - Uses deterministic conceptual IDs (`aws:user:<name>`, `aws:role:<arn>`, `aws:policy:<arn>`, `aws:s3:<name>`, `aws:secret:<arn>`, `aws:ec2:<id>`, etc.).
   - Employs `MERGE` queries so configuration sync never destroys CloudTrail activity history.

4. **Multi-Source & Multi-Target Attack Path Consolidation**:
   - Computes multi-hop paths to high-value cloud targets and administrative roles.
   - Frontend groups duplicate paths sharing identical security chains into clean, multi-target branching DAG diagrams.
   - Preserves backend `orderedRelationships` (`CAN_ASSUME`, `HAS_POLICY`, `ALLOWS`, `ASSUMED_ROLE`).

5. **Evidence-Based Risk Scoring**:
   - Deterministic factor points bounded strictly within `0–100`.
   - Global Posture weighting: IAM Security (30%), Resource Security (25%), Attack Path Risk (25%), Identity Hygiene (10%), Monitoring / Audit (10%).

6. **CloudTrail Runtime Activity Correlation**:
   - Normalizes management events (`AssumeRole`, `CreateAccessKey`, `AttachRolePolicy`, `PutBucketPolicy`, etc.) with `eventId` idempotency.
   - Injects dynamic activity edges into graph analysis and flags `OBSERVED_ATTACK_ACTIVITY`.

7. **Dynamic Region Discovery & Regional Failure Isolation**:
   - **Default Dynamic Discovery**: Automatically discovers all usable/enabled AWS regions via `DescribeRegions` (`opt-in-status`). Configured via `SCAN_REGIONS=""`.
   - **Configured Region Override**: Supports explicit comma-separated region lists (e.g. `SCAN_REGIONS="ap-south-1,eu-north-1"`) or runtime single-region selection.
   - **Regional Failure Isolation (`FAILED != EMPTY`)**: API errors or timeouts in a region produce `FAILED: <error>` rather than false empties. Overall scan reflects `PARTIAL` status.
   - **Failed-Region Data Preservation**: Non-destructive reconciliation preserves cached resources for failed regions so network blips never delete valid infrastructure from the inventory or graph.
   - **Running-EC2 Security View**: Distinguishes collected inventory from security posture visibility; only running EC2 instances participate in the security graph, risk calculation, and attack paths.

8. **Hardened Multi-Stage IAM Evaluation & Aurora / RDS IAM Authentication**:
   - **Explicit 4-State Decision Model**: Every authorization evaluation yields `ALLOWED`, `DENIED`, `CONDITIONAL`, or `NOT_APPLICABLE`.
   - **Explicit Deny Precedence**: An explicit Deny in any matching statement (identity policy, attached policy, or boundary) immediately overrides any Allow.
   - **Permissions Boundary Intersection**: When a boundary is present, access requires both an explicit Allow in identity/group policies AND an explicit Allow in the boundary policy.
   - **Evidence-Based Explanation**: Every authorization check and effective access calculation produces structured evidence with matched statements, action patterns, resource patterns, conditions, and boundary evaluation.
   - **RDS Management vs. Database Connect Separation**: Strictly distinguishes control-plane actions (`rds:DescribeDBClusters`, `rds:ModifyDBCluster`) from data-plane database authentication (`rds-db:connect`). `rds:*` or `rds:Describe*` never confers database login rights.
   - **Aurora / RDS IAM DB User Modeling**: Maps `arn:aws:rds-db:<region>:<account>:dbuser:<db-id>/<username>` in graph analytics via `Policy -> DB_CONNECT -> AuroraDBUser -> BELONGS_TO -> RDS` with MITRE ATT&CK mapping (`T1078`, `T1530`).
   - **Conditional Safety**: Statements with unresolved conditions evaluate to `CONDITIONAL` and are blocked from creating false-positive unconditional `ALLOWS` graph edges.

9. **Security Graph Provenance & Explainable Attack Paths (Phase 3)**:
   - **Centralized Semantic Edge Validation**: Centralized validation (`validate_edge`) ensures every relationship adheres to explicit AWS authorization semantics. Illegal edges (e.g. `Secret -[ALLOWS]-> User`) are deterministically rejected with diagnostic feedback.
   - **Provenance-Backed Relationships**: All graph edges (`MEMBER_OF`, `HAS_POLICY`, `CAN_ASSUME`, `EXECUTES_WITH`, `DB_CONNECT`, `ALLOWS`) carry full authorization provenance metadata: `policy_name`, `statement_sid`, `action`, `decision`, `why`, `region`, and `evidence`.
   - **Dual-Signature `iam:PassRole` Escalation Analysis**: Evaluates `iam:PassRole` permission to pass an elevated target role (risk score >= 60) that trusts an AWS compute service (`lambda.amazonaws.com`, `ec2.amazonaws.com`).
   - **Authoritative Effective-Access Blast Radius**: Strictly counts unique reachable cloud data resources (S3, Secrets, RDS, DynamoDB), cleanly separating operational target assets from intermediate IAM roles and policies.
   - **Explainable Attack Path Details**: Attack paths return complete `ordered_nodes`, `ordered_relationships`, and step-by-step `transition_evidence` showing exact authorization rationale and region context for every hop.

10. **CloudTrail Runtime Activity Analysis & 4-State Correlation (Phase 4)**:
   - **Idempotent Ingestion & Timestamp Normalization**: Deduplicates events by `eventId` and standardizes timezone-aware ISO 8601 timestamps, source IPs, user agents, and error codes.
   - **Multi-Principal Normalization**: Authoritatively normalizes `IAMUser`, `AssumedRole` (extracting parent role), `Root`, and `FederatedUser` callers.
   - **Distinct 4-State Security Classification**:
     - `POSSIBLE_CAPABILITY`: Permitted by static IAM policy; no runtime execution recorded in CloudTrail.
     - `OBSERVED_ACTIVITY`: Recorded in CloudTrail; anomalous or outside modeled static graph topology.
     - `CORRELATED_ACTIVITY`: Permitted by static configuration AND corroborated by observed CloudTrail activity.
     - `OBSERVED_ATTACK_ACTIVITY`: Concrete CloudTrail activity verified along the execution hops of a discovered attack path.
   - **Zero False-Positive Exploitation Claims**: Errors (`AccessDenied`, `Client.UnauthorizedOperation`) are strictly isolated and never treated as successful transitions. Exploitation is never claimed unless verifiable CloudTrail events match the attack vector.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, Uvicorn, Boto3, Pydantic v2, NetworkX, Neo4j Python Driver, APScheduler
- **Database & Cache**: Neo4j Graph Database (Bolt Protocol), Redis (Cache layer with automatic in-memory fallback), Local Durable State Store
- **Frontend**: React 19, Vite, TypeScript, Tailwind CSS, Lucide React, Cytoscape.js (`cytoscape-dagre`), TanStack Query, Recharts

---

## 🚀 Setup & Installation

### 1. Prerequisites
- Python 3.10+
- Node.js 18+
- Docker & Docker Compose (optional for Neo4j/Redis)
- AWS CLI configured with a read-only profile named `identityscope-scanner`:
  ```bash
  aws configure --profile identityscope-scanner
  ```

### 2. Scanner IAM Permissions
The scanner requires read-only metadata inspection permissions. **Secrets Manager secret values are never retrieved** (only secret metadata via `DescribeSecret` / `ListSecrets`).

Minimal required managed policies:
- `SecurityAudit`
- `ViewOnlyAccess`

### 3. Running with Docker Compose
Start Neo4j, Redis, and the Backend with a single command:
```bash
docker compose up -d
```
Neo4j Console: `http://localhost:7474` (Credentials: `neo4j` / `password`)

### 4. Running Locally

#### Backend Setup
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate      # Windows
source venv/bin/activate    # macOS/Linux

pip install -r requirements.txt
pip install -r requirements-dev.txt

# Start FastAPI server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Frontend Web UI: `http://localhost:5173`

---

## 📊 Deterministic Risk Scoring Model

### Entity Risk Score (0–100)
Scores are computed from discrete, itemized evidence factors:

| Category | Finding Code | Points | Description |
|---|---|:---:|---|
| **Identity Hygiene** | `MFA_DISABLED` | +15 | User has no virtual or hardware MFA configured |
| | `STALE_CREDENTIALS` | +10 | Password / access key inactive > 90 days |
| **Permissions** | `WILDCARD_ALLOW_ALL` | +30 | Policy statement allows `Action: *` on `Resource: *` |
| | `WILDCARD_ACTION` | +20 | Policy allows `Action: *` on specific resource |
| | `WILDCARD_RESOURCE` | +15 | Policy allows specific action on `Resource: *` |
| | `PRIVILEGE_ESCALATION_PERMS`| +25 | Permissions include dangerous escalation actions (`iam:PassRole`, `iam:AttachRolePolicy`, etc.) |
| **Trust Boundary** | `WILDCARD_TRUST_PRINCIPAL` | +30 | Role trust policy permits `Principal: *` |
| | `CROSS_ACCOUNT_TRUST` | +15 | Trust policy allows external AWS account root |
| **Resource Security** | `S3_PUBLIC_EXPOSURE` | +35 | S3 bucket has Block Public Access disabled or public policy |
| | `S3_UNENCRYPTED` | +15 | Server-side encryption is disabled |
| | `SECRET_NO_ROTATION` | +15 | Automatic rotation is disabled |
| | `EC2_PUBLIC_IP` | +20 | Instance has public IPv4 and overprivileged profile |

### Severity Thresholds
- **Critical**: `80 – 100`
- **High**: `60 – 79`
- **Medium**: `40 – 59`
- **Low**: `0 – 39`

### Global Security Posture Score (0–100)
$$\text{Overall Score} = (0.30 \times \text{IAM}) + (0.25 \times \text{Resource}) + (0.25 \times \text{AttackPath}) + (0.10 \times \text{Hygiene}) + (0.10 \times \text{Monitoring})$$

---

## 🌲 Attack Path Consolidation (Branching DAGs)

When multiple attack paths share a common security chain, the frontend consolidates them into a single branching card:

```
                      Alice ─┐
                      Bob ───┼→ OverlyTrustingAdminRole → AdministratorAccess
                      Carol ─┘                                │
                                             ┌────────────────┼────────────────┐
                                             ▼                ▼                ▼
                                         S3-Bucket-A      S3-Bucket-B     DB-Secret-Key
```

---

## 🛡️ Phase 5: Unified Security Findings & Lifecycle Management

CloudScope integrates static posture analysis, privilege escalation graph vectors, and runtime CloudTrail correlation into a unified, evidence-based security finding lifecycle:

### Canonical Finding Model (`SecurityFinding`)
Every finding generated by the platform adheres to a strictly structured schema:
- **`finding_id`**: Deterministic SHA-256 hash computed from finding type, resource ID, and principal identity (no random or timestamped IDs for static findings).
- **`title` & `description`**: Plain-English security description explaining the exact risk.
- **`severity`**: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- **`category`**: `IDENTITY_EXCESSIVE_PRIVILEGE`, `DATA_EXPOSURE`, `NETWORK_EXPOSURE`, `SECRETS_MANAGEMENT`, `ATTACK_PATH_RISK`, `RUNTIME_ACTIVITY`, or `SECURITY_HYGIENE`.
- **`status`**: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, or `SUPPRESSED`.
- **`source`**: `STATIC_ANALYSIS`, `ATTACK_PATH`, or `CLOUDTRAIL_CORRELATION`.
- **`remediation`**: Actionable guidance including:
  - **`summary`**: Direct, clear explanation of the corrective action.
  - **`action_type`**: `IAM_POLICY_REVISION`, `ENABLE_MFA`, `S3_BLOCK_PUBLIC_ACCESS`, `ROTATE_SECRET`, `RESTRICT_SECURITY_GROUP`, or `REVIEW_CLOUDTRAIL_ACTIVITY`.
  - **`steps`**: Ordered, numbered remediation procedures.
  - **`priority`**: `IMMEDIATE`, `SCHEDULED`, or `PLANNED`.
  - **`read_only_notice`**: Explains why CloudScope provides guidance rather than modifying production AWS resources.
- **`evidence`**: Raw dictionary containing resource attributes, policy statements, and CloudTrail event records backing the finding.
- **`risk_factors`**: Itemized score contributions explaining how the risk score was calculated.

### Finding Lifecycle & Regional Fault Isolation
- Findings transition cleanly through `OPEN` → `ACKNOWLEDGED` → `RESOLVED` / `SUPPRESSED`.
- Scans reconcile active findings against current scan results. If a resource or misconfiguration is removed, its finding transitions to `RESOLVED` with `resolved_at` timestamp.
- **Regional Isolation**: If an AWS region fails or times out during a scan, CloudScope will **never** resolve findings belonging to that failed region, preventing false positive resolution loops.

### Real-Data-Only Reporting
- All mock compliance percentages and hardcoded finding counts have been eradicated.
- Reports and export summaries (PDF, CSV, JSON) are computed strictly from verified scan findings and live AWS inventory. If no scan has been executed, reports present an explicit empty state.

---

## ⚡ Phase 6: Hardening, Performance Optimization, Docker Reliability & E2E Validation

Phase 6 elevates CloudScope to production-hardened prototype reliability, high-resolution performance observability, and containerized deployment readiness:

### 1. Dashboard Refinement & Four Security States
The CloudScope dashboard clearly separates and visualizes the four core security states:
- **`POSSIBLE_CAPABILITY`**: Static authorization exists in the security graph, but no runtime CloudTrail activity has been recorded.
- **`OBSERVED_ACTIVITY`**: Telemetry recorded in CloudTrail without verified static IAM authorization (anomalous dynamic activity).
- **`CORRELATED_ACTIVITY`**: Verified static IAM authorization actively exercised and corroborated by CloudTrail management events.
- **`OBSERVED_ATTACK_ACTIVITY`**: Telemetry matches an exact multi-hop privilege escalation or lateral movement transition along an identified attack path.
- **Cold Cache Safety**: All dashboard endpoints provide safe default structures and onboarding banners when the database or cache is uninitialized, with zero hardcoded or mock metrics.
- **Scan Freshness Tracking**: Accurately differentiates `lastCompletedScanAt` (timestamp of the last finished execution, including partial scans) from `lastSuccessfulScanAt` (timestamp of the last 100% successful scan with zero regional failures).

### 2. Granular Pipeline Performance Instrumentation
The scan pipeline instruments every execution phase with high-resolution monotonic timing (`time.perf_counter()`) and phase status tracking (`COMPLETED`, `FAILED`, `SKIPPED`):
- **`discovery`**: Parallel multi-region AWS service resource collection via ThreadPoolExecutor.
- **`iam_analysis`**: Managed policy document resolution, AST statement parsing, and principal risk evaluation.
- **`graph_construction`**: Idempotent Neo4j graph synchronization and NetworkX digraph assembly.
- **`path_analysis`**: Transitive attack path discovery and blast radius containment.
- **`cloudtrail_correlation`**: Telemetry normalization, ActivityEvent node creation, and exact transition correlation.
- **`finding_synthesis`**: Canonical finding generation, deterministic ID deduplication, and lifecycle state reconciliation.
- **Error Status Guarantee**: If any phase encounters a fatal error, that phase is marked `FAILED`, subsequent unreached phases remain `SKIPPED`, and `total` is marked `FAILED` with elapsed monotonic duration.
- Timing metrics are logged with `[PERF]` prefixes and exposed via `/api/v1/scan/status` and `/api/v1/dashboard`.

### 3. API Hardening & State Machine Validation
- **Finding Lifecycle State Machine**: Invalid transitions (e.g. attempting to transition directly from `RESOLVED` to `ACKNOWLEDGED` or `SUPPRESSED`) are rejected with `HTTP 400 Bad Request` requiring findings to be reopened first.
- **Reopen Endpoint**: Added `POST /api/v1/findings/{finding_id}/reopen` enabling controlled lifecycle resurrection.
- **Scanner Concurrency Protection**: Re-entrant or concurrent scan invocations are safely rejected (`status: skipped`) using an atomic lock.
- **JSON Security Report Export**: Dedicated export endpoint (`GET /api/v1/reports/export/json`) exposing authentic scan information, security summary, and canonical findings.

### 4. Production Docker & Multi-Service Compose
- **Multi-Stage Frontend Dockerfile**: Builds React/TypeScript application with Node 20 and serves production static assets via high-performance Nginx Alpine.
- **Docker Compose Orchestration**: Configures `backend`, `frontend`, `neo4j`, and `redis` with container naming standards (`cloudscope-*`), production healthchecks (`/ready` probe, `redis-cli ping`, `wget` bolt), dependency order gating, and decoupled environment variable credential injection (`${NEO4J_USER:-neo4j}`, `${NEO4J_PASSWORD:-password}`).

---

## 📡 API Endpoint Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Application status, active scan mode, and selected regions |
| `GET` | `/ready` | Service readiness probe (Neo4j and Redis connection checks) |
| `GET` | `/api/v1/health/aws` | AWS STS authentication and scanner identity validation |
| `POST` | `/api/v1/scan` | Triggers an asynchronous multi-service AWS scan |
| `GET` | `/api/v1/scan/status` | Real-time scanner execution state, duration, and metrics |
| `GET` | `/api/v1/dashboard` | Aggregated live security KPI metrics, risk breakdown, and inventory counts |
| `GET` | `/api/v1/users` | Discovered IAM users with MFA status, policies, and risk scores |
| `GET` | `/api/v1/roles` | Discovered IAM roles with trust documents and risk scores |
| `GET` | `/api/v1/resources` | Discovered cloud assets (S3, EC2, Lambda, Secrets, RDS, DynamoDB) |
| `GET` | `/api/v1/policies/explain` | Evidence-based authorization explanation for a principal and resource/action |
| `GET` | `/api/v1/graph` | Filtered Cytoscape elements for progressive disclosure visualization |
| `GET` | `/api/v1/attack-paths` | Discovered lateral movement paths and MITRE ATT&CK mappings |
| `GET` | `/api/v1/findings` | Canonical security findings with multi-attribute filtering (severity, category, status, region, principal, search) |
| `POST` | `/api/v1/findings/{finding_id}/acknowledge` | Move finding lifecycle state to ACKNOWLEDGED |
| `POST` | `/api/v1/findings/{finding_id}/resolve` | Move finding lifecycle state to RESOLVED |
| `POST` | `/api/v1/findings/{finding_id}/suppress` | Move finding lifecycle state to SUPPRESSED |
| `POST` | `/api/v1/findings/{finding_id}/reopen` | Reopen a RESOLVED finding back to OPEN state |
| `GET` | `/api/v1/risk-assessment` | Itemized security risk findings and remediation recommendations (backward compatible) |
| `GET` | `/api/v1/alerts` | CloudTrail audit events and correlated activity alerts |
| `GET` | `/api/v1/correlated-risks` | Runtime activity events correlated against static attack paths |
| `GET` | `/api/v1/reports/summary` | Verified Security Control Coverage across the 5 security domains (real scan data only) |
| `POST` | `/api/v1/copilot` | Context-aware cloud security assistant |

---

## 🧭 Identity Graph Analyst Visualization

CloudScope features an interactive, high-readability Identity Graph designed specifically for security analysts to quickly comprehend complex IAM topologies without getting overwhelmed by statement-level hairballs:

- **Deterministic 3-Column Hierarchical Layout**:
  - **Column 1 (Left)**: IAM Principals & Identities (`IAM Users`, `IAM Groups`).
  - **Column 2 (Center)**: Execution & Privilege Boundaries (`IAM Roles`).
  - **Column 3 (Right)**: Reachable Cloud Assets & Workloads (`S3`, `EC2`, `Lambda`, `RDS`, `Secrets Manager`, etc.).
  - Remains stable across browser reloads and minimizes edge crossings.

- **Aggregated Effective-Access Abstraction**:
  - Replaces individual statement clutter (`ALLOWS`, `ALLOWS_WRITE`, etc.) with consolidated, typed effective-access edges (e.g., `READ / WRITE`, `FULL ADMIN`, `ASSUME_ROLE`).
  - Edge labels display canonical access categories computed by the backend evaluation engine.

- **Analyst Workflows & Modes**:
  - **Identity Overview (Default)**: Top-down view of all identities, roles, and connected resources.
  - **Resource Detail**: Select a sensitive resource to isolate inbound access paths and identify which identities possess reachability.
  - **Attack Path**: Filters the graph down to high-risk privilege escalation and lateral movement attack chains.

- **Neighborhood Focus Mode**:
  - Isolate connected topologies with `1-Hop` or `2-Hop` depth filtering when investigating a selected principal or target asset.

- **Complete Technical Evidence Disclosure**:
  - Clicking any node displays ARN, type, risk score, and policy attachments.
  - Clicking any edge reveals comprehensive evidence in the side panel: aggregated access category, searchable list of exact IAM actions, policy origins, statement Sids, evaluation decisions, and correlated CloudTrail activity.
  - Toggleable policy diamonds allow progressive disclosure of raw statement-level diamond nodes on demand.

---

## 🧪 Testing & Verification

### Local Commands to Match CI

The developer can reproduce the exact GitHub Actions CI execution locally:

#### Backend Automated Testing
```bash
cd backend
python -m pytest tests/ -v --tb=short
```

#### Frontend Dependency Installation & Production Build
```bash
cd frontend
npm ci
npm run build
```

---

## 🚀 Continuous Integration (GitHub Actions)

CloudScope uses automated CI configured in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) to continuously validate changes across both backend and frontend layers:

- **Triggers**:
  - `push` to the `sura` branch.
  - `pull_request` targeting `sura`.
  - Manual execution via `workflow_dispatch`.

- **Independent Parallel Jobs**:
  1. **`backend-tests`** (`ubuntu-latest`, Python 3.11):
     - Sets up Python 3.11 with pip dependency caching.
     - Upgrades `pip` and installs dependencies from `backend/requirements.txt` and `backend/requirements-dev.txt`.
     - Executes the full 320+ test suite covering Phases 1 through 6 via `python -m pytest tests/ -v --tb=short`.
  2. **`frontend-build`** (`ubuntu-latest`, Node.js 20):
     - Sets up Node.js 20 with npm caching from `frontend/package-lock.json`.
     - Installs clean dependencies via `npm ci`.
     - Compiles TypeScript and builds the production bundle via `npm run build`.

- **Validation Requirement**: Both `backend-tests` and `frontend-build` must pass for the CI workflow to be green. A change should not be considered validated until the GitHub Actions workflow passes.
- **AWS Credential Isolation**: Normal CI jobs never configure or access real AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN`). All security evaluation, attack path, and graph construction tests run in hermetic environments using verified in-memory models and stubs.

---

## 🔒 Security & Limitations

- **Read-Only Operation**: The scanner never modifies AWS infrastructure or policy configurations during discovery.
- **No Secret Value Exposure**: Secrets Manager secret payloads are never retrieved.
- **CloudTrail Latency**: CloudTrail monitoring operates via continuous/scheduled lookup rather than synchronous sub-second kernel streaming.
- **IAM Condition Scope**: Implements standard Condition keys (`aws:PrincipalArn`, `aws:SourceIp`, MFA checks). Complex custom condition operator chaining outside AWS standard specs is reported as `CONDITIONAL`.
- **Intended Purpose**: Designed for cloud security posture assessment, CIEM access analysis, and academic demonstration.
