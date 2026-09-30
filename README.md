# CloudScope — AWS Cloud Security Posture Management & Identity Attack Path Analysis

[![CloudScope CI](https://github.com/SurendiranBJ/CloudScope/actions/workflows/ci.yml/badge.svg?branch=sura)](https://github.com/SurendiranBJ/CloudScope/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/SurendiranBJ/CloudScope?logo=github&label=Release)](https://github.com/SurendiranBJ/CloudScope/releases)
[![GHCR Docker](https://img.shields.io/badge/GHCR-Docker%20Release-2496ED?logo=docker&logoColor=white)](https://github.com/SurendiranBJ/CloudScope/pkgs/container/cloudscope-backend)

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
   - **Authoritative Effective-Access Blast Radius**: Strictly counts unique reachable cloud data and compute resources (S3, EC2, Lambda, RDS, DynamoDB, Secrets), cleanly separating operational target assets from intermediate IAM roles and policies.
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

11. **Evidence-Grounded AI Security Copilot (Gemini-Powered)**:
    - **Strictly Grounded in Authoritative Evidence**: Explains direct and transitive IAM permissions, complex attack paths, and security findings using authoritative scan facts. Never invents users, roles, policies, attack paths, or risk scores.
    - **Server-Side API Key & Confidentiality**: The Gemini API key (`GEMINI_API_KEY`) is stored strictly server-side and never exposed to the frontend or printed in logs.
    - **Automated Credential & Secret Redaction**: Sanitizes AWS access keys, secret keys, session tokens, passwords, and private keys before dispatching context to the model. Secrets Manager secret values are never read or transmitted.
    - **Prompt Injection Defense**: Untrusted cloud strings (policy descriptions, tag names, resource metadata) are isolated as raw untrusted data within strict prompt delimiters.
    - **Interactive Investigation & Remediation**: Provides structured summaries, root-cause analyses, verified evidence points, least-privilege remediation recommendations, and suggested follow-up questions.
    - **Provider Abstraction**: Extensible AI architecture (`AIProvider` protocol) supporting Gemini with configurable models, temperature, and timeouts.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, Uvicorn, Boto3, Pydantic v2, NetworkX, Neo4j Python Driver, APScheduler, Google GenAI SDK (`google-genai`)
- **AI Engine**: Google Gemini (`gemini-3.8-flash`) for evidence-grounded security explanations and remediation recommendations
- **Database & Cache**: Neo4j Graph Database (Bolt Protocol), Redis (Cache layer with automatic in-memory fallback), Local Durable State Store
- **Frontend**: React 19, Vite, TypeScript, Tailwind CSS, Lucide React, Cytoscape.js (`cytoscape-dagre`), TanStack Query, Recharts

---

## 🐳 Production Docker Installation & Distribution

CloudScope provides prebuilt, immutable Docker container images published to **GitHub Container Registry (GHCR)**. A new user can run the complete CloudScope stack (Frontend, Backend, Neo4j, Redis) without installing Python, Node.js, Redis, or Neo4j locally.

### 1. Prerequisites
- [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://www.docker.com/products/docker-desktop/) (v24.0+ recommended)
- Docker Compose v2.20+ (`docker compose version`)
- AWS credentials file configured on the host machine (`~/.aws/credentials` or `%USERPROFILE%\.aws\credentials`)

### 2. Quickstart with Prebuilt Release Images (Recommended)

#### Step 1: Obtain Deployment Files
```bash
git clone https://github.com/SurendiranBJ/CloudScope.git
cd CloudScope
```

#### Step 2: Configure Environment
Copy the environment template and set your secure passwords:
```bash
cp .env.example .env
```
Edit `.env` to configure:
1. `NEO4J_PASSWORD`: Strong password for the Neo4j database (e.g. `openssl rand -hex 16`).
2. `JWT_SECRET`: Random 32+ character secret for JWT tokens (e.g. `openssl rand -hex 32`).
3. `AWS_PROFILE`: The AWS CLI profile to use (default: `default` or `identityscope-scanner`).
4. `AWS_CREDENTIALS_DIR`: Path to your AWS credentials directory:
   - **Linux / macOS**: `~/.aws` (default)
   - **Windows PowerShell**: `$env:USERPROFILE\.aws` (or `C:\Users\<username>\.aws`)
5. *(Optional)* `GEMINI_API_KEY`: API key for Gemini Security Copilot.

#### Step 3: Pull and Start CloudScope
```bash
# Pull official immutable images from GitHub Container Registry
docker compose -f compose.release.yaml pull

# Start all services in the background
docker compose -f compose.release.yaml up -d
```

#### Step 4: Access Web Application
- **CloudScope UI**: [http://localhost](http://localhost)
- **API Health Check**: `http://localhost/healthz`
- **Backend Readiness**: `docker compose -f compose.release.yaml exec -T backend curl -fsS http://127.0.0.1:8000/ready`
- **Neo4j Console (Localhost only)**: [http://localhost:7474](http://localhost:7474) (User: `neo4j`, Password: configured in `.env`)

---

### 3. Service Management & Operations

#### Check Service Status
```bash
docker compose -f compose.release.yaml ps
```

#### View Live Application Logs
```bash
# All services
docker compose -f compose.release.yaml logs -f

# Specific service (backend / frontend / neo4j / redis)
docker compose -f compose.release.yaml logs -f backend
```

#### Stop CloudScope
```bash
docker compose -f compose.release.yaml down
```
> [!NOTE]
> All graph data (`neo4j_data`), audit logs (`neo4j_logs`), cache state (`redis_data`), and authoritative scan snapshots (`app_storage`) are stored in persistent Docker volumes and remain completely safe across restarts.

#### Update CloudScope to Latest Release
```bash
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```
No manual compilation, `npm install`, or `pip install` is required.

#### Roll Back to a Specific Immutable Git Commit
Every release build publishes an immutable tag matching the Git commit SHA:
```bash
# Pin to a specific known-good release commit SHA
export IMAGE_TAG=79dfb74d34e4a031c5138a88490d07470537c1a8
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```
On Windows PowerShell:
```powershell
$env:IMAGE_TAG="79dfb74d34e4a031c5138a88490d07470537c1a8"
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```

---

### 4. Development Workflow (Build from Source)

For active local development and building images from local source:
```bash
docker compose -f compose.yaml up --build
```

---

### 5. GitHub Container Registry (GHCR) Public Access
By default, GitHub packages may be private. To allow anyone to pull images without authentication:
1. Navigate to your repository on GitHub.
2. Under **Packages**, select `cloudscope-backend` (and `cloudscope-frontend`).
3. Click **Package settings** -> **Danger Zone** -> **Change package visibility** -> **Public**.
4. Confirm the change. Users can now pull release images directly without logging into GHCR.

---

## 🛠️ Local Development & Manual Setup

### 1. Prerequisites
- Python 3.10+
- Node.js 18+
- AWS CLI configured with a read-only profile named `identityscope-scanner`:
  ```bash
  aws configure --profile identityscope-scanner
  ```

### 2. Scanner IAM Permissions
The scanner requires read-only metadata inspection permissions. **Secrets Manager secret values are never retrieved** (only secret metadata via `DescribeSecret` / `ListSecrets`).

Minimal required managed policies:
- `SecurityAudit`
- `ViewOnlyAccess`

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

### 5. AI Security Copilot Configuration (Gemini)

CloudScope integrates with Google Gemini for evidence-grounded security explanations, investigation assistance, and remediation advice:

```bash
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
AI_MAX_OUTPUT_TOKENS=1200
AI_TEMPERATURE=0.2
AI_CONTEXT_MAX_CHARS=24000
AI_TIMEOUT_SECONDS=30
```

> [!IMPORTANT]
> `GEMINI_API_KEY` must remain strictly server-side in your `.env` or deployment environment. It is never transmitted to the browser or frontend. CloudScope automatically redacts AWS credentials, tokens, and secret values before prompt dispatch.

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
| `POST` | `/api/v1/copilot` | Evidence-grounded security analysis and chat assistant powered by Gemini |
| `POST` | `/api/v1/copilot/explain-finding` | Deep-dive explanation and remediation for a specific security finding |
| `POST` | `/api/v1/copilot/explain-attack-path` | Step-by-step authorization mechanics and impact analysis for an attack path |

---

## 🧭 Identity Graph Analyst Visualization

CloudScope features an interactive, path-centric Identity Graph designed specifically for security analysts to quickly comprehend complex IAM topologies and attack exposure without getting overwhelmed by statement-level clutter:

- **Path-Centric Security Visualization**:
  - Preserves the full cloud topology as global context while dynamically focusing on active identity and resource attack paths.
  - The relevant identity/resource subgraph is highlighted with distinct colored borders and glowing badges, while unrelated nodes and edges are smoothly dimmed for immediate visual clarity.
  - Interactive layouts (`dagre`, `concentric`, `breadthfirst`) adapt naturally across browser viewports while minimizing edge crossings.

- **Centralized Canonical Styling (`graphStyles.ts`)**:
  - Unified visual styling and color system shared across the Identity Graph and Attack Path UI.
  - Authoritative palette: User (`#3B82F6`), Group (`#6366F1`), Policy (`#14B8A6`), Role (`#8B5CF6`), S3 (`#F59E0B`), EC2 (`#10B981`), Lambda (`#EC4899`), RDS (`#0EA5E9`), DynamoDB (`#A855F7`), Secrets (`#EF4444`).
  - Supported cloud resources comprehensively cover EC2, Lambda, S3, RDS, DynamoDB, Secrets Manager, and other discovered cloud assets.

- **Role-Target Attack Paths & Downstream Reachability**:
  - For direct identity-to-role escalation paths (e.g., `User -> CAN_ASSUME -> Role`), the role remains the attack target while downstream reachable assets (S3, EC2, Lambda, RDS, etc.) are explicitly exposed and visualised in downstream branching DAGs.
  - The UI presents an explainable blast-radius asset breakdown detailing exact counts per resource type (e.g., `4 S3 • 1 EC2 • 3 Lambda • 1 RDS`) backed by authoritative effective access evaluation.

- **Aggregated Effective-Access Abstraction**:
  - Replaces individual statement clutter (`ALLOWS`, `ALLOWS_WRITE`, etc.) with consolidated, typed effective-access edges (e.g., `READ / WRITE`, `FULL ADMIN`, `ASSUME_ROLE`).
  - Edge labels display canonical access categories computed by the backend evaluation engine.

- **Analyst Workflows & Modes**:
  - **Identity Overview (Default)**: Interactive view of all identities, roles, and connected resources.
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

You can reproduce the exact GitHub Actions CI execution phases locally:

#### 1. Preflight & Byte Compilation
```bash
cd backend
python -m compileall app tests
python -m pytest --collect-only -q tests/

cd ../frontend
npm ci --dry-run
```

#### 2. Partitioned Backend Test Suites
```bash
cd backend
# Phase 1: Core & APIs
python -m pytest tests/test_api_endpoints.py tests/test_aws_session.py tests/test_region_cache.py -v --tb=short

# Phase 2: Security Engines & Policies
python -m pytest tests/test_policy_evaluator.py tests/test_resource_boundary_and_conditions.py tests/test_trust_assumption.py tests/test_phase2_iam_hardening.py tests/test_cloudtrail_correlation.py tests/test_phase4_cloudtrail_correlation.py -v --tb=short

# Phase 3: Graph & Attack Paths
python -m pytest tests/test_graph_construction.py tests/test_duplicate_nodes.py tests/test_graph_reconciliation.py tests/test_identity_graph_resources.py tests/test_path_engine.py tests/test_attack_path_grouping.py tests/test_carol_lambda_effective_access.py tests/test_effective_access_multihop.py tests/test_role_target_downstream_assets.py tests/test_phase3_provenance_attack_paths.py -v --tb=short

# Phase 4: Scanner & Snapshot Consistency
python -m pytest tests/test_scan_lifecycle.py tests/test_published_snapshot_consistency.py tests/test_phase1_regional_discovery.py tests/test_scan_iam_reconciliation.py tests/test_phase6_hardening_performance_e2e.py -v --tb=short

# Phase 5: Policies, Risk & Alerts
python -m pytest tests/test_policies_relationships_integration.py tests/test_risk_engine.py tests/test_phase5_unified_findings.py -v --tb=short

# Phase 6: AI & Copilot
python -m pytest tests/test_ai_context_builder.py tests/test_ai_provider.py tests/test_copilot.py -v --tb=short

# Phase 7: Policy Simulation
python -m pytest tests/test_simulation.py tests/test_simulation_pass.py -v --tb=short
```

#### 3. Complete Backend Regression with Coverage
```bash
cd backend
python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=xml:test-results/coverage.xml --junitxml=test-results/backend-full.xml -v --tb=short --durations=20
```

#### 4. Frontend Verification
```bash
cd frontend
npm test          # Native ESM test runner
npm run lint      # oxlint static analysis
npm run build     # TypeScript strict compilation & Vite bundle
```

---

## 🚀 Continuous Integration (GitHub Actions)

CloudScope utilizes an enterprise-grade, multi-phase CI pipeline defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) consisting of **13 specialized jobs** executing in parallel where possible:

- **Triggers**:
  - `push` to the `sura` branch.
  - `pull_request` targeting `sura`.
  - Manual execution via `workflow_dispatch`.

- **Pipeline Architecture**:
  1. **`preflight`** (`ubuntu-latest`):
     - Validates runtime environments (Python 3.11, Node.js 22, npm).
     - Confirms zero syntax or import errors via `python -m compileall app tests`.
     - Validates test collection and dependency tree.
  2. **7 Partitioned Backend Jobs** (Parallel execution):
     - `backend-core`: API endpoints, AWS session management, and regional caching.
     - `backend-security-engines`: Policy evaluator, boundary conditions, trust assumption, IAM hardening, and CloudTrail correlation.
     - `backend-graph-and-attack-paths`: Graph construction, reconciliation, identity graph resources, path engine, and multi-hop attack paths.
     - `backend-scanner-and-snapshots`: Scan lifecycle, published snapshot consistency, regional discovery, and end-to-end performance.
     - `backend-policies-risk-alerts`: Policies and relationships integration, risk scoring engine, and unified findings synthesis.
     - `backend-ai-and-copilot`: AI context builder, AI provider fallbacks, and Copilot intelligence.
     - `backend-simulation`: Policy simulation and blast radius impact analysis.
     - *Artifacts*: Each backend phase exports JUnit XML reports (`test-results-backend-*.xml`).
  3. **3 Frontend Jobs** (Parallel execution):
     - `frontend-tests`: Unit tests verifying graph styling, scan refresh logic, and cache invalidation.
     - `frontend-lint`: Fast static analysis with `oxlint`.
     - `frontend-build`: Strict TypeScript verification (`tsc -b`) and Vite production bundle generation (`frontend-dist` artifact).
  4. **`backend-full-regression`** (Runs after partitioned phases):
     - Complete test suite execution across all test modules.
     - Full code coverage reporting with `pytest-cov` (terminal table + XML artifact).
     - Slowest 20 tests duration profiling via `--durations=20`.
  5. **`ci-summary`** (Pipeline Gatekeeper):
     - Runs unconditionally (`if: ${{ always() }}`) after all jobs complete.
     - Aggregates status across all 12 prior jobs.
     - Fails the workflow if ANY phase failed, ensuring zero regressions reach `sura`.

- **AWS Credential Isolation**: Normal CI jobs never configure or access real AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN`). All security evaluation, attack path, and graph construction tests run in hermetic environments using verified in-memory models and stubs.

---

## 🛡️ Phase 2: Production Reliability, Security & Operations Hardening

CloudScope incorporates enterprise production hardening designed for multi-instance distributed reliability, strict authorization, and complete auditability:

### 1. Authentication & Role-Based Access Control (RBAC)
- **OIDC / JWT Validation**: Cryptographic signature validation with claims normalization, supporting RSA/ECDSA JWKS and symmetric HMAC secrets.
- **Monotonic Role Hierarchy**:
  - `VIEWER` (Level 1): Read-only visibility into graphs, inventory, alerts, and risk assessments.
  - `ANALYST` (Level 2): What-if policy simulations and natural language Copilot AI analysis.
  - `SECURITY_OFFICER` (Level 3): Security finding lifecycle management (Acknowledge, Suppress, Resolve) and administrative audit log viewing.
  - `ADMINISTRATOR` (Level 4): Full operational management, manual scan triggering, region configuration, and distributed lock inspection.
- **Development Authentication**: Configurable `DEV_AUTH_MODE` for local development and UI testing with instant role switching.

### 2. Distributed Scan Lock & Multi-Worker Coordination
- **Atomic Locking**: Uses Redis `SET cloudscope:scan:lock <token> NX EX 120` to guarantee mutual exclusion across multiple instances.
- **Heartbeat & Lease Renewal**: Active scan processes maintain an atomic Lua script heartbeat every 10 seconds to renew lease locks safely.
- **Stale Lock Auto-Recovery**: Prevents permanent deadlocks in the event of hard worker termination.

### 3. Durable Relational Persistence
- **Decoupled Architecture**: Redis functions strictly as an ephemeral cache and lock coordinator.
- **Relational Store**: Scan executions (`ScanRun`), published snapshots (`ScanSnapshot`), finding triage states (`FindingState`), and audit records (`AuditEvent`) are durably persisted in SQLite (dev) or PostgreSQL (prod).

### 4. Sliding Window Rate Limiting
- Dynamic sliding window rate limits keyed by authenticated user ID (with IP address fallback for unauthenticated probes).
- Rejections return HTTP 429 Too Many Requests with compliant `Retry-After` headers and UI countdown banners.

### 5. Administrative Audit Logging & Automated Secret Redaction
- Comprehensive audit records for scan triggers, region configuration changes, finding lifecycle updates, simulations, and Copilot queries.
- **Zero-Credential Leakage**: Centralized regex and dictionary-key masking (`sanitizer.py`) automatically strips AWS access keys, secret keys, session tokens, and Gemini API keys prior to storage or log emission.

### 6. Observability, Health Probes & Operations Center
- **Kubernetes Probes**: `/live` (in-memory liveness) and `/ready` (dependency check decoupled from AWS API availability).
- **Prometheus Metrics**: `GET /metrics` exposing request counters, latency histograms, and scanner run counts.
- **Operations Dashboard**: Dedicated UI at `/operations` (Restricted to `ADMINISTRATOR`) displaying real-time lock status, dependency health, scan execution history, and audit log inspector.

---

## 🔒 Security & Limitations

- **Read-Only Operation**: The scanner never modifies AWS infrastructure or policy configurations during discovery.
- **No Secret Value Exposure**: Secrets Manager secret payloads are never retrieved.
- **CloudTrail Latency**: CloudTrail monitoring operates via continuous/scheduled lookup rather than synchronous sub-second kernel streaming.
- **IAM Condition Scope**: Implements standard Condition keys (`aws:PrincipalArn`, `aws:SourceIp`, MFA checks). Complex custom condition operator chaining outside AWS standard specs is reported as `CONDITIONAL`.
- **Intended Purpose**: Designed for cloud security posture assessment, CIEM access analysis, and academic demonstration.

---

## 📦 Open Source Releases & Docker Distribution

CloudScope provides prebuilt, hardened container images published to **GitHub Container Registry (GHCR)**. A user can run the entire CloudScope platform using only Docker and Docker Compose—**without installing Python, Node.js, Redis, or Neo4j on the host machine**.

### 🚀 Quick Start (Production / Release Installation)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SurendiranBJ/CloudScope.git
   cd CloudScope
   ```

2. **Configure your environment secrets:**
   ```bash
   cp .env.example .env
   # Edit .env and configure NEO4J_PASSWORD, JWT_SECRET, and AWS_CREDENTIALS_DIR
   ```

3. **Pull and start the released images:**
   ```bash
   # Stable semantic version release (e.g. v1.0.0):
   IMAGE_TAG=v1.0.0 docker compose -f compose.release.yaml pull
   IMAGE_TAG=v1.0.0 docker compose -f compose.release.yaml up -d
   ```

4. **Access the application:**
   - **Web UI & Graph Cytoscape:** [http://localhost](http://localhost)
   - **Liveness Probe:** `http://localhost/healthz`
   - **Backend Readiness:** `docker compose -f compose.release.yaml exec backend curl -fsS http://localhost:8000/ready`
   - **Operations & Health Center:** [http://localhost/operations](http://localhost/operations)

---

### 🏷️ Release Policy & Automatic Semantic Versioning

CloudScope uses automated **Semantic Versioning (`MAJOR.MINOR.PATCH`)**:

```text
git push origin sura
        │
        ▼
   CloudScope CI (13/13 quality gate jobs)
        │
     SUCCESS
        ▼
   CloudScope CD (on default branch master)
        │
        ├─► Resolve exact CI commit SHA
        ├─► Discover latest SemVer tag & increment PATCH (e.g. v1.0.0 -> v1.0.1)
        ├─► Build multi-arch backend & frontend Docker images
        ├─► Publish immutable tags to GHCR
        ├─► Create annotated Git tag pointing to exact CI SHA
        └─► Create GitHub Release with automated notes
```

- **Patch Increments**: Every push to development branch `sura` that passes all 13 CI jobs produces the next consecutive patch release (`v1.0.0` → `v1.0.1` → `v1.0.2`...).
- **Strict Quality Invariant**: Failed, cancelled, or in-progress CI runs **never** trigger a release or tag creation.
- **Commit Invariant**:
  The Git commit tested by CI is the exact commit tagged, packaged, and released:
  $$\text{CI-tested SHA} \equiv \text{Git Tag Target SHA} \equiv \text{Image Revision Label} \equiv \text{Release Commitish}$$

---

### 🐳 Published Container Images

Published under the `ghcr.io/surendiranj` namespace:

| Service | Image Repository | Tag Classes Published |
|---|---|---|
| **Backend** | `ghcr.io/surendiranj/cloudscope-backend` | `vX.Y.Z`, `<FULL_COMMIT_SHA>`, `sura-latest` |
| **Frontend** | `ghcr.io/surendiranj/cloudscope-frontend` | `vX.Y.Z`, `<FULL_COMMIT_SHA>`, `sura-latest` |
| **Graph DB** | `neo4j:5.18.0-community` *(Official)* | APOC enabled, loopback port binding |
| **Cache/Lock** | `redis:7-alpine` *(Official)* | Internal network only, no published host ports |

> **Note**: For each release, the semantic version tag (`v1.0.0`), the immutable commit SHA tag, and `sura-latest` all share the exact same cryptographic image digest.

---

### 🔄 Updating & Rolling Back Releases

#### Updating to the Newest Release:
```bash
docker compose -f compose.release.yaml pull
docker compose -f compose.release.yaml up -d
```

#### Rolling Back to a Specific Pinned Release:
To roll back without data loss (persistent database volumes `neo4j_data` and `app_storage` are retained):
```bash
IMAGE_TAG=v1.0.0 docker compose -f compose.release.yaml pull
IMAGE_TAG=v1.0.0 docker compose -f compose.release.yaml up -d
```

---

### 🌐 GHCR Package Visibility

For public open-source distribution:
1. In GitHub, navigate to **Packages** on your profile/organization.
2. Select `cloudscope-backend` and `cloudscope-frontend`.
3. Under **Package settings** → **Danger Zone**, set package visibility to **Public**.
4. Once public, any user can run `docker pull ghcr.io/surendiranj/cloudscope-backend:v1.0.0` without requiring GitHub credentials.


