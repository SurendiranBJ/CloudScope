# CloudScope — AWS Cloud Security Posture Management & Identity Attack Path Analysis

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

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11, FastAPI, Uvicorn, Boto3, Pydantic v2, NetworkX, Neo4j Python Driver, APScheduler
- **Database & Cache**: Neo4j Graph Database (Bolt Protocol), Redis (with automatic in-memory fallback)
- **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Lucide React, Cytoscape.js (`cytoscape-dagre`), TanStack Query, Recharts

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
| `GET` | `/api/v1/graph` | Filtered Cytoscape elements for progressive disclosure visualization |
| `GET` | `/api/v1/attack-paths` | Discovered lateral movement paths and MITRE ATT&CK mappings |
| `GET` | `/api/v1/risk-assessment` | Itemized security risk findings and remediation recommendations |
| `GET` | `/api/v1/alerts` | CloudTrail audit events and correlated activity alerts |
| `GET` | `/api/v1/correlated-risks` | Runtime activity events correlated against static attack paths |
| `GET` | `/api/v1/reports/summary` | Verified Security Control Coverage across the 5 security domains |
| `POST` | `/api/v1/copilot` | Context-aware cloud security assistant |

---

## 🧪 Testing & Verification

Run the full automated test suite:
```bash
cd backend
python -m pytest tests/ -v
```

Build the frontend production bundle:
```bash
cd frontend
npm run build
```

---

## 🔒 Security & Limitations

- **Read-Only Operation**: The scanner never modifies AWS infrastructure or policy configurations during discovery.
- **No Secret Value Exposure**: Secrets Manager secret payloads are never retrieved.
- **CloudTrail Latency**: CloudTrail monitoring operates via continuous/scheduled lookup rather than synchronous sub-second kernel streaming.
- **IAM Condition Scope**: Implements standard Condition keys (`aws:PrincipalArn`, `aws:SourceIp`, MFA checks). Complex custom condition operator chaining outside AWS standard specs is reported as `CONDITIONAL`.
- **Intended Purpose**: Designed for cloud security posture assessment, CIEM access analysis, and academic demonstration.
