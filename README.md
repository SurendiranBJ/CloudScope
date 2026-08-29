# CloudScope 🌩️ - AWS Cloud Security Posture Management & Identity Attack Path Analysis Platform

CloudScope is an enterprise-grade Cloud Security Posture Management (CSPM) and Cloud Infrastructure Entitlement Management (CIEM) platform built for Amazon Web Services (AWS). It discovers cloud resources and identities, computes actual effective permissions through true IAM policy AST evaluation, builds graph-theoretic identity relationship topologies in **Neo4j** and **NetworkX**, detects lateral-movement attack paths, and displays actionable risk metrics via an interactive **React** dashboard.

---

## 🏛️ Unified Continuous Scanning Pipeline

CloudScope operates on **ONE continuous, unified security scanning pipeline**:

```
AWS Account
    ↓
Boto3 Read-Only Scanner (identityscope-scanner Profile)
    ↓
AWS Inventory (IAM, Compute, Storage, Databases, Secrets, CloudTrail)
    ↓
IAM Policy AST & Trust Evaluation (Action + Resource Analysis, AssumeRole)
    ↓
Neo4j Graph Construction (Stable Unique Node IDs, MERGE Idempotency)
    ↓
NetworkX Graph Synchronization
    ↓
Risk Engine & Blast Radius Analysis (Deterministic Scoring, Graph Reachability)
    ↓
FastAPI Asynchronous REST API
    ↓
TanStack React Query / Axios
    ↓
React Dashboard & Cytoscape.js Identity Graph
```

### Pipeline Execution Steps:
1. **AWS Authentication & Diagnostics**: Authenticates via `boto3.Session` using the read-only AWS CLI profile (`identityscope-scanner`). Validates identity via STS `GetCallerIdentity` without exposing secrets.
2. **Multi-Service Concurrent Discovery**: Scans IAM (Users, Groups, Roles, Managed Policies, Inline Policies), Compute (EC2, Lambda), Storage & Databases (S3, RDS, DynamoDB), Secrets (Secrets Manager metadata only), IAM Access Analyzer findings, and CloudTrail audit alerts using boto3 paginators across configured regions.
3. **IAM Policy Document Analysis (No Name Heuristics)**: Inspects the actual JSON policy document statements (`Effect`, `Action`, `Resource`, `Principal`, `Condition`, `NotAction`, `NotResource`). Evaluates wildcard actions/resources and specific ARN patterns.
4. **AssumeRole Trust Policy Parsing**: Resolves `CAN_ASSUME` relationships between Users/Roles and target Roles based on IAM trust documents (supporting account root, wildcard, and specific principal ARNs).
5. **Graph Topologies (Neo4j & NetworkX)**: Populates Neo4j and NetworkX with stable unique IDs (`aws:user:<name>`, `aws:role:<name>`, `aws:policy:<name>`, `aws:s3:<name>`, `aws:secret:<name>`, `aws:rds:<name>`, `aws:dynamodb:<name>`, `aws:ec2:<id>`, `aws:lambda:<name>`). Constructs `MEMBER_OF`, `HAS_POLICY`, `CAN_ASSUME`, `ATTACHED_TO`, `EXECUTES_WITH`, and `ALLOWS` relationships.
6. **Attack Path & Blast Radius Engine**: Computes shortest lateral movement paths from entry points (Users, EC2 instances) to critical assets and admin roles using BFS/shortest path. Maps MITRE ATT&CK techniques (T1078, T1548.003, T1530, T1552.004) and calculates blast radius reachability.
7. **FastAPI & React Dashboard Synchronization**: Delivers live inventory counts, security scores, diagnostic badges, and attack paths to the React frontend.

---

## 🛠️ Technical Stack

*   **Backend**: Python 3.11, FastAPI, Uvicorn, Boto3, Pydantic, NetworkX, Neo4j Python Driver, APScheduler
*   **Database & Cache**: Neo4j Graph Database (Bolt protocol), Redis (with automatic in-memory fallback)
*   **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Lucide React, Cytoscape.js (`cytoscape-dagre`), TanStack Query

---

## 🚀 Getting Started

### 1. Prerequisites
*   Python 3.10+
*   Node.js 18+
*   AWS CLI configured with a read-only profile named `identityscope-scanner`:
    ```bash
    aws configure --profile identityscope-scanner
    ```
*   (Optional) Neo4j Desktop or Docker container on `bolt://localhost:7687`

---

### 2. Quickstart (Unified Runner)
Run both backend and frontend development servers concurrently:
```bash
npm run dev
```

---

### 3. Step-by-Step Manual Setup

#### Backend Setup
```bash
cd backend

# Create & activate virtual environment
python -m venv venv
.\venv\Scripts\activate      # Windows
source venv/bin/activate    # macOS/Linux

# Install dependencies
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

Visit `http://localhost:5173` to view the live dashboard.

---

## 🧪 Testing & Verification

Run the automated backend test suite:
```bash
cd backend
python -m pytest tests/ -v
```

Build the frontend bundle:
```bash
cd frontend
npm run build
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | API service health check |
| `GET` | `/health/aws` | Safe AWS STS caller identity diagnostics |
| `GET` | `/ready` | Full readiness check (Backend, AWS, Neo4j, Redis) |
| `GET` | `/api/v1/dashboard` | Live aggregated dashboard metrics and security score |
| `POST` | `/api/v1/scan` | Trigger an asynchronous AWS security scan |
| `GET` | `/api/v1/scan/status` | Current scan progress and per-service health status |
| `GET` | `/api/v1/users` | Discovered IAM users ledger |
| `GET` | `/api/v1/roles` | Discovered IAM roles ledger |
| `GET` | `/api/v1/resources` | Discovered cloud resources (S3, EC2, Lambda, RDS, DynamoDB, Secrets) |
| `GET` | `/api/v1/graph` | Cytoscape graph elements (nodes & edges) |
| `GET` | `/api/v1/attack-paths` | Lateral movement attack paths with MITRE ATT&CK techniques |
| `GET` | `/api/v1/risk-assessment` | Risk assessment findings and remediation recommendations |
| `GET` | `/api/v1/alerts` | CloudTrail audit events |
| `GET` | `/api/v1/correlated-risks` | Correlated security findings linking CloudTrail activity to attack paths |
| `POST` | `/api/v1/settings/scan-region` | Update runtime scan region (`single` or `global`) |
| `POST` | `/api/v1/settings/scan-interval` | Reschedule automated scan frequency |

---

## 🔒 Security & Safe Metadata Collection
*   **Zero Credential Exposure**: Never logs, exposes, or stores AWS access keys, secret keys, or secret values.
*   **Secrets Manager**: Collects metadata only (ARN, name, rotation status, tags, dates); never calls `GetSecretValue`.
*   **Read-Only Operations**: Uses read-only AWS APIs exclusively (`list_*`, `describe_*`, `get_*_policy`, `lookup_events`).
*   **Near-Real-Time Activity Monitoring**: Correlates recent CloudTrail management events against graph topologies to detect active attack execution without requiring intrusive inline agent installations.
