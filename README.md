# CloudScope 🌩️ - Enterprise Cloud Security Posture Management (CSPM)

CloudScope is a modern, real-time Cloud Security Posture Management (CSPM) and Cloud Infrastructure Entitlement Management (CIEM) platform specifically engineered for Amazon Web Services (AWS). It continuously evaluates the security posture of an AWS environment by discovering misconfigurations, identifying over-privileged IAM mappings, flagging exposed resources, and dynamically mapping critical attack paths using graph theory.

Designed with a premium glassmorphism React dashboard and backed by a highly concurrent, asynchronous FastAPI engine, CloudScope enables security teams to visualize the blast radius of compromised identities before an attacker can exploit them.

> **Latest Security & Architecture Updates**: See [`AUDIT_AND_CHANGES.md`](file:///c:/Users/surab/Desktop/CloudScope/AUDIT_AND_CHANGES.md) for a complete breakdown of recent IAM risk engine fixes, AWS-managed policy document resolution, API endpoints, and UI audit results.

---

## 🏛️ Architectural Paradigm: The Two-Phase Security Model

Enterprise cloud security fundamentally requires distinguishing between **Potential Risk** (what *could* happen based on misconfigurations) and **Active Exploitation** (what is *actually* happening right now). 

To achieve this, CloudScope is architected around a strict **Two-Phase Security Pipeline**. This separation of concerns ensures that the platform is both highly performant and analytically rigorous.

### Phase A: Static Configuration Baseline (The "State" of the Cloud)
Phase A is responsible for understanding the exact configuration of the AWS environment at a given point in time. It answers the question: *"What dangerous permissions exist right now, and how can they be chained together to compromise critical infrastructure?"*

1. **Multithreaded AWS Discovery (Boto3)**: The backend `ScanManager` orchestrates a highly concurrent data collection process using Python's `ThreadPoolExecutor`. It pre-caches the target AWS regions (configured via `SCAN_REGIONS` or defaulting to the default AWS session region) to prevent redundant API calls, and then simultaneously dispatches collection threads for:
   - **Identity Access Management (IAM)**: Users, Groups, Roles, Customer-Managed Policies, and AWS-Managed Policies (`arn:aws:iam::aws:policy/...`).
   - **Compute**: EC2 Instances and Lambda Execution Environments.
   - **Storage & Databases**: S3 Buckets, RDS Instances, and DynamoDB Tables.
   - **Secrets Management**: AWS Secrets Manager metadata.
   - **Security Services**: IAM Access Analyzer findings.

2. **Graph Construction (Neo4j & NetworkX)**: The raw JSON configurations are passed to the `GraphBuilder`. Relationships are algorithmically derived (e.g., matching a User's attached policies to a Role's Trust Relationship document). These nodes and edges are persisted into a **Neo4j Graph Database** (and mirrored in memory via `NetworkX` for rapid mathematical pathfinding).
   - **Static Edges Constructed**: `MEMBER_OF`, `HAS_POLICY`, `CAN_ASSUME`, `ALLOWS`, `ATTACHED_TO`, `EXECUTES_WITH`.

3. **Advanced Risk Engine**: The system does not rely on simple naming conventions. The `RiskEngine` explicitly parses raw IAM JSON policy documents, utilizing AST-like evaluation to identify wildcard permissions (`Action: *` or `Resource: *`), lack of MFA enforcement, cross-account trust vulnerabilities, and public exposure on S3/RDS resources. It inspects both customer-managed and resolved AWS-managed policy documents.

### Phase B: Dynamic Activity Monitoring (The "Behavior" of the Cloud)
While Phase A maps the *potential* attack paths, Phase B monitors the *actual* behavioral telemetry of the environment.

1. **CloudTrail Event Processor**: A decoupled background daemon continuously polls AWS CloudTrail. Instead of acting as a secondary inventory scanner, this processor exclusively captures state-mutating and privilege-escalating API calls (e.g., `AssumeRole`, `PutBucketPolicy`, `CreateAccessKey`).
2. **Dynamic Edge Generation**: These behavioral events are transformed into time-series nodes and injected into the Neo4j graph as **Dynamic Edges** (e.g., `ASSUMED_ROLE`, `MODIFIED_POLICY`, `ACCESSED_RESOURCE`).

### The Correlation Engine
The true power of CloudScope lies in the **Correlation Engine**. By querying the unified Neo4j database, CloudScope executes complex Cypher queries that intersect Phase A (Static) and Phase B (Dynamic) topologies. 

If the static graph indicates that `User:Alice` has a theoretical `CAN_ASSUME` path to `Role:DatabaseAdmin`, and the dynamic graph suddenly records an `ASSUMED_ROLE` edge matching that exact trajectory, the Correlation Engine flags this as an **Active Correlated Risk** with a critical severity score, instantly pushing the alert to the React frontend.

---

## 🛠️ Technical Implementation Deep Dive

### Backend Architecture (Python 3.11 + FastAPI)
The backend is structured as a modular, event-driven API server running on **Uvicorn** and **FastAPI**.

*   **Concurrency & Asynchrony**: To prevent the UI from hanging during massive AWS API sweeps, manual scans are triggered asynchronously. The POST `/scan` endpoint dispatches a daemon thread and returns immediately. The frontend seamlessly polls a lightweight `/scan/status` endpoint.
*   **APScheduler Integration & Runtime Rescheduling**: Automated, periodic scanning is managed by `APScheduler`. Scans enforce `max_instances=1` and utilize `threading.Lock(blocking=False)` to prevent duplicate execution. Admins can update the scan frequency dynamically via `POST /api/v1/settings/scan-interval`, which atomically reschedules the running job at runtime.
*   **Strict CORS Policy**: `CORS_ORIGINS` environment variable replaces wildcard settings, defaulting to trusted origins (`http://localhost:5173`, `http://localhost:3000`).
*   **Caching Layer (Redis)**: Enterprise AWS environments can produce graphs with tens of thousands of nodes. The backend implements a transparent caching layer utilizing **Redis** (`redis-py`). Complex graph topologies and Dashboard aggregations are cached with a configurable TTL. If Redis is unavailable, the application gracefully degrades to local memory caching without crashing.
*   **Data Models (Pydantic)**: All API payloads and internal data structures are strictly typed and validated using Pydantic, ensuring zero runtime data malformations.

### Frontend Architecture (React 18 + Vite + TypeScript)
The frontend is a Single Page Application (SPA) designed with a premium, enterprise-grade dark mode aesthetic relying heavily on glassmorphism (translucency, background blurring, and structural gradients).

*   **State Management & Data Fetching**: Powered by **TanStack Query (React Query)**. This handles caching, background synchronization, and automatic refetching of the dashboard data.
*   **Identity Graph Visualization (Cytoscape.js)**: Built on `Cytoscape.js` with `cytoscape-dagre` hierarchical layout rendering. Renders live node properties including raw IAM trust relationship policies and attached policy lists.
*   **Interactive Modals & Real Data Reporting**: Includes an in-app JSON inspector modal for cloud resources, live Copilot AI integration for attack path explanations, client-side alert dismissal, and client-side document generators for PDF (jsPDF), CSV, JSON, and SVG vector graphics.
*   **Styling (Tailwind CSS)**: Utility-first Tailwind CSS for precise geometric layout, hover transitions, and glassmorphism styling.

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- AWS CLI configured with a read-only profile named `identityscope-scanner`.
- (Optional) Redis server running on localhost:6379 for enhanced caching performance.
- (Optional) Neo4j Desktop / Server running on localhost:7687.

---

### 💻 Unified Development Startup (Recommended)
You can start both the backend server (with auto-reload enabled) and the frontend dev server simultaneously using a single command from the project root:

```bash
# Run both servers concurrently
npm run dev
```

---

### 🛠️ Step-by-Step Manual Setup

#### 1. Backend Setup
Navigate to the `backend` directory and initialize the Python environment:

```bash
cd backend
python -m venv venv

# Activate the virtual environment
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install runtime dependencies
pip install -r requirements.txt

# (Optional) Install test/dev dependencies
pip install -r requirements-dev.txt

# Start the FastAPI Uvicorn Server with hot reload enabled
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Run the test suite
python -m pytest tests/ -v
```

#### 2. Frontend Setup
In a new terminal, navigate to the `frontend` directory:

```bash
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev
```

Navigate to `http://localhost:5173` in your web browser. The dashboard will automatically connect to the backend, trigger an initial scan, and populate the Identity Graph.

---

## ⚙️ Local Development Notes

*   **Auto-Reload (Hot Reload)**: The FastAPI server automatically reloads whenever python files in `backend/` are updated (via `--reload`). The Vite frontend hot-reloads similarly for code changes in `frontend/`.
*   **Self-Healing Cache**: At boot, the backend automatically calls `cache.clear()` to ensure that code/schema changes do not conflict with stale cached keys.
*   **Version Verification**: To verify that your locally running servers are up-to-date with your latest git commit, refer to the **version marker in the Sidebar footer**. It fetches the current commit hash and server launch time from the `/api/v1/health` endpoint at startup. If the commit hash doesn't match your changes, restart the servers.


---

## 🔄 Scan Refresh Model & Lifecycle

CloudScope operates on a **Scheduled + Manual-Trigger** refresh model rather than a real-time event-driven detection system for raw baseline configuration changes. 

*   **Manual Trigger**: Users can click the **Scan Again** button (available on the Dashboard, Attack Paths, and Risk Assessment pages) to force an immediate scan of the AWS environment.
*   **Scheduled Scans**: Automatic scans occur periodically based on the `SCAN_INTERVAL_MINUTES` setting (configurable dynamically in the Settings panel).
*   **Delayed Visibility**: Any configuration changes made in your AWS environment (e.g., policy updates, group membership changes, or new resources) will not be visible in CloudScope until either a manual scan is triggered or the next scheduled scan executes.

---

## ⚠️ Current Scope & Limitations

> **Region Scoping & Configured Scan Regions**: By default, CloudScope is scoped to a **single AWS region** — whichever region the AWS session defaults to (or set via `AWS_DEFAULT_REGION`).
>
> To scan specific target region(s), configure the `SCAN_REGIONS` setting in the backend `.env` file (e.g., `SCAN_REGIONS=us-east-1,ap-south-1`). If this setting is omitted, the scan defaults to a single region (matching the AWS session default).
>
> Multi-region auto-discovery (which described and queried all enabled regions by default) is disabled to prevent scanning empty regions and optimize performance. Explicitly configure target regions in `SCAN_REGIONS` to scan multiple regions.


---

## 🗺️ Roadmap & Future Iterations

1. **Cypher Query Builder UI**: Expose a visual query builder on the frontend allowing security analysts to write custom Neo4j Cypher queries directly against the Identity Graph.
2. **Automated Remediation Workflows (Lambda)**: Implement safe, click-to-remediate workflows directly from the dashboard.
3. **Multi-Region & Multi-Cloud Expansion**: Enumerate all enabled AWS regions and scan resources across them in parallel; then abstract the collectors to support Azure RM and GCP Resource Manager.
4. **Kubernetes (EKS) Node Integration**: Expand the configuration scanner to utilize the Kubernetes Python Client, parsing RBAC `ClusterRoles` and `RoleBindings`.
