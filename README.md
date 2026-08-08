# CloudScope 🌩️ - Enterprise Cloud Security Posture Management (CSPM)

CloudScope is a modern, real-time Cloud Security Posture Management (CSPM) and Cloud Infrastructure Entitlement Management (CIEM) platform specifically engineered for Amazon Web Services (AWS). It continuously evaluates the security posture of an AWS environment by discovering misconfigurations, identifying over-privileged IAM mappings, flagging exposed resources, and dynamically mapping critical attack paths using graph theory.

Designed with a premium glassmorphism React dashboard and backed by a highly concurrent, asynchronous FastAPI engine, CloudScope enables security teams to visualize the blast radius of compromised identities before an attacker can exploit them.

---

## 🏛️ Architectural Paradigm: The Two-Phase Security Model

Enterprise cloud security fundamentally requires distinguishing between **Potential Risk** (what *could* happen based on misconfigurations) and **Active Exploitation** (what is *actually* happening right now). 

To achieve this, CloudScope is architected around a strict **Two-Phase Security Pipeline**. This separation of concerns ensures that the platform is both highly performant and analytically rigorous.

### Phase A: Static Configuration Baseline (The "State" of the Cloud)
Phase A is responsible for understanding the exact configuration of the AWS environment at a given point in time. It answers the question: *"What dangerous permissions exist right now, and how can they be chained together to compromise critical infrastructure?"*

1. **Multithreaded AWS Discovery (Boto3)**: The backend `ScanManager` orchestrates a highly concurrent data collection process using Python's `ThreadPoolExecutor`. It pre-caches available AWS regions to prevent redundant API calls, and then simultaneously dispatches collection threads for:
   - **Identity Access Management (IAM)**: Users, Groups, Roles, Managed Policies, and Inline Policies.
   - **Compute**: EC2 Instances and Lambda Execution Environments.
   - **Storage & Databases**: S3 Buckets, RDS Instances, and DynamoDB Tables.
   - **Secrets Management**: AWS Secrets Manager metadata.
   - **Security Services**: IAM Access Analyzer findings.

2. **Graph Construction (Neo4j & NetworkX)**: The raw JSON configurations are passed to the `GraphBuilder`. Relationships are algorithmically derived (e.g., matching a User's attached policies to a Role's Trust Relationship document). These nodes and edges are persisted into a **Neo4j Graph Database** (and mirrored in memory via `NetworkX` for rapid mathematical pathfinding).
   - **Static Edges Constructed**: `MEMBER_OF`, `HAS_POLICY`, `CAN_ASSUME`, `CAN_ACCESS`, `ATTACHED_TO`.

3. **Advanced Risk Engine**: The system does not rely on simple naming conventions. The `RiskEngine` explicitly parses raw IAM JSON policy documents, utilizing Abstract Syntax Tree (AST)-like evaluation to identify wildcard permissions (`Action: *` or `Resource: *`), lack of MFA enforcement, cross-account trust vulnerabilities, and public exposure on S3/RDS resources.

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
*   **APScheduler Integration**: Automated, periodic scanning is managed by `APScheduler` running in the background. To prevent memory leaks and API rate-limiting (HTTP 429 Too Many Requests), the scheduler enforces `max_instances=1` and utilizes Threading Locks (`threading.Lock(blocking=False)`) to guarantee mutually exclusive execution.
*   **Caching Layer (Redis)**: Enterprise AWS environments can produce graphs with tens of thousands of nodes. The backend implements a transparent caching layer utilizing **Redis** (`redis-py`). Complex graph topologies and Dashboard aggregations are cached with a configurable TTL. If Redis is unavailable, the application gracefully degrades to local memory caching without crashing.
*   **Data Models (Pydantic)**: All API payloads and internal data structures are strictly typed and validated using Pydantic, ensuring zero runtime data malformations when transitioning between AWS Boto3 dictionaries and React JSON payloads.

### Frontend Architecture (React 18 + Vite + TypeScript)
The frontend is a Single Page Application (SPA) designed with a premium, enterprise-grade dark mode aesthetic relying heavily on glassmorphism (translucency, background blurring, and structural gradients).

*   **State Management & Data Fetching**: Powered by **TanStack Query (React Query)**. This handles caching, background synchronization, and automatic refetching of the dashboard data. When the asynchronous scanner completes, React Query actively invalidates the cache, seamlessly re-rendering the UI without a page reload.
*   **Identity Graph Visualization (Cytoscape.js)**: The core visualization component is built on top of `Cytoscape.js`. 
   - **Dagre Layout Engine**: Utilizes the `cytoscape-dagre` extension to enforce a strict Directed Acyclic Graph (DAG) hierarchical layout, ensuring complex attack paths flow logically from left to right (Identities -> Roles -> Resources).
   - **Interactive DOM Overlays**: The graph features a floating, collapsible legend overlay and distinct color-coded node rendering. Static edges are rendered as solid gray lines, while active Risk Paths and Dynamic Edges are rendered with bold, colored strokes (e.g., solid red for `RISK PATH`).
*   **Styling (Tailwind CSS)**: The entire interface avoids generic component libraries in favor of utility-first Tailwind CSS. This allows for absolute control over micro-animations, hover states, and the precise geometric aesthetic required for a modern cybersecurity tool.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- AWS CLI configured with a read-only profile named `identityscope-scanner`.
- (Optional) Redis server running on localhost:6379 for enhanced caching performance.
- (Optional) Neo4j Desktop / Server running on localhost:7687.

### 1. Backend Setup
Navigate to the `backend` directory and initialize the Python environment:

```bash
cd backend
python -m venv venv

# Activate the virtual environment
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI Uvicorn Server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Frontend Setup
In a new terminal, navigate to the `frontend` directory:

```bash
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev
```

Navigate to `http://localhost:5173` in your web browser. The dashboard will automatically connect to the backend, trigger an initial asynchronous scan, and populate the Identity Graph.

---

## 🗺️ Roadmap & Future Iterations

1. **Cypher Query Builder UI**: Expose a visual query builder on the frontend allowing security analysts to write custom Neo4j Cypher queries directly against the Identity Graph (e.g., "Find all Users who can assume a Role that has Access to S3 Bucket X").
2. **Automated Remediation Workflows (Lambda)**: Implement safe, click-to-remediate workflows directly from the dashboard. This will trigger a backend AWS SDK call to automatically revoke over-privileged inline policies or disable public bucket access block settings.
3. **Multi-Cloud Generalization**: Abstract the AWS-specific Boto3 collectors behind a generic `CloudProvider` interface to support subsequent Azure RM and GCP Resource Manager integrations.
4. **Kubernetes (EKS) Node Integration**: Expand the configuration scanner to utilize the Kubernetes Python Client, parsing RBAC `ClusterRoles` and `RoleBindings` to map identities into the EKS data plane.
