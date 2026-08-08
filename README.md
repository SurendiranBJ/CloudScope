# CloudScope 🌩️

CloudScope is a modern, real-time Cloud Security Posture Management (CSPM) platform tailored for AWS. It scans your cloud environment, identifies over-privileged IAM mappings, exposed resources, and highlights critical attack paths visually. 

The platform features a highly responsive, glassmorphism-styled React dashboard, backed by a fast, asynchronous FastAPI backend capable of building complex relationships between your AWS resources.

## 🚀 Two-Phase Security Architecture

CloudScope is designed around a powerful two-phase architecture to distinguish between **Potential Risk** and **Active Exploitation**:

### Phase A: Configuration Baseline (Static)
The initial fast-scanner enumerates your AWS environment (IAM, EC2, S3, RDS, DynamoDB, Lambda, Secrets Manager, etc.) to build a static identity graph. This answers: *"What dangerous permissions exist right now?"*

### Phase B: Activity Monitoring (Dynamic)
CloudScope uses a dedicated CloudTrail event processor to capture actual activity (e.g., `AssumeRole`). By correlating observed activity with the static graph, CloudScope can detect and alert on active attack paths in real-time.

---

## ✨ Features

### Backend (FastAPI + Python)
*   **Blazing Fast Multithreading**: Wraps all AWS service collectors into a `ThreadPoolExecutor` and uses a centralized region cache, drastically reducing scan times to mere seconds.
*   **Comprehensive AWS Resource Scanning**: Integration with `boto3` to actively scan IAM (Users/Roles), S3 Buckets, EC2 instances, Secrets Manager, Lambda Functions, **RDS Databases**, and **DynamoDB Tables**.
*   **Advanced Risk Engine**: Evaluates security risks dynamically based on public exposure, missing encryption, lack of MFA, and explicitly parses raw JSON IAM policies for wildcard permissions (`Action: *`).
*   **Attack Path Analysis**: Maps blast radiuses and potential privilege escalations (e.g., User -> Role -> S3 Bucket) into a graph model.

### Frontend (React + Vite)
*   **Premium Glassmorphism Design**: An aesthetically pleasing, fully responsive dark-mode UI powered by Tailwind CSS.
*   **Asynchronous Scan Polling**: The dashboard never freezes. Manual scans run asynchronously with a beautiful progress banner, polling the server for live status updates.
*   **Advanced Identity Graph**: A fully interactive, full-screen graph visualization powered by Cytoscape and Dagre. Features a **collapsible legend**, hierarchical layouts, real-time risk highlighting, and integrated filtering.
*   **Interactive Visualizations**: Risk Distribution charts (`recharts`), critical attack paths, and recent security alerts.

### Infrastructure & Operations
*   **Auto-Scan Scheduling**: Safely manages recurring background scans using APScheduler with concurrency locks to prevent pile-ups.
*   **Local Execution**: Uses local AWS profiles (`identityscope-scanner`) for safe, read-only authentication to AWS accounts.

## 🛠️ Tech Stack
*   **Frontend**: React, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts, Cytoscape.
*   **Backend**: Python, FastAPI, Uvicorn, Boto3 (AWS SDK), NetworkX, Redis.

---

## 🗺️ Roadmap / Future Work

1.  **Persistent Graph Database (Neo4j)**
    *   Migrate the in-memory attack path graphs to Neo4j to support complex Cypher queries on massive cloud environments.
2.  **Expanded AWS Coverage**
    *   Add scanners for VPCs, EKS Clusters, and further CloudTrail configurations.
3.  **Multi-Cloud Support**
    *   Expand beyond AWS to support Azure (Azure RM) and Google Cloud (GCP) configurations.
4.  **Authentication & RBAC**
    *   Implement user authentication (e.g., via Cognito, Auth0, or JWT) to secure the dashboard and introduce Role-Based Access Control.

---

## 💻 Running Locally

### Backend
1. Navigate to the `backend` folder.
2. Install dependencies: `pip install -r requirements.txt`
3. Ensure your AWS CLI is configured with the correct profile (`identityscope-scanner`) with read-only permissions.
4. Run the server: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`

### Frontend
1. Navigate to the `frontend` folder.
2. Install dependencies: `npm install`
3. Start the dev server: `npm run dev`

Navigate to `http://localhost:5173` to view the dashboard!
