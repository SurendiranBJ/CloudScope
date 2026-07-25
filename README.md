# CloudScope 🌩️

CloudScope is a modern, real-time Cloud Security Posture Management (CSPM) platform tailored for AWS. It scans your cloud environment, identifies over-privileged IAM mappings, exposed resources, and highlights critical attack paths visually. 

The platform features a highly responsive, glassmorphism-styled React dashboard, backed by a fast, asynchronous FastAPI backend capable of building complex relationships between your AWS resources.

## 🚀 Currently Implemented Features

### Backend (FastAPI + Python)
*   **Modular Architecture**: Cleanly separated into endpoints, services (AWS scanners), and utility modules.
*   **Live AWS Resource Scanning**: Integration with `boto3` to scan IAM (Users/Roles), S3 Buckets, EC2 instances, and Secrets Manager.
*   **Risk Engine**: Evaluates security risks dynamically based on public exposure, missing encryption, lack of MFA, and excessive inline policies.
*   **Attack Path Analysis**: Uses in-memory graph models (`NetworkX`) to map blast radiuses and potential privilege escalations (e.g., User -> Role -> S3 Bucket).
*   **Caching Layer**: Built-in support for Redis caching to accelerate dashboard data loading, with a seamless fallback to local in-memory caching.

### Frontend (React + Vite)
*   **Premium Glassmorphism Design**: An aesthetically pleasing, fully responsive dark-mode UI powered by Tailwind CSS.
*   **Real-time Dashboard**: Displays your overall security score, risk distribution, and aggregate resource counts.
*   **Interactive Visualizations**: 
    *   Risk Distribution charts powered by `recharts`.
    *   Top Critical Attack paths and recent security alerts.
*   **Live Data Integration**: Connects seamlessly with the backend REST APIs to present live data from your AWS environment.

### Infrastructure & Operations
*   **Organized Repository**: Codebase cleanly partitioned into `frontend`, `backend`, `aws` (for IaC/scripts), and `copilot` directories.
*   **Local Execution**: Uses local AWS profiles (`identityscope-scanner`) for safe, read-only authentication to AWS accounts.

## 🛠️ Tech Stack
*   **Frontend**: React, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts.
*   **Backend**: Python, FastAPI, Uvicorn, Boto3 (AWS SDK), NetworkX, Redis.

---

## 🗺️ Roadmap / Future Work

While the core mechanics are operational, several features are planned for future development to make CloudScope an enterprise-ready CSPM:

1.  **Persistent Graph Database (Neo4j)**
    *   Migrate the in-memory `NetworkX` attack path graphs to Neo4j to support complex Cypher queries on massive cloud environments.
2.  **Expanded AWS Coverage**
    *   Add scanners for RDS, VPCs, EKS Clusters, Lambda functions, and CloudTrail configurations.
3.  **Multi-Cloud Support**
    *   Expand beyond AWS to support Azure (Azure RM) and Google Cloud (GCP) configurations.
4.  **Authentication & RBAC**
    *   Implement user authentication (e.g., via Cognito, Auth0, or JWT) to secure the dashboard and introduce Role-Based Access Control.
5.  **Automated Remediation**
    *   Add safe, click-to-remediate workflows that trigger Lambda functions to automatically revoke over-privileged policies or close public buckets.
6.  **Infrastructure as Code (IaC) & Deployment**
    *   Provide Terraform/CloudFormation templates to quickly deploy the CloudScope backend inside an AWS account.
    *   Provide Dockerfiles and Kubernetes Helm charts for easy containerized deployments.
7.  **Reporting & Compliance**
    *   Automated mapping to compliance frameworks (CIS, SOC2, PCI-DSS) and exportable PDF/CSV reports for auditing.

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
