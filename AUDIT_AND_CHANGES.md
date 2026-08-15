# CloudScope — Audit, Architecture Updates & Previous vs. Current State

> **Document Summary**: Comprehensive record of security fixes, backend refactoring, API expansions, and frontend UI audit & remediation completed during the platform hardening phase.

---

## 1. Summary of Major Changes

### Backend Refactoring & Security Fixes
1. **IAM Risk Engine Wildcard Detection Fix (`risk_engine.py`)**:
   - *Previous Defect*: `_has_wildcard_permissions()` expected JSON string policy documents but received policy name strings from `score_user_risk()` and `score_role_risk()`. Calling `json.loads()` threw exceptions on every call, silently swallowed by `except Exception: pass`, resulting in wildcard permission checks always returning `False` and falling back to name-substring matching.
   - *Fix*: Refactored `risk_engine.py` to inspect policy document contents provided via a resolved document lookup map (`policy_doc_map`).
2. **AWS-Managed Policy Document Resolution (`iam_service.py` & `scan_manager.py`)**:
   - *Previous Defect*: `collect_policies()` previously only fetched documents for customer-managed policies (`Scope='Local'`). AWS-managed policies like `AdministratorAccess` or `PowerUserAccess` were never fetched, defaulting to substring checks.
   - *Fix*: Updated `iam_service.py` to capture `attachedPolicyArns` for users and roles, and added `fetch_managed_policy_documents(arns)` to fetch specific AWS-managed policy documents (`arn:aws:iam::aws:policy/...`). `scan_manager.py` dynamically merges these documents into `policy_doc_map` before risk scoring.
3. **CORS Security Hardening (`config.py` & `.env.example`)**:
   - *Previous Defect*: `CORS_ORIGINS` allowed all origins (`*`) by default.
   - *Fix*: Removed `*` wildcard. Replaced with comma-separated list read from environment variable `CORS_ORIGINS`, defaulting to `["http://localhost:5173", "http://localhost:3000"]`. Documented in `.env.example`.
4. **Runtime Scanner Rescheduling API (`scheduler.py` & `settings.py`)**:
   - *New Capability*: Added `reschedule_scan_job(minutes)` to `app/utils/scheduler.py` which atomically reschedules the running `APScheduler` job without creating duplicates or restarting the server. Exposed via `POST /api/v1/settings/scan-interval`.

---

## 2. Frontend Audit & Remediation (Pass 1 & Pass 2)

Every interactive UI element across all 10 pages and component panels was audited and classified into 4 categories:
- **WORKING**: Calls real FastAPI endpoint, processes data, or executes valid DOM actions.
- **REMEDIATED / WIRED**: Previously mocked or dead, now connected to live endpoints or client-side capabilities.
- **REMOVED**: Decorative/dead buttons with no backend capability or duplicate purpose.
- **DOCUMENTED FUTURE WORK**: Labeled explicitly as "Coming Soon" or "Sandbox".

### Detailed Page-by-Page Comparison Matrix

| Page / Component | Interactive Element | Previous State | Current State | Action Taken |
|---|---|---|---|---|
| **Dashboard** | Scan Again button | Working | Working | Preserved (`POST /graph/rebuild` + status polling) |
| **Dashboard** | View All Alerts link | **Dead** (no `onClick`) | **Working** | Wired to navigate to `/alerts` |
| **Dashboard** | Audit Vector button | **Dead** (no `onClick`) | **Removed** | Cleaned up non-functional row button |
| **Resources** | Register Asset button | **Dead** (no backend endpoint) | **Removed** | CloudScope is read-only scanner; button removed |
| **Resources** | View JSON Config button | **Dead** (no `onClick`) | **Working** | Opens modal displaying full pretty-printed JSON with Copy to clipboard action |
| **Alerts** | Clear Resolved button | **Dead** (no `onClick`) | **Working** | Client-side dismiss filter (`dismissedIds` Set). Hides resolved alerts until next scan refresh |
| **Alerts** | Inspect JSON payload | Working | Enhanced | Added Copy details action to expanded payload box |
| **Attack Paths** | Explain with AI button | **Mocked** (`setTimeout` fake) | **Working** | Calls real `POST /api/v1/copilot` endpoint with path metadata and displays AI analysis |
| **NodeDetailsPanel** | Trust Relationship Policy | **Mocked** (hardcoded JSON) | **Working** | Renders real `trustPolicy` from Neo4j/Cytoscape node data with JSON formatting |
| **NodeDetailsPanel** | Attached Policies | **Mocked** (hardcoded policies) | **Working** | Renders actual `policies` list attached to the user, flagging admin privileges |
| **NodeDetailsPanel** | Audit History Logs button | **Dead** (closed panel) | **Removed** | Removed redundant footer button (header X button performs close) |
| **Settings** | Scan Interval Form | **Dead** (3s visual flash only) | **Working** | Submits selection to `POST /api/v1/settings/scan-interval` to reschedule APScheduler at runtime |
| **Settings** | Slack / Email Toggles | **Dead** (local state discard) | **Updated** | Replaced with "Coming Soon" notification integrations banner |
| **Reports** | PDF Export | **Mocked** (wrote static txt) | **Working** | Built client-side PDF generator using `jsPDF` for audit assessment report |
| **Reports** | CSV Export | **Mocked** (hardcoded table) | **Working** | Generates CSV from live compliance audit data |
| **Reports** | JSON Export | Working | Enhanced | Exports live compliance summary + graph data payload |
| **Reports** | SVG Export | **Mocked** (wrote static txt) | **Working** | Generates standalone vector drawing (`.svg`) of node and edge topology |
| **IdentityGraphPage** | Layout Selector (Sidebar) | **Redundant** | **Removed** | Header dropdown retained as single control; sidebar duplicate removed |
| **IdentityGraphPage** | Filter / Export / View Details | **Dead** (no action) | **Removed** | Cleaned up non-functional sidebar buttons |
| **Navbar** | Region Selector | **Dead** (no query effect) | **Removed** | Removed dead selector; documented multi-region support on roadmap |
| **Navbar** | Settings dropdown item | **Dead** (no `onClick`) | **Working** | Wired to navigate to `/settings` |
| **Navbar** | My Profile menu item | **Dead** (no route) | **Removed** | Removed item with no corresponding view |
| **Attack Simulation** | Sandbox Launcher & Selects | **Mocked** (fake delay) | **Labeled** | Marked with explicit banner: "Interactive Sandbox (Custom Graph Engine Coming Soon)" |

---

## 3. Verification & Build Results

- **Backend API**: All 12 router modules loaded (`dashboard`, `users`, `roles`, `resources`, `graph`, `attack_paths`, `alerts`, `reports`, `scan`, `copilot`, `risks`, `settings`).
- **Frontend Production Build**:
  ```bash
  > cloudscope@0.0.0 build
  > tsc -b && vite build
  ✓ built in 29.51s
  ```
  Zero TypeScript errors across all components.
