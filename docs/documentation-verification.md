# Documentation Review Record

**Review date:** 2026-10-22
**Repository:** `SurendiranBJ/CloudScope`
**Purpose:** Record how repository-owned project documentation was reconciled with the implementation. This is a documentation/source review, not a product certification.

## Scope

Reviewed Git-tracked Markdown documentation, the root README, the AWS setup guide, Copilot guidelines, `.env.example`, Compose configuration, backend settings, API routers, scanner/analysis modules and frontend routes. Dependency-owned documentation under `node_modules` and generated cache docs were excluded. No tracked PDF, Word or other report template was present in the repository at review time.

The README is the entry point. `phase3-architecture.md` now describes service coverage, region handling, evidence categories, supported analysis behavior and limitations. Focused docs explain configuration, deployment, authentication, roles, security, secrets, audit, operations, observability, simulation, readiness and validation evidence.

## Source-of-truth checks

- Runtime settings: `backend/app/config.py`, `.env.example`, `compose.yaml`, `compose.release.yaml`.
- Credential resolution: `backend/app/services/aws/session.py`; backend AWS credentials select one account per deployment.
- Region discovery: `backend/app/services/aws/region_cache.py`; UI region selection and scan recording in `frontend/src/components/RegionSelector.tsx` and `backend/app/services/scanner/scan_manager.py`.
- Collector set: `backend/app/services/scanner/scan_manager.py` and `backend/app/services/aws/`.
- Policy/graph/path/risk: `backend/app/services/attack/`, `backend/app/services/graph/` and `backend/app/services/risk/`.
- Snapshot history: `backend/app/services/scanner/snapshot_store.py`, `backend/app/persistence/repository.py`, `backend/app/routers/snapshots.py`.
- Simulation: `backend/app/services/simulation/`, `backend/app/routers/simulation.py`, and the What-If/Saved Changes frontend.
- Authentication/RBAC: `backend/app/security/` and route-level dependencies.
- User workflows/API clients: `frontend/src/App.tsx`, `frontend/src/pages/`, `frontend/src/components/`, and `frontend/src/api/`.
- AWS permissions: `aws/policies/read_only_scanner_policy.json` and `aws/templates/deployment_guide.md`.

## Corrections made for clarity

- Clarified that the current UI scans one credential-selected account and does not offer Projects/account-role onboarding.
- Documented legacy project tables/columns as compatibility data, not an active multi-account feature.
- Replaced broad “all AWS resources” implications with the actual current collector list and service-level detail limits.
- Documented the difference between static potential capability, CloudTrail-observed activity and correlation.
- Clarified that read permission alone does not imply execution on EC2; workload pivots require specific control actions and remain conditional.
- Specified the simulation's supported actions/principals and its no-AWS-write guarantee.
- Corrected the region-selection explanation: empty `SCAN_REGIONS` allows enabled-region discovery; a UI single/global choice can override configured mode as documented.
- Updated verification records to show successful local checks, incomplete suites and unverified hosted/deployment/AWS validation separately.

## Accuracy limits

Documentation describes the source paths inspected and may not cover every runtime override. IAM semantics are partial; regional inventory may be partial; database migration/recovery and deployment isolation remain unverified. Configuration values can be overridden by shell, `.env`, Compose or a deployment platform. Secrets and real account identifiers must not be copied into documentation.

## Verification record

The current check inventory is [final-verification.md](final-verification.md). Frontend build and lint were run after the current UI theme edits; focused backend tests and the last frontend unit run are dated separately there. The full backend scanner suite and hosted CI were not established for this local workspace.
