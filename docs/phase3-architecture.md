# Phase 3 Architecture: Provenance-Aware Security Analysis & Attack Path Hardening

## Overview
Phase 3 establishes rigorous provenance tracking, explainable attack path derivation, deterministic canonical IDs, authoritative blast-radius quantification, unified finding lifecycles with reopen lineage, CloudTrail activity correlation with confidence tiers, AI/Copilot grounding, and a fail-closed CD release pipeline.

---

## 1. Provenance-Aware Security Analysis & Snapshot Isolation
- **Snapshot Scoping**: All analytical derivations (attack paths, blast radii, risk assessments, security findings) are bound to immutable snapshot identifiers (`snapshot_id`, `source_snapshot_id`, `snapshot_published_at`).
- **Audit Lineage**: Every finding and attack path carries explicit provenance fields linking back to the exact discovery scan run, configuration snapshot, and policy evaluator context.
- **Model Versioning**: Analysis engines explicitly tag their outputs with `risk_model_version = "phase3-v1"` to guarantee analytical reproducibility and model governance over time.

---

## 2. Explainable Attack Paths & Privilege Escalation
- **Deterministic Canonical Identification**:
  - Attack paths receive stable canonical IDs computed via `ap-{sha256(start_node|steps|target_node)[:12]}`.
  - Ensures path identity is reproducible and completely decoupled from non-deterministic traversal sequence or transient array indexes (`path-001`).
- **Structured Transition Evidence**:
  - Each step along an attack path provides granular authorization evidence:
    - Step type (`STS_ASSUME_ROLE`, `IAM_PASS_ROLE`, `PRIVILEGE_ESCALATION`, `SERVICE_ACCESS`).
    - Evaluated authorization decision (`ALLOWED` / `DENIED`).
    - Exact matching policy statement (`policy_name`, `statement_sid`, `action`, `resource`).
    - Trust policy conditions, role boundaries, and principal ARNs.
- **PassRole Escalation Modeling**:
  - Models `iam:PassRole` combinations with compute services (`ec2:RunInstances`, `lambda:CreateFunction`, `ecs:RunTask`), verifying role trust relationships and target permissions.
- **Traversal Limits & Loop Bounds**:
  - Strict computational ceilings prevent infinite cycles and combinatorial explosions:
    - `max_paths_per_source = 25`
    - `max_candidate_transitions = 1000`
    - `max_execution_time_seconds = 10.0`
  - Explicit truncation flags (`is_truncated: bool`, `truncation_reason: str`) ensure consumers know when search boundaries were triggered.

---

## 3. Authoritative Blast Radius Model
- **Resource Classification**:
  - **Data Resources (`DATA_RESOURCE_TYPES`)**: High-value data repositories (`S3`, `Secrets`, `Secret`, `RDS`, `DynamoDB`).
  - **Operational Assets (`OPERATIONAL_RESOURCE_TYPES`)**: Compute infrastructure (`EC2`, `Lambda`).
  - **IAM Principals & Intermediaries**: Roles and policies are excluded from data asset counts to prevent inflated impact metrics.
- **Metrics**:
  - `data_resource_count`: Count of unique reachable data resources.
  - `operational_resource_count`: Count of reachable operational assets.
  - `shortest_path_to_data`: Traversal depth from source to reachable assets.
  - `reachable_data_resources`: Granular list of ARNs and metadata for affected data stores.

---

## 4. Deterministic Risk Engine
- **Scoring Model**: Versioned as `phase3-v1`.
- **Global Posture & Entity Scores**:
  - Principals and resources receive bounded 0–100 scores based on additive risk factors.
  - Posture calculations remain strictly deterministic: identical topology and configuration snapshots always yield bit-for-bit identical risk scores.
- **Risk Explanation API**:
  - `GET /api/v1/risk-explanation/{entity_id}` returns factor breakdowns, contributing policies, blast radius exposure, and remediation guidance.

---

## 5. CloudTrail Normalization & Confidence Correlation
- **Canonical Event Normalization**:
  - Missing or unstructured event IDs fallback to deterministic hashes: `ct-{sha256(event_time|event_name|actor|source_ip)[:16]}`.
  - Extracts full metadata: `management_event`, `session_context`, `response_elements`, `resource_names`, `source_type: "CLOUDTRAIL"`.
- **Temporal & Session Tracking**:
  - Events are sorted chronologically by timezone-aware timestamps.
  - Assumed-role session mapping traces STS AssumeRole operations forward to subsequent API calls by temporary credentials.
- **Deterministic Confidence Tiers**:
  - `EXACT` (100%): Observed CloudTrail activity matches both static IAM permissions and attack path transition edge.
  - `HIGH` (85%): Activity matches static permissions and involved entity, but outside active attack path.
  - `MEDIUM` (65%): Activity recorded in related account/region with plausible principal match.
  - `LOW` (30–40%): General anomalous or management activity.

---

## 6. Unified Finding Lifecycle & Regional Isolation
- **Deterministic Finding IDs**:
  - Synthesized findings derive IDs from canonical path IDs (`find-path-{clean_path_id}`) and resource/principal keys (`find-{type}-{hash}`).
- **State Machine Transitions**:
  - Supported states: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `SUPPRESSED`.
  - Reopening Lineage: If a previously `RESOLVED` finding reappears in a subsequent scan snapshot, its status transitions to `OPEN`, `resolvedAt` is cleared, and historical reopen lineage (`reopened_at`, `reopened_from_finding_id`, `previous_resolved_at`) is preserved in `evidence`.
- **Regional Failure Isolation**:
  - If a scan fails or partially degrades in specific AWS regions, findings located in those failed regions are **not** marked `RESOLVED`. They remain in their prior state until a successful scan verifies resolution.

---

## 7. AI / Copilot Grounding & Safety
- **Strict Citation Requirements**:
  - The AI assistant is constrained by prompt guidelines to cite only verified system artifacts:
    - `Finding <ID>`
    - `Attack Path <ID>`
    - `CloudTrail Event <ID>`
    - `Snapshot <ID>`
- **Fabrication Prohibition**:
  - AI may never invent AWS ARNs, event IDs, or policy statements.
- **Prompt Injection Defense**:
  - System prompts enforce clear role separation and instruct the model to ignore user attempts to override safety boundaries or posture scoring rules.
- **Non-Blocking Resilience**:
  - Failure of the AI provider or external LLM service degrades gracefully without interrupting core scanning, graph analysis, or API delivery.

---

## 8. Phase 3 Security Investigation APIs
- `GET /api/v1/findings/{id}/evidence`: Returns full authorization evidence, policy statements, and CloudTrail correlation data.
- `GET /api/v1/attack-paths/{id}/evidence`: Returns step-by-step transition evidence, evaluated policy ASTs, and blast radius details. Supports both sequential and canonical path IDs.
- `GET /api/v1/attack-paths`: Supports filtering by `severity`, `source`, `target_type`, `region`, and pagination (`limit`, `offset`, `page`, `page_size`).
- `GET /api/v1/risk-explanation/{entity_id}`: Delivers detailed risk factor composition, blast radius impact, and contextual mitigations.
- `GET /api/v1/alerts`: Paginated and filterable security alert stream.

---

## 9. CD & Release Automation Hardening
- **Fail-Closed Tag Discovery**:
  - Release pipeline discovers remote tags via `git ls-remote --tags origin`. If tag discovery fails or encounters an empty result, the workflow terminates immediately (`sys.exit(1)`), preventing accidental `v1.0.0` or zero-tag resets.
- **Same-SHA Release Idempotency**:
  - The workflow checks if the current commit SHA has already been released (including peeled annotated tags `^{}`). If already released, the pipeline skips Docker building/pushing, Git tagging, and GitHub release generation cleanly with `already_released=true`.
- **Release Immutability**:
  - Existing version tags (such as `v1.0.0` and `v1.0.1`) are treated as immutable and never overwritten.
- **Queue Concurrency Control**:
  - Stale queued CD runs on the same branch are automatically cancelled via `gh run cancel`, eliminating redundant worker backlog.

---

## 10. Observability & Performance Metrics
Prometheus metrics exported via `backend/app/metrics/metrics.py`:
- `attack_paths_analyzed_total`
- `attack_paths_truncated_total`
- `path_traversal_duration_seconds`
- `cloudtrail_events_normalized_total`
- `cloudtrail_correlations_total`
- `cloudtrail_correlation_duration_seconds`
- `findings_created_total`
- `findings_updated_total`
- `findings_reopened_total`
- `risk_evaluations_total`
- `evidence_retrieval_duration_seconds`
- `copilot_failures_total`
