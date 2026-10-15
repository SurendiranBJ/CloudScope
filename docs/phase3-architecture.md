# Security Analysis Architecture Notes

**Reviewed:** 2026-10-15
**Status:** Descriptive design note; source code and schemas are authoritative.

CloudScope produces evidence-backed security analysis from collected AWS inventory. The application distinguishes a configuration-derived possibility from activity corroborated by collected CloudTrail data. It does not claim complete AWS authorization equivalence or complete runtime attack detection.

## Analysis flow

1. Collect supported AWS identity, policy, resource, and CloudTrail data.
2. Preserve scan/snapshot provenance and regional collection outcomes.
3. Evaluate supported IAM and trust-policy constructs with structured evidence.
4. Build graph relationships and bounded candidate attack paths.
5. Calculate CloudScope risk and reachable-resource summaries.
6. Synthesize findings and expose details through APIs/UI.
7. Optionally request an AI explanation based on selected evidence.

## Evidence and uncertainty

Static capability paths describe graph transitions the modeled configuration appears to allow. Correlated or observed activity labels require matching collected runtime evidence. A missing CloudTrail event is not proof that activity did not occur. Partial collection, unsupported conditions, graph-size ceilings, or failed analysis can limit conclusions.

## Current user workflow

The Attack Paths page orders groups by severity and risk score and numbers the visible filtered results sequentially. The Cloud Graph can trace selected identities/paths. Finding details expose status, evidence, provenance, and analyst workflow. AI explanations are optional and advisory.

## Boundaries

- IAM behavior is only as complete as implemented policy, principal, resource, boundary, condition, and service semantics.
- Graph reachability is a topology model, not proof of exploitability.
- Risk scores are product-specific prioritization values, not compliance outcomes.
- Path search is bounded; large graphs may require pagination, truncation reporting, or optimization.
- Simulation drafts are durable what-if inputs and never mutate AWS.
- Production-grade tenant isolation and large-account performance still require external review and deployment testing.
