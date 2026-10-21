# Real AWS Validation Record

**Current status:** No fresh real-AWS validation was performed for the 2026-10-22 working tree.

## Historical artifact review

An earlier report recorded a run with 6 users, 2 groups, 26 roles, 39 policies, 10 resources, 263 graph edges, 31 attack paths, and 52 findings. It also recorded the scan as SCANNING with duration 0.0 seconds, zero graph nodes, and a failed risks endpoint, while marking all validation criteria as passed.

These contradictory fields make the historical artifact INCONCLUSIVE. The counts may provide context but are not treated as verified current metrics, complete account coverage, or release evidence. The report does not validate the current credential-selected account scan workflow.

## Procedure for a future run

1. Use a dedicated AWS test account and explicitly read-only scanner credentials available to the backend runtime.
2. Confirm the active account and principal with STS from the same runtime environment.
3. Trigger a manual scan; account selection comes from the backend credential configuration.
4. Record commit SHA, scan ID, snapshot ID, account ID, regions attempted/succeeded/failed, and completion status.
5. Confirm that dashboard, resources, policies, findings, graph, attack paths, and reports show the same published snapshot.
6. Confirm incomplete/permission-denied collection is visible rather than interpreted as absence.
7. Confirm the AWS principal has no mutation permissions and review AWS API/CloudTrail evidence.
8. Save sanitized logs/results according to the data handling policy.
