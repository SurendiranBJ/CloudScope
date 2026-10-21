# Verification Notes

**Updated:** 2026-10-22
**Purpose:** Keep local checks and their limits explicit. This record is not a production certification.

## Checks recorded for the current work

| Check | Result | Scope and timing |
| --- | --- | --- |
| Frontend TypeScript and production build | PASS | `npm run build`, 2026-10-22, after theme changes. |
| Frontend lint | PASS with warnings | `npm run lint` exited 0 on 2026-10-22. Non-blocking Fast Refresh warnings and an existing hook dependency warning remain in the repository. |
| Focused backend tests | PASS: 47 passed | Snapshot consistency, AI provider, API endpoints and audit logging; 2026-10-21. |
| Frontend unit tests | PASS: 33 passed | Last run 2026-10-21, before the latest theme source changes. |
| Diff whitespace check | PASS before this documentation edit | `git diff --check`; repeat after all documentation changes. |

## Not verified for this workspace

- Full backend regression suite after the latest changes.
- Complete scanner/snapshot CI group. A long attempt was interrupted before finishing; do not treat it as a pass.
- Frontend unit suite after the theme source updates.
- Hosted GitHub Actions result for the current local workspace.
- Fresh real AWS scan, exact regional/service coverage, throttling behavior, or credential refresh during a long scan.
- Production Compose startup, OIDC login, PostgreSQL migration, Redis/Neo4j recovery, backup restore, or rollback.
- Penetration test, large-account performance test, or independent AWS authorization-model review.

## Reproduction commands

Run from the repository root or the corresponding folder:

```powershell
cd backend
python -m pytest -q
python -m compileall -q app tests

cd ..\frontend
npm test
npm run lint
npm run build
```

For a release decision, run all applicable checks on the same pinned commit and attach the hosted CI and deployment evidence to that release record. Local checks on a modified working tree do not certify a pushed artifact.

## Historical verification

Earlier reports of 564 backend tests, 502 backend tests, or real-AWS inventory counts refer to earlier code and environments. They are not evidence for the current workspace. See [real AWS validation](real-aws-validation.md) for the handling of the older AWS artifact.
