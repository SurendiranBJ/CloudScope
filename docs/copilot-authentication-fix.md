# Historical note: Explain with AI authentication incident

This file records a prior local-development incident and is retained for context. It is not a current deployment or verification report; the exact working tree and test results change over time. For current configuration, read [authentication.md](authentication.md), [configuration-reference.md](configuration-reference.md), and [release-readiness.md](release-readiness.md).

The reported symptom was an authentication error when using Explain with AI. The investigation at that time identified stale local bearer-token state, inconsistent development identity headers, and confusing error presentation as contributing issues. The then-current change set added token cleanup after unauthorized responses, more specific error messaging, and regression coverage.

Do not copy the historical local-development settings into production. Production must use configured OIDC/JWT validation with development authentication disabled. An AI explanation also requires a configured provider and may send finding/path context to that provider; review the current security and data-handling docs before enabling it.
