# AWS account connection guide

CloudScope collects inventory and security configuration through AWS read APIs. Use a dedicated, short-lived credential source for the CloudScope host and a cross-account role for each registered account. Avoid IAM users with long-lived access keys where workload identity, federation, or short-lived profiles are available.

## 1. Configure the CloudScope source credentials

Provide credentials to the backend using its deployment's supported AWS credential chain. For a local workstation, an AWS CLI profile can be used:

```bash
aws configure --profile identityscope-scanner
aws sts get-caller-identity --profile identityscope-scanner
```

Set `AWS_PROFILE=identityscope-scanner` and ensure the profile is available to the backend process. In containers, mount the credentials directory read-only. Never put access keys in source control, frontend configuration, or project records. See [../../docs/secrets.md](../../docs/secrets.md).

## 2. Create a least-privilege role in the target account

Create a role with the collection actions in [`../policies/read_only_scanner_policy.json`](../policies/read_only_scanner_policy.json), adjusting the policy to the services and regions you intend to collect. The policy is read-only in intent but includes wildcard resources because many AWS list/describe APIs do not support resource-level restrictions; review it against your collection needs and AWS service authorization reference.

Configure the role trust policy to allow only the CloudScope source principal to call `sts:AssumeRole`, and require the unique ExternalId shown for that project in the CloudScope Projects screen. Do not reuse ExternalIds across projects or trust arbitrary AWS principals. CloudScope's role verification checks STS identity; it does not prove every collector action is allowed.

## 3. Register and verify the project

In CloudScope, create an AWS account project with its account ID and role ARN. Copy the generated ExternalId into the role trust policy, save the project, then run **Verify role**. Start a manual scan only after verification succeeds. Scans for a selected project assume that project's role; scheduled scans are not yet project-aware.

## 4. Validate carefully

Confirm the caller and target account IDs, check CloudTrail for the expected `AssumeRole` event, and review the scan output for collector permission errors. Start with a non-production account. CloudScope is an inventory and analysis tool; it does not apply remediations to AWS resources.
