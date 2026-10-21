# AWS connection guide

CloudScope collects inventory and security configuration through AWS read APIs. It scans the single AWS account identified by credentials configured on the backend host or container; the UI does not select an account or assume a user-selected role. Prefer workload identity, federation, or short-lived profiles over long-lived IAM user keys.

## 1. Configure backend credentials

For a local workstation, configure an AWS CLI profile and confirm its identity:

```bash
aws configure --profile identityscope-scanner
aws sts get-caller-identity --profile identityscope-scanner
```

Set `AWS_PROFILE=identityscope-scanner` for the backend process and ensure the profile is available there. The backend may use the AWS SDK credential chain when no usable named profile is selected. In containers, mount the credentials directory read-only. Alternatively, provide credentials through the AWS SDK default chain, such as a task or instance role. Never put access keys in source control or frontend configuration. See [../../docs/secrets.md](../../docs/secrets.md).

## 2. Grant collection permissions

Attach the actions in [`../policies/read_only_scanner_policy.json`](../policies/read_only_scanner_policy.json) to the configured principal, adjusting the policy to the services and regions you intend to collect. The sample policy is read-only in intent but includes wildcard resources because many AWS list/describe APIs do not support resource-level restrictions. Review it against your collection needs and the AWS service authorization reference. Collector status is per service: an empty result and a permission or regional failure have different meanings.

## 3. Validate carefully

Confirm the configured identity and account using `aws sts get-caller-identity` in the same environment as the backend. Review scan status and diagnostics for collector permission errors. Start with a non-production account. CloudScope is an inventory and analysis tool; it does not apply remediations to AWS resources.
