# AWS Identity and Policy Review Guidelines

This reference supports CloudScope's configuration analysis. It is defensive guidance, not a complete AWS IAM specification. Validate high-impact decisions with AWS's current service documentation and an isolated test account.

## 1. Minimize effective permissions

- Prefer explicit action and resource scopes. Avoid broad combinations such as `Action: "*"` and `Resource: "*"` when the AWS API supports narrower resource ARNs.
- Many inventory APIs (`List*`, `Describe*`) require `Resource: "*"`; document those exceptions and keep the action list narrow.
- Review identity policies together with resource-based policies, permissions boundaries, session policies, SCPs, trust policies, and service control context. CloudScope does not fully calculate every layer.
- Treat wildcard principal trust, broad `sts:AssumeRole`, privilege-escalation actions, and permissions-policy administration as high risk.

## 2. Harden role assumption

- Trust only the expected source principal or federation provider. Restrict which principals can pass/assume roles where relevant.
- Use short-lived role credentials and review CloudTrail for `AssumeRole` events. ExternalId mitigates the confused-deputy risk; it is not a secret credential or a replacement for principal restrictions.
- Require MFA or other context conditions where compatible with the workload and AWS service behavior. Do not add a condition that breaks the intended noninteractive scanner role without validating the resulting assumption flow.

## 3. Protect credentials and sensitive data

- Prefer workload identity, federation, or short-lived credentials over long-lived IAM user access keys.
- If static credentials are unavoidable for a constrained environment, store them in a managed secret system, restrict usage, rotate on exposure/expiry policy, and monitor last-used metadata.
- Never include credentials, access tokens, private keys, or secret values in policy descriptions, tags, logs, findings, prompt context, or screenshots.

## 4. Interpret CloudScope evidence carefully

- A static attack path indicates a modeled possible configuration transition, not evidence of an actual intrusion.
- CloudScope distinguishes static possible capability from CloudTrail-observed activity and correlated activity. A configured path is not proof of privilege escalation or exploitation; missing CloudTrail events are not proof that activity did not occur.
- Workload pivots such as EC2-to-SSM, Lambda-to-resource, or ECS task-role access require the relevant identity permissions and service prerequisites. Do not infer that read access to a compute resource grants code execution.
- Collection failures and unsupported policy conditions must remain visible as uncertainty. Absence from an incomplete scan is not proof that a resource or permission does not exist.
- Use source evidence, account/region provenance, scan ID, and snapshot ID when validating a finding. Confirm remediation against the AWS account before changing policy.
- What-if simulations and AI explanations are advisory workflows. They do not replace AWS policy validation, change approval, or a controlled rollout.
