# AWS Coverage and Security Analysis Architecture

**Updated:** 2026-10-22
**Status:** Describes the current source design; source code and API schema remain authoritative.

## Purpose and boundary

CloudScope collects selected AWS inventory and evidence, then models how identities may reach resources under supported IAM semantics. It is a security-analysis aid. It is not an AWS-managed detection service, a complete AWS inventory, an IAM authorization oracle, or proof of exploitation.

## Data collection coverage

The scan status has sixteen collector groups:

| Collector group | AWS data collected |
| --- | --- |
| `IAM_Users` | IAM users, user attributes, membership/attached policy references and selected credential/MFA metadata. |
| `IAM_Groups` | IAM groups, group membership and attached policy references. |
| `IAM_Roles` | IAM roles, trust documents and attached policy references. |
| `IAM_Policies` | Policies discoverable through the configured account and attached/inline policy sources used by the scan. The Policies UI also queries a separate attachable policy catalog. |
| `EC2` | Regional EC2 instances and selected instance metadata. |
| `S3` | Buckets and selected security configuration such as access-block/public-access and encryption metadata. |
| `Lambda` | Functions, selected configuration and execution-role references. |
| `Secrets` | Secrets Manager secret metadata and rotation/configuration status. The collector does not retrieve secret values. |
| `RDS` | Database instance metadata and selected configuration; resource/connection policy paths where data is available. |
| `DynamoDB` | Table metadata and selected security/backup configuration. |
| `ECS` | Running ECS tasks, task definitions, task/execution role references, images and execute-command configuration. |
| `ECR` | Repositories, image tag mutability and repository policy documents where permission allows. No image layers are downloaded. |
| `CodeCommit` | Repository metadata such as ARN/default branch. Source code contents are not collected. |
| `ExtendedAWS` | SQS queue metadata/policies, SNS topic metadata/policies, customer-managed KMS key metadata/policies, EKS cluster metadata and Step Functions state-machine metadata. No queue/topic payloads, key material or state-machine inputs are read. |
| `AccessAnalyzer` | Available IAM Access Analyzer findings in the configured account/regions. Empty means no findings were returned in collected scope, not global proof of safety. |
| `CloudTrail` | Selected recent security-relevant management/data event types according to service permissions, region and configured event history availability. |

This is a deliberate subset of AWS services and fields. Check [real AWS validation](real-aws-validation.md) before relying on current production coverage. Collector success-empty, failure and partial-region statuses have different meanings.

## Region selection and completion

The runtime region resolver follows this order:

1. UI-requested single region.
2. Explicit `SCAN_REGIONS` list, unless the UI explicitly chose global mode.
3. EC2 `DescribeRegions` discovery of enabled regions when no list is configured or global mode is selected.
4. Session/default-region fallback if discovery fails or returns no enabled regions.

Regional service results include successful, empty and failed regions. A failure to enumerate a region must not be interpreted as a zero-resource region. A snapshot records scan mode, attempted/resolved regions, successful/failed regions and collection-completeness metadata where available. Runtime region selection is held in process memory and should be rechecked after a backend restart.

## Analysis pipeline

1. **Normalize:** convert AWS responses to internal IAM and resource records with ARN, account, region, type and selected details.
2. **Policy evidence:** evaluate supported identity policies, inline policies, group membership and trust/role assumptions. Resource policy documents are included only for collectors that retrieve them.
3. **Graph construction:** create nodes for identities, groups, roles, policies, workloads and supported resources. Edges preserve relationship semantics such as membership, attached policy, assumption, execution role, permission and data connection.
4. **Validate transitions:** the path engine checks allowed typed transitions; a generic graph edge does not itself grant access.
5. **Calculate access and risk:** derive action categories, candidate reachable assets, blast-radius summaries, risk factors and findings.
6. **Enumerate paths:** search simple candidate paths with maximum six role hops and emit at most 200 attack paths. Output limits and unsupported semantics may omit possibilities.
7. **Correlate activity:** selected CloudTrail events are normalized and compared to modeled transitions. This correlation has event coverage and matching limits.
8. **Publish:** persist scan metadata and data as an immutable snapshot and make it current atomically after durable publication.

NetworkX supports in-process graph analysis. Neo4j stores/loads graph topology. SQL stores snapshots, scan runs and workflows. Redis provides cache/scan coordination. Store outages and deployment setup can affect behavior; see [operations](operations.md).

## Access mode and workload pivots

The evaluator classifies supported actions into user-facing categories such as read, write, delete, execute, access and administrative. A read action on an EC2 resource is not treated as permission to execute code there. Workload pivots require selected control-capable actions and relationship evidence:

| Workload | Example actions considered for a possible control pivot | Important limitation |
| --- | --- | --- |
| EC2 | `ssm:SendCommand`, `ssm:StartSession`, `ec2-instance-connect:SendSSHPublicKey` | Instance reachability, SSM agent/role/configuration, operating-system controls and credentials are not all verified by static inventory. |
| Lambda | `lambda:UpdateFunctionCode` | Code deployment prerequisites, artifact provenance, runtime state and downstream credentials may be unknown. |
| ECS | `ecs:ExecuteCommand` | The collected task must have execute-command enabled; cluster/task configuration and runtime access still need validation. |
| Step Functions | `states:StartExecution` | State-machine definition/data-flow and downstream integrations can limit what execution can do. |

The engine may include further action checks. Treat path evidence and uncertainty as the source for review. Do not generalize a supported workload pivot to every AWS resource or permission.

## Evidence categories

| Category | Source | Interpretation |
| --- | --- | --- |
| `POSSIBLE_CAPABILITY` | Static inventory, IAM documents and graph rules | Configuration appears to permit a modeled transition. Does not prove runtime prerequisites or use. |
| `OBSERVED_ACTIVITY` | Collected CloudTrail event | AWS recorded an event. Actor attribution, event coverage and intent require interpretation. |
| `CORRELATED_ACTIVITY` | Event plus matching graph capability | Activity and a modeled capability align under current correlation rules. |
| `OBSERVED_ATTACK_ACTIVITY` | Event matching an identified path transition | Stronger product-level correlation, still dependent on event completeness and matching logic; investigate the source event. |

An absent CloudTrail event is not evidence that the event could not occur. CloudTrail data events may require explicit configuration and additional permissions/cost. Access Analyzer findings are a separate AWS source and do not replace path analysis.

## What-If Analysis

Simulation accepts multiple `ATTACH_POLICY`/`DETACH_POLICY` changes against `USER`, `GROUP`, or `ROLE` identities. It applies the proposal to an in-memory desired inventory copy, then runs the shared graph, effective-access, risk, blast-radius and attack-path logic against current and desired state. The result includes graph/path/reachable-resource differences, and saved changes can be edited or removed.

Simulation drafts are saved to SQL by analyst identity. Preview can be computed before saving. No IAM write API is called; no draft is deployed. Current/proposed accuracy inherits the scan's completeness and the custom evaluator's semantic limits. Arbitrary inline policy document editing, new-role creation and every AWS change type are not modeled.

## User-visible workflows

- Dashboard presents status and summarized posture.
- Cloud Resources lists collected service records.
- Cloud Graph explores identity/resource relationships and opens evidence panels.
- Attack Paths groups candidate paths, highlights targets and links to graph context.
- Security Findings manages prioritized finding state and evidence.
- Policies shows discovered/attachable policy metadata and risk information.
- What-If Analysis and Saved Changes compare proposed managed policy changes.
- Alerts distinguishes event data from static capability and provides optional explanation.
- Reports exports supported summaries and graph data.
- Snapshot History restores a read-only application view from up to ten retained full scans; return to live mode to inspect current data.

## Known analytical limits

- No complete implementation of AWS evaluation order across identity/resource policies, permissions boundaries, session policies, SCPs, RCPs, VPC endpoint policies, service control context and every condition key.
- Cross-account/resource-policy behavior and some service-specific authorization semantics may be partial or unsupported.
- Workload code execution and resource data flow have runtime prerequisites not fully visible in inventory.
- Collector permission failures, region failures and API throttles reduce coverage.
- Path depth and output limits can omit findings at graph scale.
- Risk scores are CloudScope model values, not AWS determinations or compliance certifications.
- AI explanations are probabilistic and may omit or misstate evidence.

Validate critical decisions in AWS and document the source scan ID, snapshot ID, regions and evidence.
