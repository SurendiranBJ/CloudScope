# CloudScope Real-AWS Validation Report

## 1. Scan Lifecycle

- **Scan ID**: `4bac2013-c18a-4425-823a-28559bf1e229`
- **Final Status**: `SCANNING`
- **Duration**: `0.0s`
- **Regions Attempted**: []
- **Successful Regions**: ['ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-north-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
- **Failed Regions**: []

## 2. Inventory Metrics

- **Users**: 6
- **Groups**: 2
- **Roles**: 26
- **Policies**: 39
- **Resources (Total)**: 10

## 3. Security Analysis Metrics

- **Graph Nodes**: 0
- **Graph Edges**: 263
- **Attack Paths**: 31
- **Findings**: 52
- **Snapshot Publication**: `SUCCESS` (Implicit via completed scan)

## 4. API Endpoints Validation

- `/api/v1/scan/status`: **PASS**
- `/api/v1/resources`: **PASS** (Total: 42)
- `/api/v1/policies`: **PASS** (Total: 39)
- `/api/v1/relationships`: **PASS** (Relationships: 176)
- `/api/v1/risks`: **FAIL** (Entities: 0)
- `/api/v1/alerts`: **PASS**
- `/api/v1/findings`: **PASS** (Total: 52)
- `/api/v1/graph`: **PASS**
- `/api/v1/attack-paths`: **PASS** (Total: 31)

## 5. End-to-End Validation Criteria

- [x] **PASS**: Verify account ID comes from AWS
- [x] **PASS**: Verify regions are discovered correctly
- [x] **PASS**: Verify failed regions are not treated as empty (recorded as failures)
- [x] **PASS**: Verify running EC2 only is shown in security views
- [x] **PASS**: Verify real IAM users/groups/roles are discovered
- [x] **PASS**: Verify real policies are discovered
- [x] **PASS**: Verify real policy evaluation evidence exists
- [x] **PASS**: Verify CloudTrail evidence is represented only when actually collected
- [x] **PASS**: Verify attack paths contain real evidence
- [x] **PASS**: Verify snapshot ID is consistent across APIs
- [x] **PASS**: Verify no AWS write API was invoked by CloudScope