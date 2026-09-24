export interface IAMUser {
  id: string;
  name: string;
  arn: string;
  status: 'active' | 'inactive';
  policies: string[];
  groups: string[];
  riskScore: number;
  mfaEnabled: boolean;
  lastActive: string;
}

export interface IAMRole {
  name: string;
  arn: string;
  trustPolicy: string;
  description: string;
  activeSessions: number;
  riskScore: number;
}

export interface IAMPolicy {
  name: string;
  arn: string;
  type: 'custom' | 'aws-managed';
  document: string;
  riskScore: number;
}

export interface CloudResource {
  name: string;
  type: 'User' | 'Role' | 'S3' | 'EC2' | 'Lambda' | 'Secrets' | 'RDS' | 'Policy' | 'DynamoDB';
  region: string;
  status: 'active' | 'stopped' | 'configured' | 'warning' | 'critical';
  owner: string;
  arn: string;
  riskScore: number;
  state?: string;
  instance_state?: string;
  details?: Record<string, any>;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  resource: string;
  description: string;
  status: 'open' | 'suppressed' | 'resolved';
  details: string;
}

export interface AttackPathNode {
  id: string;
  name: string;
  type: 'User' | 'Role' | 'EC2' | 'S3' | 'Lambda' | 'Secrets' | 'Policy' | string;
  riskScore?: number;
}

export interface DownstreamReachableAsset {
  id: string;
  name: string;
  type: string;
  arn?: string;
  region?: string;
  riskScore?: number;
  access_category?: string;
  evidence?: Record<string, any>;
}

export interface TransitionEvidence {
  from_node: string;
  from_name?: string;
  from_type?: string;
  to_node: string;
  to_name?: string;
  to_type?: string;
  relationship: string;
  why: string;
  policy_name?: string;
  statement_sid?: string;
  action?: string;
  resource_arn?: string;
  decision?: string;
  condition_status?: string;
  region?: string;
  evidence?: Record<string, any>;
}

export interface PrivilegeEscalationDetails {
  title?: string;
  summary?: string;
  source_identity?: string;
  target_identity?: string;
  trigger_permission: string;
  supporting_evidence?: Record<string, any>;
  impact?: string;
  reason?: string;
  limitations?: string;
  is_passrole?: boolean;
  target_role?: string;
  target_role_trust_evidence?: string;
  risk_elevation?: string;
}

export interface LateralMovementDetails {
  origin?: string;
  transition?: string;
  destination?: string;
  authorization_evidence?: string;
  impact?: string;
  service_trust?: string;
  is_lateral?: boolean;
}

export interface AttackPath {
  id: string;
  name: string;
  nodes: AttackPathNode[];
  ordered_nodes?: AttackPathNode[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  riskScore?: number;
  risk_score?: number;
  confidence?: number;
  pathType?: string;
  attack_type?: string;
  orderedRelationships?: string[];
  ordered_relationships?: string[];
  blastRadius: string;
  mitreTechniques: string[];
  recommendation: string;
  description: string;
  reason?: string;
  source?: string;
  destination?: string;
  target?: string;
  diffStatus?: 'new' | 'removed' | 'changed' | 'unchanged' | string;
  region?: string;
  evidence?: TransitionEvidence[];
  privilege_escalation_details?: PrivilegeEscalationDetails;
  privilegeEscalationDetails?: PrivilegeEscalationDetails;
  lateral_movement_details?: LateralMovementDetails;
  lateralMovementDetails?: LateralMovementDetails;
  risk_factors?: Record<string, any>;
  correlation_status?: 'POSSIBLE_CAPABILITY' | 'OBSERVED_ACTIVITY' | 'CORRELATED_ACTIVITY' | 'OBSERVED_ATTACK_ACTIVITY' | string;
  correlationStatus?: 'POSSIBLE_CAPABILITY' | 'OBSERVED_ATTACK_ACTIVITY' | 'CORRELATED_ACTIVITY' | 'OBSERVED_ACTIVITY' | string;
  observed_activity?: any[];
  observedActivity?: any[];
  target_type?: string;
  target_category?: string;
  targetCategory?: string;
  downstream_reachable_assets?: DownstreamReachableAsset[];
  downstreamReachableAssets?: DownstreamReachableAsset[];
}

export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'SUPPRESSED';

export type SecurityFindingCategory =
  | 'IAM'
  | 'RESOURCE'
  | 'PRIVILEGE_ESCALATION'
  | 'LATERAL_MOVEMENT'
  | 'CLOUDTRAIL'
  | 'CREDENTIAL'
  | 'CONFIGURATION'
  | 'DATA_ACCESS'
  | 'MONITORING';

export interface FindingRemediation {
  title: string;
  summary: string;
  steps: string[];
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  references?: string[];
}

export interface SecurityFinding {
  id: string;
  type: string;
  category: SecurityFindingCategory | string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  riskScore: number;
  riskFactors?: { code: string; points: number; reason: string }[];
  principal?: string;
  principalType?: string;
  resource?: string;
  resourceType?: string;
  region?: string;
  policy?: string;
  policyArn?: string;
  statementSid?: string;
  action?: string;
  resourceArn?: string;
  attackPathId?: string;
  eventId?: string;
  eventName?: string;
  eventTime?: string;
  evidence?: Record<string, any>;
  impact?: string;
  remediation?: FindingRemediation;
  status: FindingStatus;
  firstSeen?: string;
  lastSeen?: string;
  source: 'STATIC_IAM' | 'RESOURCE_CONFIGURATION' | 'ATTACK_PATH' | 'CLOUDTRAIL' | 'CORRELATION' | string;
  tags?: string[];
  // Backwards compatibility with RiskFinding
  identity?: string;
  identityType?: 'User' | 'Role' | 'EC2' | 'Lambda' | string;
  issue?: string;
  recommendation?: string;
}

export interface RiskFinding {
  id: string;
  identity: string;
  identityType: 'User' | 'Role' | 'EC2' | 'Lambda' | string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  riskScore: number;
  recommendation: string;
  // Extended canonical finding fields
  type?: string;
  category?: string;
  title?: string;
  description?: string;
  riskFactors?: { code: string; points: number; reason: string }[];
  principal?: string;
  principalType?: string;
  resource?: string;
  resourceType?: string;
  region?: string;
  policy?: string;
  policyArn?: string;
  statementSid?: string;
  action?: string;
  resourceArn?: string;
  attackPathId?: string;
  eventId?: string;
  eventName?: string;
  eventTime?: string;
  evidence?: Record<string, any>;
  impact?: string;
  remediation?: FindingRemediation;
  status?: FindingStatus;
  firstSeen?: string;
  lastSeen?: string;
  source?: string;
  tags?: string[];
}

export interface DashboardData {
  securityScore: string;
  stats: {
    users: number;
    roles: number;
    policies: number;
    risks: number;
    paths: number;
    resources: number;
  };
  activityMetrics?: {
    staticAttackPaths: number;
    observedSecurityEvents: number;
    correlatedFindings: number;
    observedAttackActivity: number;
  };
  riskDistribution: { name: string; value: number; color: string }[];
  recentAlerts: SecurityAlert[];
  criticalPaths: AttackPath[];
  recommendations: { title: string; desc: string }[];
  lastScan?: {
    timestamp: string;
    duration_seconds: number;
    resources_found: number;
    risks_found: number;
    graph_nodes_count: number;
    graph_edges_count: number;
    scanned_regions?: string[];
    phase_durations?: {
      discovery?: number | { duration_seconds?: number; status?: string };
      iam_analysis?: number | { duration_seconds?: number; status?: string };
      graph_construction?: number | { duration_seconds?: number; status?: string };
      path_analysis?: number | { duration_seconds?: number; status?: string };
      cloudtrail_correlation?: number | { duration_seconds?: number; status?: string };
      finding_synthesis?: number | { duration_seconds?: number; status?: string };
      total?: number | { duration_seconds?: number; status?: string };
    } | Record<string, any>;
  };
  phaseDurations?: {
    discovery?: number | { duration_seconds?: number; status?: string };
    iam_analysis?: number | { duration_seconds?: number; status?: string };
    graph_construction?: number | { duration_seconds?: number; status?: string };
    path_analysis?: number | { duration_seconds?: number; status?: string };
    cloudtrail_correlation?: number | { duration_seconds?: number; status?: string };
    finding_synthesis?: number | { duration_seconds?: number; status?: string };
    total?: number | { duration_seconds?: number; status?: string };
  } | Record<string, any>;
  topRiskyIdentities?: { name: string; type: 'User' | 'Role'; riskScore: number }[];
  resourceBreakdown?: { type: string; count: number }[];
  scannedRegions?: string[];
  scanId?: string;
  scanStatus?: 'NO_SCAN' | 'SCANNING' | 'SUCCESS' | 'FAILED' | 'PARTIAL';
  lastCompletedScanAt?: string | null;
  lastCompletedScanId?: string | null;
  lastSuccessfulScanAt?: string | null;
  lastSuccessfulScanId?: string | null;
  lastError?: string | null;
  serviceStatus?: Record<string, string>;
  failedRegions?: string[];
}

// ─── Policy Catalog ──────────────────────────────────────────────────────────

export interface PolicyFinding {
  code: string;
  points: number;
  reason: string;
}

export interface PolicyCatalogEntry {
  name: string;
  arn: string;
  policyId?: string;
  type: 'customer-managed' | 'aws-managed' | 'inline';
  defaultVersionId?: string;
  attachmentCount: number;
  isAttachable: boolean;
  description?: string;
  createDate?: string;
  updateDate?: string;
  document?: string | null;
  documentParsed?: object | null;
  documentUnavailable?: boolean;
  riskScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  findings: PolicyFinding[];
  attachedTo?: { type: string; name: string; arn: string }[];
}

export interface PaginatedPolicyCatalog {
  items: PolicyCatalogEntry[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

// ─── Simulation ───────────────────────────────────────────────────────────────

export interface SimulationChange {
  change_id: string;
  action: 'ATTACH_POLICY' | 'DETACH_POLICY';
  principal_type: 'USER' | 'GROUP' | 'ROLE';
  principal_id: string;
  policy_arn: string;
  policy_name?: string;
  timestamp?: string;
}

export interface SimulationState {
  simulation_active: boolean;
  pending_changes: number;
  changes: SimulationChange[];
}

// ─── Graph Diff ───────────────────────────────────────────────────────────────

export interface GraphNodeDiff {
  id: string;
  label: string;
  type: string;
}

export interface GraphEdgeDiff {
  source: string;
  target: string;
  label: string;
}

export interface GraphDiff {
  added_nodes: GraphNodeDiff[];
  removed_nodes: GraphNodeDiff[];
  added_edges: GraphEdgeDiff[];
  removed_edges: GraphEdgeDiff[];
  unchanged_node_count: number;
  unchanged_edge_count: number;
}

// ─── Risk Comparison ──────────────────────────────────────────────────────────

export interface RiskComparison {
  current_score: number;
  desired_score: number;
  delta: number;
  current_severity: string;
  desired_severity: string;
  top_reasons: string[];
  simulation_active: boolean;
}

// ─── Attack Path Comparison ───────────────────────────────────────────────────

export interface AttackPathComparison {
  new_paths: AttackPath[];
  removed_paths: AttackPath[];
  unchanged_paths: AttackPath[];
  changed_paths: { current: AttackPath; desired: AttackPath; risk_delta: number }[];
}

// ─── Blast Radius Comparison ──────────────────────────────────────────────────

export interface BlastRadiusComparison {
  current_blast_score: number;
  desired_blast_score: number;
  delta: number;
  current_resource_count: number;
  desired_resource_count: number;
  resources_delta?: number;
  current_identities_count?: number;
  desired_identities_count?: number;
  identities_delta?: number;
  current_sensitive_count?: number;
  desired_sensitive_count?: number;
  sensitive_delta?: number;
  current_critical_count?: number;
  desired_critical_count?: number;
  critical_delta?: number;
  current_resource_types?: Record<string, number>;
  desired_resource_types?: Record<string, number>;
  new_reachable_resources: { id?: string; name?: string; type?: string; riskScore?: number; identity?: string; identity_type?: string; resource_id?: string }[];
  removed_reachable_resources: { id?: string; name?: string; type?: string; riskScore?: number; identity?: string; identity_type?: string; resource_id?: string }[];
}

// ─── Simulation Analysis ──────────────────────────────────────────────────────

export interface SimulationAnalysis {
  simulation_active: boolean;
  pending_changes?: number;
  graph_diff?: GraphDiff;
  desired_elements?: any[];
  risk_comparison?: RiskComparison;
  attack_path_comparison?: AttackPathComparison;
  blast_radius_comparison?: BlastRadiusComparison;
  new_reachable_resources?: { id?: string; name?: string; type?: string; riskScore?: number; identity?: string; identity_type?: string; resource_id?: string }[];
  removed_reachable_resources?: { id?: string; name?: string; type?: string; riskScore?: number; identity?: string; identity_type?: string; resource_id?: string }[];
  summary?: string;
  simulation_note?: string;
}

// ─── Relationships ────────────────────────────────────────────────────────────

export interface RelationshipEntry {
  source_id: string;
  source_label: string;
  source_type: string;
  relationship: string;
  target_id: string;
  target_label: string;
  target_type: string;
  provenance?: string[];
}

export interface RelationshipsResponse {
  total: number;
  relationships: RelationshipEntry[];
  entity_counts: {
    users: number;
    roles: number;
    policies: number;
    groups: number;
    resources: number;
  };
}

// ─── Effective Access ─────────────────────────────────────────────────────────

export interface EffectiveAccess {
  identity_id: string;
  identity_name: string;
  identity_type: string;
  target_resource_id: string;
  target_resource_name: string;
  target_resource_type: string;
  access_path: string[];
  through_relationship: string[];
  policy_names: string[];
  policy_arns: string[];
}

