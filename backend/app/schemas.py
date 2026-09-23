from pydantic import BaseModel, ConfigDict
from typing import Generic, TypeVar, Optional, List, Dict, Any
from datetime import datetime

T = TypeVar('T')

class APIResponse(BaseModel, Generic[T]):
    success: bool
    message: str
    timestamp: str = datetime.utcnow().isoformat() + "Z"
    data: T

# IAM Schemas matching types/index.ts
class IAMUser(BaseModel):
    id: str
    name: str  # maps to username
    arn: str
    status: str  # 'active' | 'inactive'
    policies: List[str]  # list of policy names
    groups: List[str]
    mfaEnabled: bool
    riskScore: int

class IAMRole(BaseModel):
    id: Optional[str] = ""
    name: str
    arn: str
    trustPolicy: str
    policies: List[str] = []
    riskScore: int

class IAMPolicy(BaseModel):
    name: str
    arn: str
    type: str  # 'custom' | 'aws-managed'
    document: str
    riskScore: int

# Cloud Resources Schemas
class CloudResource(BaseModel):
    id: Optional[str] = ""
    name: str
    type: str  # 'User' | 'Role' | 'S3' | 'EC2' | 'Lambda' | 'Secrets' | 'RDS' | 'Policy' | 'DynamoDB'
    region: str
    status: str
    owner: str
    arn: str
    riskScore: int
    details: Optional[dict] = None

# Alert Schemas
class SecurityAlert(BaseModel):
    id: str
    timestamp: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    resource: str
    description: str
    status: str  # 'open' | 'suppressed' | 'resolved'
    details: str

# Graph / Path Schemas
class AttackPathNode(BaseModel):
    id: str
    name: str
    type: str  # 'User' | 'Role' | 'EC2' | 'S3' | 'Lambda' | 'Secrets' | 'Policy'
    arn: Optional[str] = None
    riskScore: Optional[int] = None

class AttackPath(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    name: str
    nodes: List[AttackPathNode]
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    riskScore: Optional[int] = None
    confidence: Optional[int] = None
    blastRadius: str
    mitreTechniques: List[str]
    recommendation: str
    description: str
    source: Optional[str] = None
    destination: Optional[str] = None
    target: Optional[str] = None
    pathType: Optional[str] = None
    attack_type: Optional[str] = None
    orderedRelationships: Optional[List[str]] = None
    ordered_relationships: Optional[List[str]] = None
    ordered_nodes: Optional[List[AttackPathNode]] = None
    hopCount: Optional[int] = None
    risk_score: Optional[int] = None
    reason: Optional[str] = None
    region: Optional[str] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    privilege_escalation_details: Optional[Dict[str, Any]] = None
    lateral_movement_details: Optional[Dict[str, Any]] = None
    risk_factors: Optional[Dict[str, Any]] = None
    correlation_status: Optional[str] = None
    observed_activity: Optional[List[Dict[str, Any]]] = None

class FindingRemediation(BaseModel):
    title: str
    summary: str
    steps: List[str]
    priority: str = "HIGH"
    references: List[str] = []

class RiskFactorItem(BaseModel):
    code: str
    points: int
    reason: str

class SecurityFinding(BaseModel):
    id: str
    type: str
    category: str
    title: str
    description: str
    severity: str
    riskScore: int
    riskFactors: Optional[List[Dict[str, Any]]] = None
    principal: Optional[str] = None
    principalType: Optional[str] = None
    resource: Optional[str] = None
    resourceType: Optional[str] = None
    region: Optional[str] = None
    policy: Optional[str] = None
    policyArn: Optional[str] = None
    statementSid: Optional[str] = None
    action: Optional[str] = None
    resourceArn: Optional[str] = None
    attackPathId: Optional[str] = None
    eventId: Optional[str] = None
    eventName: Optional[str] = None
    eventTime: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    impact: Optional[str] = None
    remediation: Optional[FindingRemediation] = None
    status: str = "OPEN"
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    updatedAt: Optional[str] = None
    resolvedAt: Optional[str] = None
    source: str
    tags: Optional[List[str]] = None
    # Backward compatibility with RiskFinding
    identity: Optional[str] = None
    identityType: Optional[str] = None
    issue: Optional[str] = None
    recommendation: Optional[str] = None

class RiskFinding(BaseModel):
    id: str
    identity: str
    identityType: str  # 'User' | 'Role' | 'EC2' | 'Lambda'
    issue: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    riskScore: int
    recommendation: str

class CytoscapeElementData(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    label: Optional[str] = None
    type: Optional[str] = None
    source: Optional[str] = None
    target: Optional[str] = None
    riskScore: Optional[int] = None
    arn: Optional[str] = None
    description: Optional[str] = None
    policyType: Optional[str] = None
    # Additional fields for NodeDetailsPanel real-data rendering
    trustPolicy: Optional[str] = None   # Role nodes: raw trust policy JSON string
    policies: Optional[List[str]] = None  # User nodes: list of attached policy names
    # Edge Provenance fields
    edge_type: Optional[str] = None
    provenance_source: Optional[str] = None
    principal: Optional[str] = None
    principal_type: Optional[str] = None
    policy_arn: Optional[str] = None
    policy_name: Optional[str] = None
    statement_sid: Optional[str] = None
    effect: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    resource_arn: Optional[str] = None
    condition_status: Optional[str] = None
    decision: Optional[str] = None
    region: Optional[str] = None
    why: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    isActivity: Optional[bool] = None
    timestamp: Optional[str] = None
    sourceIp: Optional[str] = None
    access_category: Optional[str] = None
    actions: Optional[List[str]] = None
    policy_names: Optional[List[str]] = None

class CytoscapeElement(BaseModel):
    data: CytoscapeElementData

class ScanHistoryItem(BaseModel):
    timestamp: str
    duration_seconds: float
    resources_found: int
    risks_found: int
    graph_nodes_count: int
    graph_edges_count: int
    scanned_regions: Optional[List[str]] = None
    scan_mode: Optional[str] = None
    successful_regions: Optional[List[str]] = None
    failed_regions: Optional[List[str]] = None

class CorrelatedRiskFinding(BaseModel):
    id: str
    type: str  # 'OBSERVED_ATTACK_ACTIVITY' | 'OBSERVED_CONFIG_DRIFT'
    title: str
    actor: str
    actor_node_id: Optional[str] = None
    target: str
    target_node_id: Optional[str] = None
    target_type: Optional[str] = None
    event_name: str
    event_time: str
    source_ip: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    risk_score: int
    matched_static_relationship: str
    reason: str
    recommendation: str
    is_correlated: bool = True

# Dashboard Compilation
class DashboardData(BaseModel):
    securityScore: str
    stats: dict
    activityMetrics: Optional[dict] = None
    riskDistribution: List[dict]
    recentAlerts: List[SecurityAlert]
    criticalPaths: List[AttackPath]
    recommendations: List[dict]
    lastScan: Optional[ScanHistoryItem] = None
    topRiskyIdentities: Optional[List[dict]] = None
    resourceBreakdown: Optional[List[dict]] = None
    scannedRegions: Optional[List[str]] = None
    resolvedRegions: Optional[List[str]] = None
    scanMode: Optional[str] = None
    successfulRegions: Optional[List[str]] = None
    correlatedRisks: Optional[List[CorrelatedRiskFinding]] = None
    serviceStatus: Optional[dict] = None
    failedRegions: Optional[List[str]] = None
    scanId: Optional[str] = None
    scanStatus: Optional[str] = "NO_SCAN"
    lastCompletedScanAt: Optional[str] = None
    lastCompletedScanId: Optional[str] = None
    lastSuccessfulScanAt: Optional[str] = None
    lastSuccessfulScanId: Optional[str] = None
    lastError: Optional[str] = None
    phaseDurations: Optional[dict] = None
    phase_durations: Optional[dict] = None

# Copilot Request/Response
class CopilotRequest(BaseModel):
    prompt: str

class CopilotResponse(BaseModel):
    sender: str
    text: str
    suggestions: List[str]
    type: Optional[str] = None
    codeBlock: Optional[str] = None


# ─── Policy Catalog ─────────────────────────────────────────────────────────

class PolicyFinding(BaseModel):
    code: str
    points: int
    reason: str

class PolicyCatalogEntry(BaseModel):
    name: str
    arn: str
    policyId: Optional[str] = None
    type: str                         # "customer-managed" | "aws-managed" | "inline"
    defaultVersionId: Optional[str] = None
    attachmentCount: int = 0
    isAttachable: bool = True
    description: Optional[str] = None
    createDate: Optional[str] = None
    updateDate: Optional[str] = None
    document: Optional[str] = None   # None until Level-2 fetch
    riskScore: int = 0
    severity: str = "low"
    findings: List[PolicyFinding] = []


class PaginatedPolicyCatalog(BaseModel):
    items: List[PolicyCatalogEntry]
    page: int
    page_size: int
    total: int
    total_pages: int


# ─── Simulation ──────────────────────────────────────────────────────────────

class SimulationChange(BaseModel):
    change_id: str
    action: str                       # "ATTACH_POLICY" | "DETACH_POLICY"
    principal_type: str               # "USER" | "GROUP" | "ROLE"
    principal_id: str                 # username / group name / role name
    policy_arn: str
    policy_name: Optional[str] = None
    timestamp: Optional[str] = None


class SimulationChangeRequest(BaseModel):
    """Request body for POST /simulation/changes."""
    action: str
    principal_type: str
    principal_id: str
    policy_arn: str


class SimulationPreviewRequest(BaseModel):
    """Request body for POST /simulation/preview — does NOT persist the change."""
    action: str
    principal_type: str
    principal_id: str
    policy_arn: str


# ─── Graph Diff ──────────────────────────────────────────────────────────────

class GraphNodeDiff(BaseModel):
    id: str
    label: str
    type: str

class GraphEdgeDiff(BaseModel):
    source: str
    target: str
    label: str

class GraphDiff(BaseModel):
    added_nodes: List[GraphNodeDiff] = []
    removed_nodes: List[GraphNodeDiff] = []
    added_edges: List[GraphEdgeDiff] = []
    removed_edges: List[GraphEdgeDiff] = []
    unchanged_node_count: int = 0
    unchanged_edge_count: int = 0


# ─── Risk Comparison ─────────────────────────────────────────────────────────

class RiskComparison(BaseModel):
    current_score: int
    desired_score: int
    delta: int
    current_severity: str
    desired_severity: str
    top_reasons: List[str] = []
    simulation_active: bool = True


# ─── Attack Path Comparison ──────────────────────────────────────────────────

class AttackPathComparison(BaseModel):
    new_paths: List[dict] = []
    removed_paths: List[dict] = []
    unchanged_paths: List[dict] = []
    changed_paths: List[dict] = []


# ─── Blast Radius Comparison ─────────────────────────────────────────────────

class BlastRadiusComparison(BaseModel):
    current_blast_score: int = 0
    desired_blast_score: int = 0
    delta: int = 0
    current_resource_count: int = 0
    desired_resource_count: int = 0
    resources_delta: int = 0
    current_identities_count: int = 0
    desired_identities_count: int = 0
    identities_delta: int = 0
    current_sensitive_count: int = 0
    desired_sensitive_count: int = 0
    sensitive_delta: int = 0
    current_critical_count: int = 0
    desired_critical_count: int = 0
    critical_delta: int = 0
    current_resource_types: Dict[str, int] = {}
    desired_resource_types: Dict[str, int] = {}
    new_reachable_resources: List[dict] = []
    removed_reachable_resources: List[dict] = []


# ─── Simulation Analysis ─────────────────────────────────────────────────────

class SimulationAnalysis(BaseModel):
    simulation_active: bool = True
    pending_changes: int = 0
    graph_diff: Optional[GraphDiff] = None
    risk_comparison: Optional[RiskComparison] = None
    attack_path_comparison: Optional[AttackPathComparison] = None
    blast_radius_comparison: Optional[BlastRadiusComparison] = None
    new_reachable_resources: List[dict] = []
    removed_reachable_resources: List[dict] = []
    summary: str = ""


# ─── Relationships ───────────────────────────────────────────────────────────

class RelationshipEntry(BaseModel):
    source_id: str
    source_label: str
    source_type: str
    relationship: str                 # Exact backend label e.g. MEMBER_OF
    target_id: str
    target_label: str
    target_type: str
    provenance: Optional[List[str]] = None   # full path chain as labels


class EffectiveAccess(BaseModel):
    identity_id: str
    identity_name: str
    identity_type: str
    target_resource_id: str
    target_resource_name: str
    target_resource_type: str
    access_path: List[str]           # e.g. ["Alice", "Developers", "S3ReadOnly", "S3-A"]
    through_relationship: List[str]  # e.g. ["MEMBER_OF", "HAS_POLICY", "ALLOWS"]
    policy_names: List[str] = []
    policy_arns: List[str] = []
    evidence: Optional[Dict[str, Any]] = None
