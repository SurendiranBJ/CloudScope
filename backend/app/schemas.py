from pydantic import BaseModel
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
    riskScore: int
    mfaEnabled: bool
    lastActive: str

class IAMRole(BaseModel):
    name: str
    arn: str
    trustPolicy: str
    description: str
    activeSessions: int
    riskScore: int

class IAMPolicy(BaseModel):
    name: str
    arn: str
    type: str  # 'custom' | 'aws-managed'
    document: str
    riskScore: int

# Cloud Resource Schemas
class CloudResource(BaseModel):
    name: str
    type: str  # 'User' | 'Role' | 'S3' | 'EC2' | 'Lambda' | 'Secrets' | 'RDS' | 'Policy'
    region: str
    status: str  # 'active' | 'stopped' | 'configured' | 'warning' | 'critical'
    owner: str
    arn: str
    riskScore: int

# Alerts Schema
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
    pathType: Optional[str] = None
    orderedRelationships: Optional[List[str]] = None
    hopCount: Optional[int] = None

class RiskFinding(BaseModel):
    id: str
    identity: str
    identityType: str  # 'User' | 'Role' | 'EC2' | 'Lambda'
    issue: str
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    riskScore: int
    recommendation: str

class CytoscapeElementData(BaseModel):
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
    riskDistribution: List[dict]
    recentAlerts: List[SecurityAlert]
    criticalPaths: List[AttackPath]
    recommendations: List[dict]
    lastScan: Optional[ScanHistoryItem] = None
    topRiskyIdentities: Optional[List[dict]] = None
    resourceBreakdown: Optional[List[dict]] = None
    scannedRegions: Optional[List[str]] = None
    correlatedRisks: Optional[List[CorrelatedRiskFinding]] = None
    serviceStatus: Optional[dict] = None
    scanId: Optional[str] = None
    scanStatus: Optional[str] = "NO_SCAN"
    lastSuccessfulScanAt: Optional[str] = None
    lastSuccessfulScanId: Optional[str] = None
    lastError: Optional[str] = None

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
