from pydantic import BaseModel
from typing import Generic, TypeVar, Optional, List
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

class AttackPath(BaseModel):
    id: str
    name: str
    nodes: List[AttackPathNode]
    severity: str  # 'critical' | 'high' | 'medium' | 'low'
    likelihood: int  # percentage
    blastRadius: str
    mitreTechniques: List[str]
    recommendation: str
    description: str

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

# Copilot Request/Response
class CopilotRequest(BaseModel):
    prompt: str

class CopilotResponse(BaseModel):
    sender: str
    text: str
    type: Optional[str] = None
    codeBlock: Optional[str] = None
