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
  type: 'User' | 'Role' | 'EC2' | 'S3' | 'Lambda' | 'Secrets' | 'Policy';
}

export interface AttackPath {
  id: string;
  name: string;
  nodes: AttackPathNode[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  likelihood: number; // percentage
  blastRadius: string;
  mitreTechniques: string[];
  recommendation: string;
  description: string;
}

export interface RiskFinding {
  id: string;
  identity: string;
  identityType: 'User' | 'Role' | 'EC2' | 'Lambda';
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  riskScore: number;
  recommendation: string;
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
  };
  topRiskyIdentities?: { name: string; type: 'User' | 'Role'; riskScore: number }[];
  resourceBreakdown?: { type: string; count: number }[];
}
