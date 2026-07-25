import type { RiskFinding } from '../types';

export const mockRisks: RiskFinding[] = [
  {
    id: 'risk-001',
    identity: 'developer-session',
    identityType: 'User',
    issue: 'MFA is deactivated for this user while possessing AssumeRole permissions to administrative accounts.',
    severity: 'critical',
    riskScore: 78,
    recommendation: 'Enable Multi-Factor Authentication (MFA) immediately via virtual app or physical security key.'
  },
  {
    id: 'risk-002',
    identity: 'AWSAdminRole',
    identityType: 'Role',
    issue: 'Trust policy permits assumption by local runner users without additional condition checking.',
    severity: 'critical',
    riskScore: 95,
    recommendation: 'Apply IAM Conditions requiring MFA and specific source IP ranges to assume this role.'
  },
  {
    id: 'risk-003',
    identity: 'EC2-Prod-AppServer',
    identityType: 'EC2',
    issue: 'Attached IAM instance profile role allows full write access to all marketing and media S3 buckets.',
    severity: 'high',
    riskScore: 52,
    recommendation: 'Apply least-privilege scoping to the EC2InstanceProfileRole, limiting actions to s3:PutObject on specific asset sub-paths.'
  },
  {
    id: 'risk-004',
    identity: 'ci-cd-runner',
    identityType: 'User',
    issue: 'User possesses full administrative roles access keys that have not been rotated in 180+ days.',
    severity: 'high',
    riskScore: 82,
    recommendation: 'Rotate IAM Access Keys and migrate the pipeline runner to use AWS IAM Identity Center OpenID Connect.'
  },
  {
    id: 'risk-005',
    identity: 'SecretsReaderRole',
    identityType: 'Role',
    issue: 'Role permits description of secret contents for all development and production master secrets.',
    severity: 'medium',
    riskScore: 68,
    recommendation: 'Add KMS decryption resource tags constraint, allowing decryption only for specific tags.'
  }
];
