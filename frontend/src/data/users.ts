import type { IAMUser } from '../types';

export const mockUsers: IAMUser[] = [
  {
    id: 'usr-001',
    name: 'admin-sandbox',
    arn: 'arn:aws:iam::123456789012:user/admin-sandbox',
    status: 'active',
    policies: ['AdministratorAccess', 'SystemAdministrator'],
    groups: ['Admins'],
    riskScore: 12,
    mfaEnabled: true,
    lastActive: '10 minutes ago'
  },
  {
    id: 'usr-002',
    name: 'developer-session',
    arn: 'arn:aws:iam::123456789012:user/developer-session',
    status: 'active',
    policies: ['PowerUserAccess', 'InlineS3FullAccess'],
    groups: ['Developers'],
    riskScore: 78,
    mfaEnabled: false,
    lastActive: '2 hours ago'
  },
  {
    id: 'usr-003',
    name: 'analyst-temp',
    arn: 'arn:aws:iam::123456789012:user/analyst-temp',
    status: 'active',
    policies: ['ReadOnlyAccess', 'SecurityAudit'],
    groups: ['AuditTeam'],
    riskScore: 45,
    mfaEnabled: true,
    lastActive: '1 day ago'
  },
  {
    id: 'usr-004',
    name: 'ci-cd-runner',
    arn: 'arn:aws:iam::123456789012:user/ci-cd-runner',
    status: 'active',
    policies: ['AdminAssumeRolePolicy', 'AmazonS3FullAccess'],
    groups: ['Automations'],
    riskScore: 82,
    mfaEnabled: false,
    lastActive: '5 minutes ago'
  },
  {
    id: 'usr-005',
    name: 'contractor-guest',
    arn: 'arn:aws:iam::123456789012:user/contractor-guest',
    status: 'inactive',
    policies: ['CustomEC2DescribePolicy'],
    groups: ['ExternalGuests'],
    riskScore: 60,
    mfaEnabled: true,
    lastActive: '3 days ago'
  }
];
