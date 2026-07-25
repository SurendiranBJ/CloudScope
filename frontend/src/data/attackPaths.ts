import type { AttackPath } from '../types';

export const mockAttackPaths: AttackPath[] = [
  {
    id: 'path-001',
    name: 'Developer Path to PII S3 Bucket',
    severity: 'critical',
    likelihood: 72,
    blastRadius: 'High (Critical Customer DB Access)',
    mitreTechniques: ['T1078 - Valid Accounts', 'T1548.003 - Abuse Elevation Control Mechanism', 'T1530 - Data from Cloud Storage Object'],
    recommendation: 'Enforce MFA on developer-session user, restrict trust policy of AWSAdminRole to specific session duration limits, and remove full wildcard permissions from InlineS3FullAccess.',
    description: 'A compromised developer user account can assume the AWSAdminRole through sts:AssumeRole permissions and subsequently access the highly sensitive S3-Customer-PII-DB storage bucket containing customer personal data.',
    nodes: [
      { id: 'usr-002', name: 'developer-session', type: 'User' },
      { id: 'pol-004', name: 'AdminAssumeRolePolicy', type: 'Policy' },
      { id: 'rol-002', name: 'AWSAdminRole', type: 'Role' },
      { id: 'res-002', name: 'S3-Customer-PII-DB', type: 'S3' }
    ]
  },
  {
    id: 'path-002',
    name: 'EC2 SSRF to RDS Database Credentials Access',
    severity: 'high',
    likelihood: 58,
    blastRadius: 'Medium (Database Credentials Compromise)',
    mitreTechniques: ['T1190 - Exploit Public-Facing Application', 'T1552 - Unsecured Credentials', 'T1083 - File and Directory Discovery'],
    recommendation: 'Upgrade EC2 to use IMDSv2 instead of IMDSv1 to prevent local server-side request forgery (SSRF), and enforce resource-level IAM policies limiting SecretsReaderRole scope.',
    description: 'An application running on EC2-Prod-AppServer is vulnerable to SSRF, allowing attackers to access the local metadata service, retrieve AWS security credentials for EC2InstanceProfileRole, and call Secrets Manager to read the RDS master credentials.',
    nodes: [
      { id: 'res-001', name: 'EC2-Prod-AppServer', type: 'EC2' },
      { id: 'rol-001', name: 'EC2InstanceProfileRole', type: 'Role' },
      { id: 'rol-004', name: 'SecretsReaderRole', type: 'Role' },
      { id: 'res-004', name: 'Secrets-RDS-MasterCredentials', type: 'Secrets' }
    ]
  },
  {
    id: 'path-003',
    name: 'CI/CD Automation Token Hijack to Infrastructure Admin Access',
    severity: 'critical',
    likelihood: 80,
    blastRadius: 'Full AWS Account takeover',
    mitreTechniques: ['T1078 - Valid Accounts', 'T1082 - System Information Discovery', 'T1199 - Trusted Relationship'],
    recommendation: 'Configure OIDC roles instead of hardcoded credentials for CI/CD, enable continuous IP checking, and alert on logins outside corporate firewall subnets.',
    description: 'The automated ci-cd-runner user contains hardcoded long-lived credentials stored in an external environment. An attacker gains access to the runner workspace, intercepts the credentials, assumes the root AWSAdminRole, and achieves complete control over all cloud services.',
    nodes: [
      { id: 'usr-004', name: 'ci-cd-runner', type: 'User' },
      { id: 'pol-004', name: 'AdminAssumeRolePolicy', type: 'Policy' },
      { id: 'rol-002', name: 'AWSAdminRole', type: 'Role' },
      { id: 'res-001', name: 'EC2-Prod-AppServer', type: 'EC2' }
    ]
  }
];
