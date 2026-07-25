import type { SecurityAlert } from '../types';

export const mockAlerts: SecurityAlert[] = [
  {
    id: 'alt-101',
    timestamp: '2026-07-25T09:12:00Z',
    severity: 'critical',
    resource: 'AWSAdminRole',
    description: 'Privilege Escalation: AWSAdminRole was assumed by developer-session from an external host.',
    status: 'open',
    details: 'CloudTrail Event: AssumeRole\nPrincipal: arn:aws:iam::123456789012:user/developer-session\nTarget Role: arn:aws:iam::123456789012:role/AWSAdminRole\nSource IP: 203.0.113.42 (Outside Company Firewall)\nLocation: Moscow, RU\nAction Status: Success'
  },
  {
    id: 'alt-102',
    timestamp: '2026-07-25T08:45:00Z',
    severity: 'high',
    resource: 'S3-Customer-PII-DB',
    description: 'Data Exposure: S3-Customer-PII-DB bucket policy contains unsafe wildcard configuration.',
    status: 'open',
    details: 'CloudTrail Event: PutBucketPolicy\nPrincipal: arn:aws:iam::123456789012:user/ci-cd-runner\nTarget Resource: arn:aws:s3:::s3-customer-pii-db-production\nPolicy Diff:\n- "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::123456789012:root" }\n+ "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"'
  },
  {
    id: 'alt-103',
    timestamp: '2026-07-25T06:18:00Z',
    severity: 'medium',
    resource: 'S3-Public-Assets',
    description: 'Resource Configuration Drift: public access blocked settings disabled.',
    status: 'resolved',
    details: 'Policy check triggered by AWS Config: PublicS3BucketCheck\nResource: s3-marketing-public-assets\nFinding: BlockPublicAccess settings are set to FALSE. Verified public assets namespace.'
  },
  {
    id: 'alt-104',
    timestamp: '2026-07-25T02:30:00Z',
    severity: 'low',
    resource: 'contractor-guest',
    description: 'Unused Credentials: guest user console password has not been rotated for 90+ days.',
    status: 'suppressed',
    details: 'IAM Credential Report Scan\nUser: contractor-guest\nPassword Last Used: 120 days ago\nPassword Creation Date: 2026-03-01\nAction Recommended: Deactivate console login'
  }
];
