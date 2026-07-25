import type { CloudResource } from '../types';

export const mockResources: CloudResource[] = [
  {
    name: 'EC2-Prod-AppServer',
    type: 'EC2',
    region: 'ap-south-1',
    status: 'active',
    owner: 'OpsTeam',
    arn: 'arn:aws:ec2:ap-south-1:123456789012:instance/i-0abcd1234efgh5678',
    riskScore: 52
  },
  {
    name: 'S3-Customer-PII-DB',
    type: 'S3',
    region: 'ap-south-1',
    status: 'critical',
    owner: 'SecurityTeam',
    arn: 'arn:aws:s3:::s3-customer-pii-db-production',
    riskScore: 94
  },
  {
    name: 'Lambda-ReportGenerator',
    type: 'Lambda',
    region: 'us-east-1',
    status: 'active',
    owner: 'DevTeam-Alpha',
    arn: 'arn:aws:lambda:us-east-1:123456789012:function:ReportGenerator',
    riskScore: 30
  },
  {
    name: 'Secrets-RDS-MasterCredentials',
    type: 'Secrets',
    region: 'ap-south-1',
    status: 'warning',
    owner: 'DB-Admins',
    arn: 'arn:aws:secretsmanager:ap-south-1:123456789012:secret:production-rds-master-key-xyz',
    riskScore: 85
  },
  {
    name: 'RDS-User-Metadata',
    type: 'RDS',
    region: 'ap-south-1',
    status: 'active',
    owner: 'DB-Admins',
    arn: 'arn:aws:rds:ap-south-1:123456789012:db:user-metadata-replica',
    riskScore: 40
  },
  {
    name: 'S3-Public-Assets',
    type: 'S3',
    region: 'eu-west-1',
    status: 'warning',
    owner: 'MarketingTeam',
    arn: 'arn:aws:s3:::s3-marketing-public-assets',
    riskScore: 65
  },
  {
    name: 'EC2-Staging-Compiler',
    type: 'EC2',
    region: 'us-east-1',
    status: 'stopped',
    owner: 'DevTeam-Beta',
    arn: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0987654321fedcba0',
    riskScore: 15
  }
];
