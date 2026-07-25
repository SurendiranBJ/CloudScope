export interface CytoscapeElement {
  data: {
    id: string;
    label?: string;
    type?: 'User' | 'Role' | 'S3' | 'EC2' | 'Lambda' | 'Secrets' | 'RDS' | 'Policy' | 'Edge';
    source?: string;
    target?: string;
    riskScore?: number;
    arn?: string;
    description?: string;
    policyType?: string;
  };
}

export const mockGraphElements: CytoscapeElement[] = [
  // Nodes
  {
    data: {
      id: 'usr-001',
      label: 'admin-sandbox',
      type: 'User',
      riskScore: 12,
      arn: 'arn:aws:iam::123456789012:user/admin-sandbox',
      description: 'System Administrator Account'
    }
  },
  {
    data: {
      id: 'usr-002',
      label: 'developer-session',
      type: 'User',
      riskScore: 78,
      arn: 'arn:aws:iam::123456789012:user/developer-session',
      description: 'Active Developer Local Terminal Session'
    }
  },
  {
    data: {
      id: 'usr-004',
      label: 'ci-cd-runner',
      type: 'User',
      riskScore: 82,
      arn: 'arn:aws:iam::123456789012:user/ci-cd-runner',
      description: 'Automated Jenkins CI/CD Deployment User'
    }
  },
  {
    data: {
      id: 'rol-001',
      label: 'EC2InstanceProfileRole',
      type: 'Role',
      riskScore: 52,
      arn: 'arn:aws:iam::123456789012:role/EC2InstanceProfileRole',
      description: 'EC2 instance operational execution policy'
    }
  },
  {
    data: {
      id: 'rol-002',
      label: 'AWSAdminRole',
      type: 'Role',
      riskScore: 95,
      arn: 'arn:aws:iam::123456789012:role/AWSAdminRole',
      description: 'Break-glass Emergency Administrative Access Role'
    }
  },
  {
    data: {
      id: 'rol-003',
      label: 'LambdaExecutionRole',
      type: 'Role',
      riskScore: 30,
      arn: 'arn:aws:iam::123456789012:role/LambdaExecutionRole',
      description: 'Lambda report aggregation process profile'
    }
  },
  {
    data: {
      id: 'rol-004',
      label: 'SecretsReaderRole',
      type: 'Role',
      riskScore: 68,
      arn: 'arn:aws:iam::123456789012:role/SecretsReaderRole',
      description: 'Permits ECS tasks to read AWS database secrets'
    }
  },
  {
    data: {
      id: 'res-001',
      label: 'EC2-Prod-AppServer',
      type: 'EC2',
      riskScore: 52,
      arn: 'arn:aws:ec2:ap-south-1:123456789012:instance/i-0abcd1234efgh5678',
      description: 'Public Web App Server Instance'
    }
  },
  {
    data: {
      id: 'res-002',
      label: 'S3-Customer-PII-DB',
      type: 'S3',
      riskScore: 94,
      arn: 'arn:aws:s3:::s3-customer-pii-db-production',
      description: 'Encrypted S3 bucket containing customer credentials and profiles'
    }
  },
  {
    data: {
      id: 'res-003',
      label: 'Lambda-ReportGenerator',
      type: 'Lambda',
      riskScore: 30,
      arn: 'arn:aws:lambda:us-east-1:123456789012:function:ReportGenerator',
      description: 'Analyzes user events daily and dumps records'
    }
  },
  {
    data: {
      id: 'res-004',
      label: 'Secrets-RDS-Master',
      type: 'Secrets',
      riskScore: 85,
      arn: 'arn:aws:secretsmanager:ap-south-1:123456789012:secret:production-rds-master-key-xyz',
      description: 'Database Master connection configuration'
    }
  },
  {
    data: {
      id: 'pol-001',
      label: 'AdministratorAccess',
      type: 'Policy',
      riskScore: 99,
      arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      description: 'Provides full access to AWS services and resources.'
    }
  },
  {
    data: {
      id: 'pol-004',
      label: 'AdminAssumeRolePolicy',
      type: 'Policy',
      riskScore: 90,
      arn: 'arn:aws:iam::123456789012:policy/AdminAssumeRolePolicy',
      description: 'Custom policy permitting sts:AssumeRole execution targeting root admin.'
    }
  },

  // Edges / Connections
  // User to Policy
  {
    data: {
      id: 'e-usr001-pol001',
      label: 'HAS_POLICY',
      source: 'usr-001',
      target: 'pol-001',
      type: 'Edge'
    }
  },
  // User to Policy (Assume Role Permission)
  {
    data: {
      id: 'e-usr002-pol004',
      label: 'HAS_POLICY',
      source: 'usr-002',
      target: 'pol-004',
      type: 'Edge'
    }
  },
  {
    data: {
      id: 'e-usr004-pol004',
      label: 'HAS_POLICY',
      source: 'usr-004',
      target: 'pol-004',
      type: 'Edge'
    }
  },
  // Policy to Role (Assumption Target)
  {
    data: {
      id: 'e-pol004-rol002',
      label: 'ASSUME_ROLE',
      source: 'pol-004',
      target: 'rol-002',
      type: 'Edge'
    }
  },
  // Role to S3 Bucket (Access Target)
  {
    data: {
      id: 'e-rol002-res002',
      label: 'CAN_ACCESS',
      source: 'rol-002',
      target: 'res-002',
      type: 'Edge'
    }
  },
  // EC2 Instance Profile Role binding
  {
    data: {
      id: 'e-res001-rol001',
      label: 'ATTACHED_TO',
      source: 'res-001',
      target: 'rol-001',
      type: 'Edge'
    }
  },
  // EC2 Role to Secrets Reader privilege path
  {
    data: {
      id: 'e-rol001-rol004',
      label: 'ASSUME_ROLE',
      source: 'rol-001',
      target: 'rol-004',
      type: 'Edge'
    }
  },
  // Secrets Reader Role access to Secrets
  {
    data: {
      id: 'e-rol004-res004',
      label: 'CAN_ACCESS',
      source: 'rol-004',
      target: 'res-004',
      type: 'Edge'
    }
  },
  // Lambda role binding
  {
    data: {
      id: 'e-res003-rol003',
      label: 'ATTACHED_TO',
      source: 'res-003',
      target: 'rol-003',
      type: 'Edge'
    }
  }
];
