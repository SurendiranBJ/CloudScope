import type { IAMRole } from '../types';

export const mockRoles: IAMRole[] = [
  {
    name: 'EC2InstanceProfileRole',
    arn: 'arn:aws:iam::123456789012:role/EC2InstanceProfileRole',
    trustPolicy: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "Service": "ec2.amazonaws.com"\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}',
    description: 'Allows EC2 instances to call AWS services on your behalf, currently mapped to S3 read privileges.',
    activeSessions: 12,
    riskScore: 52
  },
  {
    name: 'AWSAdminRole',
    arn: 'arn:aws:iam::123456789012:role/AWSAdminRole',
    trustPolicy: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "AWS": [\n          "arn:aws:iam::123456789012:user/developer-session",\n          "arn:aws:iam::123456789012:user/ci-cd-runner"\n        ]\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}',
    description: 'Emergency break-glass role with broad administrative privileges. High security risk exposure.',
    activeSessions: 1,
    riskScore: 95
  },
  {
    name: 'LambdaExecutionRole',
    arn: 'arn:aws:iam::123456789012:role/LambdaExecutionRole',
    trustPolicy: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "Service": "lambda.amazonaws.com"\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}',
    description: 'Standard execution permission role for analytical processing microservices.',
    activeSessions: 4,
    riskScore: 30
  },
  {
    name: 'SecretsReaderRole',
    arn: 'arn:aws:iam::123456789012:role/SecretsReaderRole',
    trustPolicy: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Principal": {\n        "Service": "ecs-tasks.amazonaws.com"\n      },\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}',
    description: 'Permits ECS container tasks to read database configuration secrets from AWS Secrets Manager.',
    activeSessions: 8,
    riskScore: 68
  }
];
