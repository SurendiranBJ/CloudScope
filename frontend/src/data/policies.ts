import type { IAMPolicy } from '../types';

export const mockPolicies: IAMPolicy[] = [
  {
    name: 'AdministratorAccess',
    arn: 'arn:aws:iam::aws:policy/AdministratorAccess',
    type: 'aws-managed',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}',
    riskScore: 99
  },
  {
    name: 'PowerUserAccess',
    arn: 'arn:aws:iam::aws:policy/PowerUserAccess',
    type: 'aws-managed',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "NotAction": "iam:*",\n      "Resource": "*"\n    }\n  ]\n}',
    riskScore: 75
  },
  {
    name: 'InlineS3FullAccess',
    arn: 'arn:aws:iam::123456789012:policy/InlineS3FullAccess',
    type: 'custom',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "s3:*",\n      "Resource": "*"\n    }\n  ]\n}',
    riskScore: 70
  },
  {
    name: 'AdminAssumeRolePolicy',
    arn: 'arn:aws:iam::123456789012:policy/AdminAssumeRolePolicy',
    type: 'custom',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "sts:AssumeRole",\n      "Resource": "arn:aws:iam::123456789012:role/AWSAdminRole"\n    }\n  ]\n}',
    riskScore: 90
  },
  {
    name: 'CustomEC2DescribePolicy',
    arn: 'arn:aws:iam::123456789012:policy/CustomEC2DescribePolicy',
    type: 'custom',
    document: '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": [\n        "ec2:Describe*",\n        "ec2:List*"\n      ],\n      "Resource": "*"\n    }\n  ]\n}',
    riskScore: 10
  }
];
