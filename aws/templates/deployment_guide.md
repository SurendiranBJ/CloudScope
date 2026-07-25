# AWS Scan Environment Deployment Guide

To deploy the **identityscope-scanner** account profile in your AWS cloud organization:

## 1. Create Scanner IAM User
1. Create a programmatic IAM User named `identityscope-scanner`.
2. Attach the policy document from [read_only_scanner_policy.json](../policies/read_only_scanner_policy.json).
3. Generate Access Keys for this user.

## 2. Configure AWS CLI Profile
Configure the access keys locally on your dashboard host machine:
```bash
aws configure --profile identityscope-scanner
```
Fill in the details:
- **AWS Access Key ID**: `[Your Access Key]`
- **AWS Secret Access Key**: `[Your Secret Access Key]`
- **Default Region**: `ap-south-1`
- **Output Format**: `json`

## 3. Verify Connectivity
Run a test lookup to confirm credentials resolution:
```bash
aws sts get-caller-identity --profile identityscope-scanner
```
This profile will be consumed automatically by the FastAPI `ScanManager` orchestrator on startup.
