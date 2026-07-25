# Identity Security Least Privilege Guidelines

To reduce the threat footprint and blast radius across cloud configurations:

## 1. Eliminate Wildcard Actions (`*`)
*   Avoid using statements like `"Action": "s3:*"` or `"Resource": "*"`.
*   Scope statements specifically to the exact actions needed (e.g. `s3:GetObject`).

## 2. Enforce MFA Conditions on sts:AssumeRole
*   Add a conditional check validating that the session has been authorized with MFA:
    ```json
    "Condition": {
      "Bool": { "aws:MultiFactorAuthPresent": "true" }
    }
    ```

## 3. Rotate Credentials Regularly
*   Enforce key age checks. Rotate any permanent access keys older than 90 days.
