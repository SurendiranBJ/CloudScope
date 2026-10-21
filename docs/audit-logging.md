# Audit Logging

## Purpose and limits

CloudScope persists operational audit events for selected security-sensitive actions. SQL-backed audit records are durable application records, but they are not tamper-proof or immutable storage. Use a protected external log sink for compliance-grade retention and integrity requirements.

## Event coverage

The audit service records selected actions such as scan triggers, finding lifecycle updates, and simulation operations. Coverage is not claimed for every API read, background job, export, authentication event, or administrative operation; review event creation in code before relying on a complete activity history.

Existing audit records may contain legacy project identifiers. New scans use the AWS credentials configured for the deployment. Access to audit APIs is controlled by backend role dependencies. Verify route permissions for the deployed revision.

## Sanitization

Audit metadata is passed through the application sanitizer to redact common credential formats and sensitive dictionary keys. Sanitization is best effort. Do not place secrets or secret values in notes, tags, or metadata.

## Retention and operations

The AUDIT_RETENTION_DAYS setting defaults to 90 days in application configuration. Confirm the cleanup job, database backup, and external retention policy before relying on a retention guarantee. Protect audit tables, backups, and exported logs with least-privilege access.

Query/API details: inspect the current audit router and OpenAPI schema because filters and access requirements may evolve.
