import logging
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")


def collect_access_analyzer_findings() -> list:
    findings = []
    try:
        session = get_aws_session()
        client = session.client('accessanalyzer')

        # Discover existing analyzers in region
        analyzers = []
        try:
            analyzers_resp = client.list_analyzers(type='ORGANIZATION')
            analyzers = analyzers_resp.get('analyzers', [])
        except Exception:
            pass

        if not analyzers:
            try:
                analyzers_resp = client.list_analyzers(type='ACCOUNT')
                analyzers = analyzers_resp.get('analyzers', [])
            except Exception:
                pass

        if analyzers:
            analyzer_arn = analyzers[0]['arn']
            paginator = client.get_paginator('list_findings')

            for page in paginator.paginate(analyzerArn=analyzer_arn):
                for f in page.get('findings', []):
                    # We focus on Active findings of public or cross-account access
                    if f['status'] == 'ACTIVE':
                        findings.append({
                            "id": f['id'],
                            "resource": f.get('resource', 'Unknown'),
                            "resourceType": f.get('resourceType', 'Unknown'),
                            "condition": f.get('condition', {}),
                            "isPublic": f.get('isPublic', False),
                            "principal": f.get('principal', {})
                        })
        logger.info(f"Access Analyzer: Discovered {len(findings)} active findings")
    except Exception as e:
        logger.error(f"Access Analyzer Collector failed: {str(e)}")
    return findings
