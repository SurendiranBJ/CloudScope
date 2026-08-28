import logging
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")


def collect_access_analyzer_findings() -> list:
    findings = []
    try:
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        for region_name in regions:
            try:
                client = region_sessions[region_name].client('accessanalyzer', region_name=region_name)

                # Discover existing analyzers in this region
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
            except Exception as e:
                logger.debug(f"Access Analyzer collection failed for {region_name}: {e}")

        logger.info(f"Access Analyzer: Discovered {len(findings)} active findings across {len(regions)} region(s)")
    except Exception as e:
        logger.error(f"Access Analyzer Collector failed: {str(e)}")
    return findings
