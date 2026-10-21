import concurrent.futures
import logging
import time

from botocore.config import Config

from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")
ACCESS_ANALYZER_CONFIG = Config(
    connect_timeout=2,
    read_timeout=5,
    retries={"total_max_attempts": 1},
)


def collect_access_analyzer_findings() -> list:
    """Collect active Access Analyzer findings with bounded regional latency."""
    started_at = time.perf_counter()
    try:
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def list_analyzers(region_name, analyzer_type):
            try:
                client = region_sessions[region_name].client(
                    "accessanalyzer",
                    region_name=region_name,
                    config=ACCESS_ANALYZER_CONFIG,
                )
                analyzers = client.list_analyzers(type=analyzer_type).get("analyzers", [])
                return region_name, analyzer_type, analyzers, None
            except Exception as exc:
                return region_name, analyzer_type, [], exc

        # Check account and organization analyzers at the same time. A sequential
        # fallback made every region pay for two network round trips.
        analyzer_map = {region: {"ORGANIZATION": [], "ACCOUNT": []} for region in regions}
        with concurrent.futures.ThreadPoolExecutor(max_workers=18) as executor:
            futures = [
                executor.submit(list_analyzers, region, analyzer_type)
                for region in regions
                for analyzer_type in ("ORGANIZATION", "ACCOUNT")
            ]
            for future in concurrent.futures.as_completed(futures):
                region, analyzer_type, analyzers, error = future.result()
                analyzer_map[region][analyzer_type] = analyzers
                if error:
                    logger.debug("Access Analyzer %s listing failed in %s: %s", analyzer_type, region, error)

        selected_analyzers = []
        for region in regions:
            analyzers = analyzer_map[region]["ORGANIZATION"] or analyzer_map[region]["ACCOUNT"]
            if analyzers:
                selected_analyzers.append((region, analyzers[0]["arn"]))

        def collect_region_findings(region_name, analyzer_arn):
            try:
                client = region_sessions[region_name].client(
                    "accessanalyzer",
                    region_name=region_name,
                    config=ACCESS_ANALYZER_CONFIG,
                )
                region_findings = []
                paginator = client.get_paginator("list_findings")
                for page in paginator.paginate(analyzerArn=analyzer_arn):
                    for finding in page.get("findings", []):
                        if finding.get("status") == "ACTIVE":
                            region_findings.append({
                                "id": finding["id"],
                                "resource": finding.get("resource", "Unknown"),
                                "resourceType": finding.get("resourceType", "Unknown"),
                                "condition": finding.get("condition", {}),
                                "isPublic": finding.get("isPublic", False),
                                "principal": finding.get("principal", {}),
                                "region": region_name,
                            })
                return region_findings, None
            except Exception as exc:
                return [], exc

        findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=18) as executor:
            futures = {
                executor.submit(collect_region_findings, region, arn): region
                for region, arn in selected_analyzers
            }
            for future in concurrent.futures.as_completed(futures):
                region_findings, error = future.result()
                findings.extend(region_findings)
                if error:
                    logger.debug("Access Analyzer findings listing failed in %s: %s", futures[future], error)

        logger.info(
            "Access Analyzer completed in %.2fs: %d active findings across %d region(s) (%d analyzer(s))",
            time.perf_counter() - started_at,
            len(findings),
            len(regions),
            len(selected_analyzers),
        )
        return findings
    except Exception as exc:
        logger.error("Access Analyzer Collector failed: %s", exc)
        return []
