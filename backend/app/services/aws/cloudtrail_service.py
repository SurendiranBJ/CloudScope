from app.utils.time import to_utc_iso, utc_now
import logging
import concurrent.futures
import json
import time
from datetime import datetime, timedelta, timezone
from app.services.aws.session import get_aws_session
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")
ALERT_LOOKBACK_DAYS = 7
_SENSITIVE_EVENT_KEYS = {"accesskeyid", "secretaccesskey", "sessiontoken", "token"}


def _is_automated_readonly_assume_role(event: dict) -> bool:
    """Exclude routine AWS service role checks from security alert counts."""
    identity = event.get("userIdentity") or {}
    invoked_by = str(identity.get("invokedBy") or "")
    return (
        event.get("eventName") == "AssumeRole"
        and event.get("readOnly") is True
        and (identity.get("type") == "AWSService" or invoked_by.endswith(".amazonaws.com"))
        and not event.get("errorCode")
    )


def _redact_cloudtrail_payload(value):
    """Remove credential material from nested CloudTrail payloads before persistence."""
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if str(key).lower() in _SENSITIVE_EVENT_KEYS else _redact_cloudtrail_payload(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_cloudtrail_payload(item) for item in value]
    return value


def collect_recent_alerts() -> list:
    alerts = []
    try:
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        event_names = ['AssumeRole', 'PutBucketPolicy', 'CreateUser', 'AttachUserPolicy',
                       'CreateAccessKey', 'PutRolePolicy', 'DeleteBucketPolicy']

        all_events = []
        start_time = time.time()
        lookup_end = datetime.now(timezone.utc)
        lookup_start = lookup_end - timedelta(days=ALERT_LOOKBACK_DAYS)

        def fetch_events_for_region(region_name):
            """Fetch CloudTrail events for all event names in a single region."""
            region_events = []
            try:
                client = region_sessions[region_name].client('cloudtrail', region_name=region_name)

                def fetch_events_for_name(event_name):
                    try:
                        paginator = client.get_paginator('lookup_events')
                        events = []
                        for page in paginator.paginate(
                            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                            StartTime=lookup_start,
                            EndTime=lookup_end,
                            PaginationConfig={'MaxItems': 50, 'PageSize': 20}
                        ):
                            events.extend(page.get('Events', []))
                        return events
                    except Exception as e:
                        logger.debug(f"Failed to lookup CloudTrail events for {event_name} in {region_name}: {e}")
                        return []

                # Parallelize event-name lookups within this region
                with concurrent.futures.ThreadPoolExecutor(max_workers=7) as name_executor:
                    results = name_executor.map(fetch_events_for_name, event_names)
                    for events in results:
                        region_events.extend(events)

            except Exception as e:
                logger.debug(f"Failed to create CloudTrail client for {region_name}: {e}")
            return region_events

        # Parallelize across regions
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for region_events in executor.map(fetch_events_for_region, regions):
                all_events.extend(region_events)

        elapsed = time.time() - start_time
        logger.info(f"CloudTrail collection step completed in {elapsed:.2f}s across {len(regions)} region(s)")

        for event in all_events:
            try:
                raw_payload = event.get("CloudTrailEvent", "{}")
                payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
            except (TypeError, ValueError):
                payload = {}

            if _is_automated_readonly_assume_role(payload):
                continue

            event_id = event['EventId']
            event_time = event.get('EventTime', utc_now())
            username = event.get('Username', 'Unknown')
            name = event.get('EventName', 'ConfigDrift')

            # Map severity based strictly on action semantics — zero name/content heuristics
            severity = 'medium'
            if name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
                severity = 'high'
            elif name in ['AttachUserPolicy', 'PutRolePolicy', 'CreateAccessKey']:
                severity = 'high'
            elif name == 'AssumeRole':
                severity = 'medium'
            elif name == 'CreateUser':
                severity = 'medium'

            res_list = event.get('Resources', [])
            resource_name = res_list[0]['ResourceName'] if res_list else 'AWSResource'

            alerts.append({
                "id": event_id,
                "timestamp": to_utc_iso(event_time) if hasattr(event_time, "isoformat") else str(event_time),
                "severity": severity,
                "resource": resource_name,
                "description": f"CloudTrail Audit Alert: {name} action executed by {username}.",
                "status": "open",
                "details": json.dumps(_redact_cloudtrail_payload(payload), separators=(",", ":"))
            })
        logger.info(f"CloudTrail Collector: Discovered {len(alerts)} alerts")
    except Exception as e:
        logger.error(f"CloudTrail Collector failed to list events: {str(e)}")
    return alerts
