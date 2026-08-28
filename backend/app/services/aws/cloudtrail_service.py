import logging
import concurrent.futures
import time
from datetime import datetime
from app.services.aws.session import get_aws_session
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")


def collect_recent_alerts() -> list:
    alerts = []
    try:
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        event_names = ['AssumeRole', 'PutBucketPolicy', 'CreateUser', 'AttachUserPolicy',
                       'CreateAccessKey', 'PutRolePolicy', 'DeleteBucketPolicy']

        all_events = []
        start_time = time.time()

        def fetch_events_for_region(region_name):
            """Fetch CloudTrail events for all event names in a single region."""
            region_events = []
            try:
                client = region_sessions[region_name].client('cloudtrail', region_name=region_name)

                def fetch_events_for_name(event_name):
                    try:
                        response = client.lookup_events(
                            LookupAttributes=[
                                {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                            ],
                            MaxResults=5
                        )
                        return response.get('Events', [])
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
            event_id = event['EventId']
            event_time = event.get('EventTime', datetime.utcnow())
            username = event.get('Username', 'Unknown')
            name = event.get('EventName', 'ConfigDrift')

            # Map severity based on event type
            severity = 'medium'
            if name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
                severity = 'high'
            elif name in ['AttachUserPolicy', 'PutRolePolicy', 'CreateAccessKey']:
                severity = 'high'
            elif name == 'AssumeRole' and 'Admin' in event.get('CloudTrailEvent', ''):
                severity = 'critical'
            elif name == 'CreateUser':
                severity = 'medium'

            res_list = event.get('Resources', [])
            resource_name = res_list[0]['ResourceName'] if res_list else 'AWSResource'

            alerts.append({
                "id": event_id,
                "timestamp": event_time.isoformat() + "Z" if hasattr(event_time, 'isoformat') else str(event_time),
                "severity": severity,
                "resource": resource_name,
                "description": f"CloudTrail Audit Alert: {name} action executed by {username}.",
                "status": "open",
                "details": event.get('CloudTrailEvent', '{}')
            })
        logger.info(f"CloudTrail Collector: Discovered {len(alerts)} alerts")
    except Exception as e:
        logger.error(f"CloudTrail Collector failed to list events: {str(e)}")
    return alerts
