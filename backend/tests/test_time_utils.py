import re
from datetime import datetime, timedelta, timezone

from app.schemas import APIResponse
from app.utils.time import to_utc_iso, utc_now_iso


def test_utc_now_iso_has_a_timezone_marker():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z", utc_now_iso())


def test_api_response_default_timestamp_is_created_per_instance():
    first = APIResponse[dict](success=True, message="first", data={})
    second = APIResponse[dict](success=True, message="second", data={})

    assert first.timestamp.endswith("Z")
    assert second.timestamp.endswith("Z")
    assert first.timestamp != second.timestamp


def test_to_utc_iso_normalizes_aware_datetimes_without_duplicate_timezone_suffix():
    value = datetime(2026, 10, 15, 12, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))

    assert to_utc_iso(value) == "2026-10-15T07:00:00Z"
