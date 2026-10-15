"""UTC clock helpers with explicit timezone information and ISO-8601 formatting."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current UTC time as an aware datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return a UTC ISO-8601 timestamp using the conventional Z suffix."""
    return utc_now().isoformat().replace("+00:00", "Z")


def to_utc_iso(value: datetime) -> str:
    """Normalize an aware or naive datetime to an unambiguous UTC timestamp."""
    aware_value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return aware_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
