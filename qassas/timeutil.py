"""Time helpers. Evidence is stored in UTC and shown in Kuwait time on request.

Kuwait observes Arabia Standard Time, UTC+03:00, all year with no daylight
saving, so a fixed offset is exact for every date this toolkit handles.
"""

from datetime import datetime, timedelta, timezone

UTC = timezone.utc
KUWAIT = timezone(timedelta(hours=3), "AST")

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_FILETIME_EPOCH = _WEBKIT_EPOCH


def iso(dt, tz=UTC):
    """ISO 8601 string in the given zone, seconds precision."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(tz).isoformat(timespec="seconds")


def zone(name):
    """Return the tzinfo for 'utc' or 'kuwait'."""
    key = (name or "utc").lower()
    if key in ("kuwait", "kw", "ast", "asia/kuwait", "+03:00"):
        return KUWAIT
    if key in ("utc", "z", "gmt"):
        return UTC
    raise ValueError("unknown time zone %r, use utc or kuwait" % name)


def from_webkit(microseconds):
    """Chromium stores times as microseconds since 1601-01-01 UTC."""
    if not microseconds:
        return None
    return _WEBKIT_EPOCH + timedelta(microseconds=int(microseconds))


def to_webkit(dt):
    return int((dt - _WEBKIT_EPOCH) / timedelta(microseconds=1))


def from_filetime(value):
    """Windows FILETIME: 100 nanosecond intervals since 1601-01-01 UTC."""
    if not value:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=int(value) // 10)


def to_filetime(dt):
    return int((dt - _FILETIME_EPOCH) / timedelta(microseconds=1)) * 10


def from_unix(seconds):
    if seconds is None:
        return None
    return datetime.fromtimestamp(float(seconds), UTC)


def from_prtime(microseconds):
    """Firefox PRTime: microseconds since 1970-01-01 UTC."""
    if not microseconds:
        return None
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(microseconds))


def parse_iso(text):
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
