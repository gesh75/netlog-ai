"""Timestamp → ISO-8601 UTC normalization for the canonical event schema.

Only shapes we can interpret are normalized; anything else returns "" so a
vendor dialect is never mis-dated. Stamps without an offset (RFC 3164,
PAN-OS ``YYYY/MM/DD``, offset-less ISO) are treated as UTC — run devices on
UTC, or the cross-vendor correlation window has to absorb the skew. Callers
get ``assumed_utc=True`` for those so the UI can say so.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache

_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
_SLASH_RE = re.compile(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})$")
_BSD_RE = re.compile(r"^\*?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$")
_EPOCH_RE = re.compile(r"^\d{9,19}$")


def _now() -> datetime:
    """Clock seam for tests (RFC 3164 year inference)."""
    return datetime.now(timezone.utc)


def _offset(text: str | None) -> timezone | None:
    if not text:
        return None
    if text == "Z":
        return timezone.utc
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    try:
        return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))
    except (ValueError, IndexError):
        return None


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_ts(stamp: str, tz: str | None = None) -> tuple[str, bool]:
    """Return (ISO-8601 UTC string or "", assumed_utc).

    Results are cached per (stamp, tz, current hour): syslog bursts repeat
    the same second many times, and RFC 3164 year inference only needs the
    clock to hour precision against its two-day threshold.
    """
    now = _now()
    return _normalize_cached(stamp or "", tz, now.replace(minute=0, second=0, microsecond=0))


@lru_cache(maxsize=8192)
def _normalize_cached(stamp: str, tz: str | None, now: datetime) -> tuple[str, bool]:
    text = stamp.strip()
    if not text:
        return "", False
    try:
        m = _ISO_RE.match(text)
        if m:
            y, mo, d, hh, mi, ss = (int(x) for x in m.groups()[:6])
            off = _offset(m.group(8)) or _offset(tz)
            dt = datetime(y, mo, d, hh, mi, ss, tzinfo=off or timezone.utc)
            return _fmt(dt), off is None
        m = _SLASH_RE.match(text)
        if m:
            y, mo, d, hh, mi, ss = (int(x) for x in m.groups())
            off = _offset(tz)
            return _fmt(datetime(y, mo, d, hh, mi, ss, tzinfo=off or timezone.utc)), off is None
        m = _BSD_RE.match(text)
        if m:
            month = _MONTHS.get(m.group(1).lower())
            if not month:
                return "", False
            day, hh, mi, ss = (int(x) for x in m.groups()[1:])
            off = _offset(tz) or timezone.utc
            dt = datetime(now.year, month, day, hh, mi, ss, tzinfo=off)
            # Yearless stamp from "the future" belongs to last year (Dec → Jan rollover).
            if dt - now > timedelta(days=2):
                dt = dt.replace(year=now.year - 1)
            return _fmt(dt), _offset(tz) is None
        if _EPOCH_RE.match(text):
            n = int(text)
            for scale in (1, 1_000, 1_000_000, 1_000_000_000):
                if n / scale < 4_102_444_800:  # < year 2100
                    return _fmt(datetime.fromtimestamp(n / scale, tz=timezone.utc)), False
    except (ValueError, OverflowError):
        return "", False
    return "", False
