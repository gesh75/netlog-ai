"""Hardened log-line ingestion helpers.

Caps oversized lines/files, decodes with replacement, strips BOM and control
characters, and drops out-of-range timestamps without dropping the event.
No extra runtime dependencies — stdlib only.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

# 64 KiB is enough for any legitimate syslog line; bigger is almost always junk.
_DEFAULT_MAX_LINE_BYTES = 65_536
# 0 = unlimited (CLI streams multi-GB files; the web route has its own cap).
_DEFAULT_MAX_FILE_BYTES = 0

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_BSD_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?:\.\d+)?$"
)
_ISO_TS_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})[T ]"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})"
)
_HMS_TS_RE = re.compile(
    r"^(?P<hh>\d{1,2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?:\.\d+)?$"
)


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def default_max_line_bytes() -> int:
    return _int_env("AI_LOG_ANALYZER_MAX_LINE_BYTES", _DEFAULT_MAX_LINE_BYTES)


def default_max_file_bytes() -> int:
    return _int_env("AI_LOG_ANALYZER_MAX_FILE_BYTES", _DEFAULT_MAX_FILE_BYTES)


def decode_bytes(raw: bytes) -> str:
    """Decode a log fragment. Invalid UTF-8 is replaced, never raised."""
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def sanitize_raw_line(line: str, max_line_bytes: int | None = None) -> str:
    """Strip BOM/control chars and truncate an oversized line.

    Returns an empty string when the line is blank after cleanup (caller skips).
    """
    if not line:
        return ""
    cleaned = line.lstrip("\ufeff").replace("\r", "")
    cleaned = _CONTROL_RE.sub("", cleaned)
    limit = default_max_line_bytes() if max_line_bytes is None else max_line_bytes
    if limit > 0:
        encoded = cleaned.encode("utf-8", errors="replace")
        if len(encoded) > limit:
            cleaned = encoded[:limit].decode("utf-8", errors="ignore")
    return cleaned


def clean_timestamp(ts: str) -> str:
    """Keep a well-formed timestamp; blank an out-of-range one.

    Unknown vendor formats are passed through unchanged so we do not invent a
    parser for every dialect. Only shapes we recognise can be rejected.
    """
    if not ts:
        return ""
    text = ts.strip()
    match = _BSD_TS_RE.match(text)
    if match:
        return text if _in_range(match, day=True) else ""
    match = _ISO_TS_RE.match(text)
    if match:
        month = int(match.group("month"))
        if not 1 <= month <= 12:
            return ""
        # Years 1 and 9999 overflow datetime once a UTC offset or a
        # year-rollover restamp is applied; no real device emits them.
        if not 1 < int(match.group("year")) < 9999:
            return ""
        return text if _in_range(match, day=True) else ""
    match = _HMS_TS_RE.match(text)
    if match:
        return text if _in_range(match, day=False) else ""
    return text


def _in_range(match: re.Match[str], *, day: bool) -> bool:
    if day:
        day_n = int(match.group("day"))
        if not 1 <= day_n <= 31:
            return False
    hh = int(match.group("hh"))
    mm = int(match.group("mm"))
    ss = int(match.group("ss"))
    return 0 <= hh <= 23 and 0 <= mm <= 59 and 0 <= ss <= 60


def iter_sanitized_lines(
    lines: Iterable[str | bytes],
    *,
    max_line_bytes: int | None = None,
) -> Iterator[str]:
    """Yield cleaned text lines, skipping blanks after sanitization."""
    limit = default_max_line_bytes() if max_line_bytes is None else max_line_bytes
    for raw in lines:
        if isinstance(raw, bytes):
            text = decode_bytes(raw)
        else:
            text = raw
        cleaned = sanitize_raw_line(text.rstrip("\n"), max_line_bytes=limit)
        if cleaned.strip():
            yield cleaned


def iter_file_lines(
    path: str | Path,
    *,
    max_line_bytes: int | None = None,
    max_file_bytes: int | None = None,
) -> Iterator[str]:
    """Read a file as binary, decode with replacement, honour size caps."""
    line_limit = default_max_line_bytes() if max_line_bytes is None else max_line_bytes
    file_limit = default_max_file_bytes() if max_file_bytes is None else max_file_bytes
    seen = 0
    with Path(path).open("rb") as handle:
        for raw_line in handle:
            if file_limit > 0 and seen >= file_limit:
                break
            seen += len(raw_line)
            cleaned = sanitize_raw_line(decode_bytes(raw_line).rstrip("\n"), max_line_bytes=line_limit)
            if cleaned.strip():
                yield cleaned
