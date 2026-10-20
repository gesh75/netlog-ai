"""Generic syslog/file adapter — parse RFC3164 / RFC5424 / freeform log files."""
from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable
from itertools import islice
from pathlib import Path

from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.ingest import (
    iter_file_lines,
    iter_sanitized_lines,
)
from ai_log_analyzer.parsers import registry as _registry
from ai_log_analyzer.parsers.base import JUNOS_RE, RFC3164_RE, RFC5424_RE, SEV_NAMES, pri_to_severity
from ai_log_analyzer.parsers.generic import SCRT_RE

# Envelope regexes now live in the parser registry; re-exported here for
# backward compatibility with code that imported them from this module.
_RFC3164_RE = RFC3164_RE
_RFC5424_RE = RFC5424_RE
_JUNOS_RE = JUNOS_RE
_SCRT_RE = SCRT_RE

# Filename pattern SecureCRT uses: "<hostname> (<ip>) -- YYYY-MM-DD_HH-MM"
_SCRT_FILENAME_RE = re.compile(r"^(?P<host>[A-Za-z0-9][\w.\-]*)\s*\(")

_MAX_DIRECTORY_FILES = 500
_MAX_DIRECTORY_ENTRIES = 10_000


def _validated_file_pattern(pattern: str) -> str:
    """Accept a filename glob, but never a path that can escape the scan root."""
    if not isinstance(pattern, str) or not pattern or pattern in {".", ".."}:
        raise ValueError("directory pattern must be a non-empty filename glob")
    if "/" in pattern or "\\" in pattern or ".." in pattern:
        raise ValueError("directory pattern must not contain path components")
    return pattern


def _matching_files(path: Path, pattern: str, recursive: bool) -> Iterable[Path]:
    pattern = _validated_file_pattern(pattern)
    root = path.resolve()
    pending = [root]
    scanned = 0
    while pending and scanned < _MAX_DIRECTORY_ENTRIES:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                scanned += 1
                if scanned > _MAX_DIRECTORY_ENTRIES:
                    return
                try:
                    if recursive and entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif (entry.is_file(follow_symlinks=False)
                          and fnmatch.fnmatchcase(entry.name, pattern)):
                        yield Path(entry.path)
                except OSError:
                    continue


def parse_lines(
    lines: Iterable[str | bytes],
    default_host: str = "",
    max_line_bytes: int | None = None,
) -> Iterable[LogEvent]:
    """Parse any iterable of log lines, picking the first format that matches.

    Lines are sanitized first (encoding replacement, control-char strip,
    oversized-line cap) so a hostile or corrupt feed cannot blow up parsing.
    """
    for line in iter_sanitized_lines(lines, max_line_bytes=max_line_bytes):
        ev = _parse_line(line, default_host)
        if ev:
            yield ev


def parse_file(
    path: str | Path,
    default_host: str = "",
    max_line_bytes: int | None = None,
    max_file_bytes: int | None = None,
) -> Iterable[LogEvent]:
    p = Path(path)
    # If the caller didn't pass a host, derive one. For SecureCRT recordings
    # the filename is `hostname (ip) -- YYYY-MM-DD_HH-MM.log` — extract just
    # the hostname so devices group together in the dashboard.
    if not default_host:
        scrt = _SCRT_FILENAME_RE.match(p.stem)
        default_host = scrt.group("host") if scrt else p.stem
    for line in iter_file_lines(
        p, max_line_bytes=max_line_bytes, max_file_bytes=max_file_bytes,
    ):
        ev = _parse_line(line, default_host)
        if ev:
            yield ev


def parse_directory(path: str | Path, pattern: str = "*.log",
                    recursive: bool = True,
                    max_files: int = _MAX_DIRECTORY_FILES) -> Iterable[LogEvent]:
    """Parse every file in a directory matching `pattern` and yield all events
    in chronological-ish order (by filename sort, then by file order).

    Each file is parsed via `parse_file`, which means each file's events get
    their hostname extracted from the filename (so SCRT logs across many
    sessions on the same device naturally group together).

    `max_files` is a safety cap to prevent accidental analysis of a 100K-file
    directory. It cannot be disabled: non-positive values use the default cap.
    """
    p = Path(path)
    if not p.is_dir():
        raise ValueError(f"{p} is not a directory")
    limit = max_files if max_files > 0 else _MAX_DIRECTORY_FILES
    # Apply the cap while iterating. Do not materialize and sort an attacker-
    # controlled number of matches before truncating the result.
    files = sorted(islice(_matching_files(p, pattern, recursive), limit))
    for f in files:
        yield from parse_file(f)


def count_directory_files(path: str | Path, pattern: str = "*.log",
                          recursive: bool = True,
                          max_files: int = _MAX_DIRECTORY_FILES) -> int:
    """Return a bounded count of files that ``parse_directory`` can ingest."""
    p = Path(path)
    if not p.is_dir():
        return 0
    limit = max_files if max_files > 0 else _MAX_DIRECTORY_FILES
    return sum(1 for _ in islice(_matching_files(p, pattern, recursive), limit))


def _parse_line(line: str, default_host: str) -> LogEvent | None:
    """Parse one line through the parser plugin registry.

    Vendor plugins (FortiOS kv, PAN-OS CSV, Cisco SD-WAN) claim their own
    formats; the generic syslog plugin keeps the legacy RFC 5424 / RFC 3164 /
    Junos field semantics and adds structured entity fields.
    """
    return _registry.parse(line, default_host)


# Syslog priority → severity-text mapping (kept for backward compatibility)
_SEV_NAMES = SEV_NAMES


def _pri_to_severity(pri: int) -> str:
    return pri_to_severity(pri)
