"""FRR log adapter — pulls `docker logs <container>` from the lab and normalizes lines.

FRR daemon log format observed in the network-lab:
    2026/05/03 23:21:06 WATCHFRR: [QDG3Y-BY5TN] zebra state -> up : connect succeeded
    2026/04/30 19:14:38 WATCHFRR: [ZCJ3S-SPH5S] bgpd state -> down : initial connection attempt failed

A few lines are free-form (e.g. "Please, use 'ip ospf passive' on an interface instead.") —
those still get captured as info-level events.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Iterable

from ai_log_analyzer.classifier import LogEvent

# Group 1: timestamp YYYY/MM/DD HH:MM:SS  Group 2: daemon  Group 3: id  Group 4: message
_FRR_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<daemon>[A-Za-z][\w\-.]*?)(?::|\s)\s*"
    r"(?:\[(?P<id>[A-Z0-9\-]+)\]\s*)?"
    r"(?P<msg>.*)$"
)

# Severity hints embedded in FRR messages
_SEV_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(emerg|crit|panic|fatal)\b", re.I), "crit"),
    (re.compile(r"\b(error|err|fail(ed)?|down|denied)\b", re.I), "err"),
    (re.compile(r"\b(warn|warning|degrade)\b", re.I), "warning"),
    (re.compile(r"\b(notice|change)\b", re.I), "notice"),
    (re.compile(r"\b(up|established|connect succeeded)\b", re.I), "info"),
]


def parse_frr_line(line: str, hostname: str = "") -> LogEvent | None:
    """Parse a single docker-logs line into a LogEvent. Returns None for empty/unparseable lines."""
    line = line.rstrip()
    if not line:
        return None

    m = _FRR_LINE_RE.match(line)
    if m:
        ts = _to_iso(m.group("ts"))
        daemon = m.group("daemon").lower()
        msg = m.group("msg").strip()
    else:
        # Free-form line (no timestamp prefix) — keep as info
        ts = ""
        daemon = "frr"
        msg = line.strip()

    severity_raw = "info"
    for pat, sev in _SEV_HINTS:
        if pat.search(msg):
            severity_raw = sev
            break

    return LogEvent(
        timestamp=ts,
        hostname=hostname,
        appname=daemon,
        severity_raw=severity_raw,
        message=msg,
    )


def _to_iso(frr_ts: str) -> str:
    """Convert '2026/05/03 23:21:06' -> '2026-05-03T23:21:06'."""
    date_part, _, time_part = frr_ts.strip().partition(" ")
    return f"{date_part.replace('/', '-')}T{time_part}"


def frr_docker_logs(
    container: str,
    tail: int = 500,
    since: str | None = None,
) -> Iterable[LogEvent]:
    """Yield LogEvents from `docker logs <container>`.

    Args:
        container: Docker container name (e.g. "de-fra-core-01")
        tail: Number of lines from the end of the log
        since: Optional time filter, e.g. "1h", "30m", "2026-05-09T00:00:00"

    Raises:
        FileNotFoundError: docker CLI is not installed.
        subprocess.CalledProcessError: container does not exist or docker daemon is down.
    """
    if not shutil.which("docker"):
        raise FileNotFoundError("docker CLI not found in PATH")

    cmd = ["docker", "logs", "--tail", str(tail)]
    if since:
        cmd.extend(["--since", since])
    cmd.append(container)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    # FRR writes to stderr by default
    raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
    for line in raw.splitlines():
        ev = parse_frr_line(line, hostname=container)
        if ev:
            yield ev


# Docker container names: [a-zA-Z0-9][a-zA-Z0-9_.-]*
# Reject flag-like / empty / non-string values before they reach docker argv.
_DOCKER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def is_docker_name(name: object) -> bool:
    """True if `name` is a well-formed docker container name (not a flag / empty)."""
    return isinstance(name, str) and bool(_DOCKER_NAME_RE.fullmatch(name))


def list_lab_containers(
    prefix_filter: tuple[str, ...] = (
        # POP codes from the bundled FRR lab (de-fra-core-01, uk-lon-edge-01, …).
        # Country-only prefixes (de-, us-) are too broad: they match
        # dev-postgres, demo-db, us-east-cache, user-api on the same host.
        "de-fra-", "uk-lon-", "nl-ams-", "us-nyc-",
    ),
    name_filter: tuple[str, ...] = (
        # Nodes in the bundled containerlab multi-vendor fabric.  Do not use
        # the generic ``clab-`` prefix here: /api/run treats this inventory as
        # the authorization boundary for its docker-exec fallback.
        *(f"clab-clos-evpn-leaf{i}" for i in range(1, 7)),
        *(f"clab-clos-evpn-spine{i}" for i in range(1, 4)),
    ),
) -> list[str]:
    """Return running containers belonging to the bundled labs."""
    if not shutil.which("docker"):
        return []
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, check=True, timeout=10,
        )
    except subprocess.CalledProcessError:
        return []
    names = [n.strip() for n in proc.stdout.splitlines() if n.strip()]
    return sorted(n for n in names if n.startswith(prefix_filter) or n in name_filter)


def is_lab_container(name: str) -> bool:
    """True if `name` is in the running bundled-lab inventory.

    ``list_lab_containers`` is the authorization boundary for docker logs /
    docker exec from the web API. Caller-supplied names must pass this check
    so a request cannot read an unrelated container on the same Docker host.
    """
    if not is_docker_name(name):
        return False
    return name in set(list_lab_containers())


def authorize_lab_containers(requested: list[str] | None) -> tuple[list[str], list[str]]:
    """Split caller-supplied names into (allowed, rejected) against the inventory.

    ``requested`` of None / empty means "use the full running inventory".
    Non-string, empty, or flag-like values are rejected (never coerced).
    """
    inventory = list_lab_containers()
    allow = set(inventory)
    if not requested:
        return inventory, []
    names: list[str] = []
    rejected: list[str] = []
    for c in requested:
        # Exact inventory name only. Do not coerce ints/bools via str() —
        # a non-string must never become an authorized docker target.
        if not isinstance(c, str) or not c or c not in allow:
            rejected.append(c if isinstance(c, str) else repr(c))
        else:
            names.append(c)
    return names, rejected
