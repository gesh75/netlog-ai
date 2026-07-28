"""TextFSM auto-detection adapter — wraps scottpeterman/tfsm_fire as a fallback parser.

Why this exists
---------------
netlog-ai's primary parsers are hand-written regex (FRR daemon logs, syslog RFC3164/5424)
and vendor-specific paths. Those handle ~80% of what we see in the lab but fall over on:

  * Multi-vendor `show` command output where the platform isn't known up-front
  * Arbitrary device snippets pasted into the analyzer
  * netlog-ai MCP tool calls where the LLM passes raw CLI output without saying which vendor

tfsm_fire scores every TextFSM template in its SQLite DB against the input and returns the
best match. We use it as a strict *fallback* — never the primary path — so regex stays fast
and tfsm only runs when we don't already have a parser for the input.

Upstream status (as of 2026-07-28) — READ THIS FIRST
----------------------------------------------------
`tfsm-fire` has been **withdrawn from PyPI**, and `github.com/scottpeterman/tfsm_fire`
has been deleted. Both return 404; there is no surviving fork, mirror, or renamed
distribution. It installed cleanly as recently as 2026-07-13, so older environments may
still have it — but it can no longer be obtained, and the template-DB URL below is dead
too. The `parse` extra that used to install it was removed in v0.5.1 because it made
`pip install netlog-ai[parse]` and `[all]` unresolvable for everyone.

This module is kept intact and fully functional for anyone who still has a copy of the
package and a copy of the template DB. It is inert (never raises, always returns
no-match) everywhere else.

Soft-dependency
---------------
All public functions return an empty/None result if the package isn't installed — they
never raise. Use `is_available()` to gate UI affordances.

Template DB
-----------
The pip package never shipped the 576KB SQLite template DB — it lived only in the (now
deleted) upstream GitHub repo. The auto-download below therefore fails on a stock setup.
To use this adapter you must supply the DB yourself:

    export TFSM_DB_PATH=/opt/netlog-ai/tfsm_templates.db   # local copy, or
    export TFSM_DB_URL=https://your-mirror.example/tfsm_templates.db

Templates originate from networktocode/ntc-templates, which is still maintained — a
compatible DB can be rebuilt from that source.
"""
from __future__ import annotations

import logging
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Historical URL of the upstream template database. The upstream repo was deleted in
# July 2026, so this default now 404s and _ensure_db() will always fall through to the
# "download failed" path unless you override it. Retained so environments that already
# cached the DB keep working, and so it starts working again if upstream is ever
# restored. Set TFSM_DB_URL to a mirror, or TFSM_DB_PATH to a local copy.
_UPSTREAM_DB_URL = os.environ.get(
    "TFSM_DB_URL",
    "https://github.com/scottpeterman/tfsm_fire/raw/main/tfire/tfsm_templates.db",
)
_DEFAULT_DB_PATH = Path(
    os.environ.get(
        "TFSM_DB_PATH",
        str(Path.home() / ".cache" / "netlog-ai" / "tfsm_templates.db"),
    )
).expanduser()

# Cached engine — tfsm_fire's engine is thread-safe and holds a SQLite connection
# per thread, so a module-level singleton is the cheapest path.
_engine = None
_engine_db_path: Optional[Path] = None


@dataclass(frozen=True)
class ParseResult:
    """Immutable result of an auto-parse attempt.

    `template` is the matched cli_command name (e.g. "cisco_ios_show_lldp_neighbors").
    `score` is on a 0-100 scale from tfsm_fire's heuristic. Treat <40 as low confidence.
    `records` is a list of dicts, one per parsed row. Empty list means no template matched.
    """

    template: Optional[str]
    score: float
    records: list[dict]
    candidates: list[tuple[str, float, int]]  # all non-zero (template, score, record_count)

    @property
    def matched(self) -> bool:
        return self.template is not None and len(self.records) > 0


def is_available() -> bool:
    """Return True if tfsm_fire is importable. Cheap to call repeatedly."""
    try:
        import tfire.tfsm_fire  # noqa: F401
        return True
    except ImportError:
        return False


def _ensure_db(db_path: Path = _DEFAULT_DB_PATH, timeout: float = 30.0) -> Optional[Path]:
    """Ensure the template DB exists locally; download from upstream if missing.

    Returns the path on success, or None if download failed.
    Idempotent — does nothing if the file already exists.
    """
    if db_path.exists() and db_path.stat().st_size > 0:
        return db_path

    db_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading tfsm_fire template DB from %s -> %s", _UPSTREAM_DB_URL, db_path)
    try:
        # urllib is stdlib — we don't pull requests in for this one cold-start call.
        # The URL is a hardcoded constant pointing at a public GitHub raw file, so no
        # SSRF surface: nosec B310 (urllib.urlopen with non-user-controlled URL).
        with urllib.request.urlopen(_UPSTREAM_DB_URL, timeout=timeout) as resp:  # noqa: S310
            data = resp.read()
        if not data:
            logger.warning("tfsm_fire DB download returned empty payload")
            return None
        # Write atomically: write to .tmp then rename, so a crash mid-download doesn't
        # leave a half-written DB that tfsm_fire would then fail to open.
        tmp_path = db_path.with_suffix(db_path.suffix + ".tmp")
        tmp_path.write_bytes(data)
        tmp_path.replace(db_path)
        logger.info("tfsm_fire DB cached at %s (%d bytes)", db_path, len(data))
        return db_path
    except Exception as exc:  # network / filesystem errors are non-fatal — caller falls back
        logger.warning("Failed to download tfsm_fire DB: %s", exc)
        return None


def _get_engine(db_path: Path = _DEFAULT_DB_PATH):
    """Return a cached TextFSMAutoEngine, building it lazily on first call.

    Returns None if tfsm_fire isn't installed or the DB couldn't be obtained.
    """
    global _engine, _engine_db_path

    if not is_available():
        return None

    if _engine is not None and _engine_db_path == db_path:
        return _engine

    resolved = _ensure_db(db_path)
    if resolved is None:
        return None

    from tfire.tfsm_fire import TextFSMAutoEngine
    _engine = TextFSMAutoEngine(str(resolved), verbose=False)
    _engine_db_path = resolved
    return _engine


def auto_parse(
    output: str,
    filter_hint: Optional[str] = None,
    min_score: float = 0.0,
) -> ParseResult:
    """Try every TextFSM template and return the best match.

    Args:
        output: Raw CLI output to parse.
        filter_hint: Optional template-name filter (e.g. "lldp", "bgp", "version") to narrow
            the candidate pool. Maps directly to tfsm_fire's `filter_string`. Faster + safer.
        min_score: Reject matches below this score. Default 0 returns whatever scored best.
            Use ~40 for production filtering of low-confidence matches.

    Returns ParseResult — never raises. `matched` is False on every failure mode
    (missing dependency, empty input, no template matched, score below threshold).
    """
    if not output or not output.strip():
        return ParseResult(template=None, score=0.0, records=[], candidates=[])

    engine = _get_engine()
    if engine is None:
        return ParseResult(template=None, score=0.0, records=[], candidates=[])

    try:
        best_template, parsed, score, all_scores = engine.find_best_template(
            output, filter_string=filter_hint
        )
    except Exception as exc:
        # tfsm_fire's engine swallows per-template parse failures internally, so reaching
        # here means a SQLite / DB-level error. Log and degrade gracefully.
        logger.warning("tfsm_fire engine error: %s", exc)
        return ParseResult(template=None, score=0.0, records=[], candidates=[])

    if score < min_score or not parsed:
        return ParseResult(
            template=None,
            score=float(score or 0.0),
            records=[],
            candidates=list(all_scores or []),
        )

    return ParseResult(
        template=best_template,
        score=float(score),
        records=list(parsed),
        candidates=list(all_scores or []),
    )


def reset_engine_cache() -> None:
    """Drop the cached engine. Primarily for tests that swap the DB path."""
    global _engine, _engine_db_path
    _engine = None
    _engine_db_path = None
