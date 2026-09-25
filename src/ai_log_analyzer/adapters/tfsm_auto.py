"""TextFSM auto-detection adapter — scores ntc-templates and returns the best match.

Why this exists
---------------
netlog-ai's primary parsers are hand-written regex (FRR daemon logs, syslog RFC3164/5424)
and vendor-specific paths. Those handle the lab but fall over on:

  * Multi-vendor ``show`` command output where the platform isn't known up-front
  * Arbitrary device snippets pasted into the analyzer
  * MCP tool calls where the LLM passes raw CLI output without naming the vendor

This module is a strict *fallback*. It tries every TextFSM template whose name matches
an optional hint, scores the parses, and returns the best one. It never raises.

Install the optional extra to turn it on::

    pip install netlog-ai[parse]

That pulls ``textfsm`` and ``ntc-templates``. Without them, ``is_available()`` is false
and ``auto_parse()`` returns an unmatched result.

``textfsm`` and ``ntc_templates`` are imported inside the functions that need them.
They are an optional extra, so importing this module must succeed when they are absent.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Cached index. ``_engine_db_path`` is the on-disk templates directory the index
# was loaded from, so a later call with a different directory rebuilds it.
_engine: _TemplateIndex | None = None
_engine_db_path: Path | None = None


@dataclass(frozen=True)
class ParseResult:
    """Immutable result of an auto-parse attempt.

    ``template`` is the matched template stem (e.g. "cisco_ios_show_lldp_neighbors").
    ``score`` is on a 0-100 scale. Treat <40 as low confidence.
    ``records`` is a list of dicts, one per parsed row. Empty list means no template matched.
    """

    template: str | None
    score: float
    records: list[dict]
    candidates: list[tuple[str, float, int]]  # all non-zero (template, score, record_count)

    @property
    def matched(self) -> bool:
        return self.template is not None and len(self.records) > 0


def is_available() -> bool:
    """Return True if textfsm and ntc-templates are importable."""
    try:
        import ntc_templates  # noqa: F401
        import textfsm  # noqa: F401
    except ImportError:
        return False
    return True


def _templates_dir() -> Path | None:
    """Return the installed ntc-templates directory, or None when it is missing."""
    try:
        import ntc_templates
    except ImportError:
        return None
    root = Path(ntc_templates.__file__).resolve().parent / "templates"
    if (root / "index").is_file():
        return root
    logger.warning("ntc-templates index missing at %s", root)
    return None


def _template_names(index_path: Path) -> tuple[str, ...]:
    """Template filenames from an ntc-templates index file.

    Each data line is ``filename.textfsm, command, platform``. The command
    column can contain commas, so only the first field is the filename.
    """
    names: list[str] = []
    for raw in index_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        filename = line.split(",", 1)[0].strip()
        if filename.endswith(".textfsm"):
            names.append(filename)
    return tuple(names)


def _filled(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(_filled(item) for item in value)
    return bool(str(value).strip())


def _token_coverage(records: list[dict], output: str) -> float:
    """Share of input tokens that show up in the parsed records.

    A template that lifts a few words out of prose looks fully populated and
    would otherwise score like a real table. Coverage pulls that back down.
    """
    source = set(re.findall(r"\S+", output.lower()))
    if not source:
        return 0.0
    captured: set[str] = set()
    for row in records:
        for value in row.values():
            captured.update(re.findall(r"\S+", str(value).lower()))
    return len(captured & source) / len(source)


def _calculate_template_score(records: list[dict], output: str) -> float:
    """Score a parse on a 0-100 scale.

    Rewards record count, field richness, how many cells are populated, and
    whether each field is consistently filled or consistently empty across rows.
    The result is scaled by how much of the input the records account for.
    """
    if not records:
        return 0.0
    fields = list(records[0].keys())
    if not fields:
        return 0.0

    row_count = len(records)
    fill_rates: list[float] = []
    populated = 0
    for field in fields:
        filled = sum(1 for row in records if _filled(row.get(field)))
        populated += filled
        fill_rates.append(filled / row_count)

    population = populated / (row_count * len(fields))
    richness = min(len(fields), 8) / 8
    consistency = sum(1 for rate in fill_rates if rate >= 0.8 or rate == 0.0) / len(fill_rates)
    volume = min(row_count, 5) / 5
    base = 100.0 * (0.45 * population + 0.20 * richness + 0.20 * consistency + 0.15 * volume)
    coverage = _token_coverage(records, output)
    # A one-row grab of a few words looks fully populated. Squaring coverage
    # on a single record drops that under the usual min_score of 40. Multi-row
    # tables keep a linear penalty so header lines do not wipe out the score.
    if row_count == 1:
        coverage *= coverage
    return round(base * coverage, 4)


def _parse_template(template_path: Path, output: str) -> list[dict]:
    """Run one TextFSM template. A bad template or a non-match returns []."""
    import textfsm

    try:
        with template_path.open(encoding="utf-8") as handle:
            fsm = textfsm.TextFSM(handle)
        rows = fsm.ParseText(output)
    except Exception:
        logger.debug("template %s did not match", template_path.name, exc_info=True)
        return []
    return [dict(zip(fsm.header, row, strict=False)) for row in rows]


class _TemplateIndex:
    """In-memory list of ntc-templates filenames. Parsing happens per call."""

    def __init__(self, templates_dir: Path) -> None:
        self.templates_dir = templates_dir
        self.names = _template_names(templates_dir / "index")

    def find_best_template(
        self,
        output: str,
        filter_string: str | None = None,
    ) -> tuple[str | None, list[dict], float, list[tuple[str, float, int]]]:
        hint = (filter_string or "").lower()
        scored: list[tuple[str, float, list[dict]]] = []
        for filename in self.names:
            stem = filename[: -len(".textfsm")]
            if hint and hint not in stem.lower():
                continue
            records = _parse_template(self.templates_dir / filename, output)
            score = _calculate_template_score(records, output)
            if score <= 0 or not records:
                continue
            scored.append((stem, score, records))

        if not scored:
            return None, [], 0.0, []

        scored.sort(key=lambda item: (item[1], len(item[2])), reverse=True)
        best_name, best_score, best_records = scored[0]
        candidates = [(name, score, len(records)) for name, score, records in scored]
        return best_name, best_records, best_score, candidates


def _get_engine() -> _TemplateIndex | None:
    """Return a cached template index, or None when the extra is not installed."""
    global _engine, _engine_db_path

    if not is_available():
        return None

    templates_dir = _templates_dir()
    if templates_dir is None:
        return None

    if _engine is not None and _engine_db_path == templates_dir:
        return _engine

    _engine = _TemplateIndex(templates_dir)
    _engine_db_path = templates_dir
    return _engine


def auto_parse(
    output: str,
    filter_hint: str | None = None,
    min_score: float = 0.0,
) -> ParseResult:
    """Try TextFSM templates and return the best match.

    Args:
        output: Raw CLI output to parse.
        filter_hint: Optional template-name substring (e.g. "lldp", "bgp", "version").
            Narrows the candidate pool. Much faster than a full scan.
        min_score: Reject matches below this score. Default 0 returns whatever scored best.
            Use ~40 for production filtering of low-confidence matches.

    Returns ParseResult — never raises. ``matched`` is False on every failure mode
    (missing extra, empty input, no template matched, score below threshold).
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
        logger.warning("auto-parse failed: %s", exc)
        return ParseResult(template=None, score=0.0, records=[], candidates=[])

    if best_template is None or score < min_score or not parsed:
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
    """Drop the cached template index. Primarily for tests."""
    global _engine, _engine_db_path
    _engine = None
    _engine_db_path = None
