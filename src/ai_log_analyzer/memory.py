"""Incident memory — "this exact issue happened before, here's when and where."

Every analysis is ephemeral by default: close the tab and the incident is
gone. With `AI_LOG_ANALYZER_INCIDENT_STORE` set to a path, each analyze run
appends its action items to a local JSONL journal, and future runs annotate
every action item with its recurrence history:

    "recurrence": {"count": 3, "last_seen": "...", "devices": ["leaf-11"]}

That one line changes triage: a first-ever BGP flap and the fourth BGP flap
this month on the same leaf are different incidents, and now they read
differently. A token-overlap search (`find_similar`) additionally powers the
`/api/incidents/similar` endpoint for free-text lookups ("have we seen fan
failures on spine-02?"). Zero dependencies, bounded file size, and nothing
ever leaves the host.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_RECORDS = 5000          # journal is rewritten (oldest dropped) past this
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{2,}")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


class IncidentStore:
    """Append-only JSONL journal of past action items, with recurrence lookup."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict) and rec.get("description"):
                    self._records.append(rec)
        except OSError as exc:
            logger.warning("incident store unreadable (%s) — starting fresh", exc)
        if len(self._records) > _MAX_RECORDS:
            self._records = self._records[-_MAX_RECORDS:]

    def __len__(self) -> int:
        return len(self._records)

    # ── recall ────────────────────────────────────────────────────────────

    def recurrence(self, description: str) -> dict | None:
        """History of this exact issue (KB descriptions are stable strings)."""
        matches = [r for r in self._records if r.get("description") == description]
        if not matches:
            return None
        devices: set[str] = set()
        for r in matches:
            devices.update(r.get("devices") or [])
        return {
            "count": len(matches),
            "last_seen": max(r.get("generated_at", "") for r in matches),
            "devices": sorted(devices)[:10],
        }

    def find_similar(self, query: str, top_n: int = 5) -> list[dict]:
        """Free-text token-overlap search across the journal (Jaccard)."""
        q = _tokens(query)
        if not q:
            return []
        scored: list[tuple[float, dict]] = []
        for r in self._records:
            blob = f"{r.get('description', '')} {' '.join(r.get('devices') or [])} " \
                   f"{' '.join(r.get('sample_messages') or [])}"
            t = _tokens(blob)
            if not t:
                continue
            overlap = len(q & t)
            if overlap == 0:
                continue
            scored.append((overlap / len(q | t), r))
        scored.sort(key=lambda x: -x[0])
        return [
            {"score": round(s, 3), **{k: r.get(k) for k in
             ("description", "severity", "category", "devices", "count", "generated_at")}}
            for s, r in scored[:top_n]
        ]

    # ── record ────────────────────────────────────────────────────────────

    def record(self, action_items: list[dict], generated_at: str) -> int:
        """Append this run's action items; rewrites the journal when it
        outgrows the cap. Failures are logged, never raised."""
        new = []
        for a in action_items:
            new.append({
                "description": a.get("description", ""),
                "severity": a.get("severity", ""),
                "category": a.get("category", ""),
                "devices": (a.get("devices") or [])[:10],
                "count": a.get("count", 0),
                "sample_messages": (a.get("sample_messages") or [])[:2],
                "generated_at": generated_at,
            })
        if not new:
            return 0
        self._records.extend(new)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if len(self._records) > _MAX_RECORDS:
                self._records = self._records[-_MAX_RECORDS:]
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                tmp.write_text(
                    "\n".join(json.dumps(r) for r in self._records) + "\n",
                    encoding="utf-8")
                tmp.replace(self.path)
            else:
                with self.path.open("a", encoding="utf-8") as fh:
                    for r in new:
                        fh.write(json.dumps(r) + "\n")
        except OSError as exc:
            logger.warning("could not persist incident store to %s: %s", self.path, exc)
        return len(new)


def get_store() -> IncidentStore | None:
    """Opt-in via AI_LOG_ANALYZER_INCIDENT_STORE; None when unset."""
    path = os.environ.get("AI_LOG_ANALYZER_INCIDENT_STORE", "")
    return IncidentStore(path) if path else None


def annotate_and_record(result_dict_items: list[dict], generated_at: str) -> None:
    """Stamp each action item with its recurrence history from prior runs,
    then append this run to the journal. No env var → no-op."""
    store = get_store()
    if store is None:
        return
    for a in result_dict_items:
        rec = store.recurrence(a.get("description", ""))
        if rec:
            a["recurrence"] = rec
    store.record(result_dict_items, generated_at)
