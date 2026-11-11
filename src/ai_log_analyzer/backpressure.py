"""Syslog backpressure signalling (P3 item 13).

The kernel drops UDP datagrams when the listener cannot keep up, and the
spool writer drops lines when its queue is full. Both are counted in the
listener (``sources/syslog.py``) but were only visible in that process's
memory. This module turns the counters into shared, durable state:

* ``publish`` persists the counters in the state DB (``syslog-backpressure``
  kv namespace) so every worker — including the dashboard — can see them;
* it appends one audit-log row when drops first appear and again at every
  further +1,000, so a storm leaves a trace instead of a silent counter;
* ``summarize`` / ``backpressure_status`` (in ``state_store``) feed the
  ``/api/status/overview`` ``backpressure`` section the dashboard renders.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

log = logging.getLogger(__name__)

BACKPRESSURE_NS = "syslog-backpressure"

#: Counters that mean lines were lost (all per listener, cumulative).
DROP_KEYS = ("udp_drops", "spool_lines_lost", "queue_overflow", "dropped_oversize")

#: Audit again each time the total passes another multiple of this.
AUDIT_STEP = 1_000


def summarize(counters: Mapping[str, int]) -> dict[str, Any]:
    """Total lost lines, a warning flag and a one-line message for a counter set."""
    vals = {key: max(0, int(counters.get(key, 0) or 0)) for key in DROP_KEYS}
    total = sum(vals.values())
    parts = [f"{key.replace('_', ' ')} {value}" for key, value in vals.items() if value]
    message = ("Syslog backpressure: " + ", ".join(parts) + " lost"
               if total else "No syslog drops recorded")
    return {**vals, "total": total, "warning": total > 0, "message": message}


def next_audit_watermark(total: int, watermark: int) -> int | None:
    """New watermark to record when ``total`` crossed an audit threshold, else None.

    The first drop audits immediately (watermark becomes the total); after
    that, one audit row per further 1,000 lost lines.
    """
    if total <= watermark:
        return None
    if watermark <= 0:
        return total
    candidate = (total // AUDIT_STEP) * AUDIT_STEP
    return candidate if candidate > watermark else None


def publish(db: Any, source: str, counters: Mapping[str, int]) -> dict[str, Any] | None:
    """Persist ``counters`` for ``source`` and audit threshold crossings.

    Returns the summary when anything changed since the last publish, else
    None. Never raises: a failed publish must not disturb the listener.
    """
    try:
        summary = summarize(counters)
        stored = db.kv_get_all(BACKPRESSURE_NS)
        prev = stored.get(f"source:{source}") or {}
        if isinstance(prev, dict) and all(summary[k] == int(prev.get(k, 0) or 0) for k in DROP_KEYS):
            return None
        db.backpressure_report(source, counters)
        total = summary["total"]
        watermark = int(stored.get(f"audited_up_to:{source}", 0) or 0)
        new_mark = next_audit_watermark(total, watermark)
        if new_mark is not None:
            from ai_log_analyzer import audit

            audit.record("syslog_backpressure", target=source, outcome="warning",
                         detail={"total_drops": total,
                                 **{key: summary[key] for key in DROP_KEYS}})
            db.kv_set(BACKPRESSURE_NS, f"audited_up_to:{source}", new_mark)
        return summary
    except Exception:
        log.debug("backpressure publish failed for %s", source, exc_info=True)
        return None
