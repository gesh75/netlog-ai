"""Continuous streaming triage: spool → sliding window → RCA → tickets.

The syslog listener writes every line to the SQLite WAL spool. This worker
tails that spool on its own, without waiting for anyone to upload logs to
``/api/analyze``, and on each tick:

1. reads new spool rows oldest-first from a persisted cursor (restarts
   resume, and a worker that falls behind catches up instead of skipping);
2. parses and classifies them, drops exact duplicates (relay echoes) and
   keeps a sliding window (``window_s``) of classified events. When the
   dependency map maps the sending address to a host, a line that names a
   different device the map knows is attributed to the sender instead
   (``hostname_mismatch`` in the totals; list collectors under ``relays``);
3. runs down→up entity pairing, topology-aware suppression and the
   action-item grouping over the window, so a core-router failure becomes
   one root incident instead of a ticket per dependent BGP session;
4. turns each root and each remaining unsuppressed group at or above
   ``min_severity`` into an incident with the RCA playbook, cited evidence
   (when a retrieval index is configured) and, for interface-level faults,
   a guarded drain plan with its Ansible check-mode playbook;
5. opens or updates tickets on the configured sinks (Jira, ServiceNow,
   webhook, or the in-memory dry-run sink), keyed by site, device and layer
   (``TriageIncidentPayload.fingerprint``), so one incident keeps one ticket
   as its streaming picture evolves.

Ticket-storm controls:

* **Per-incident cooldown** (``cooldown_s``, default 15 min): after a ticket
  is opened or updated, new events for the same fingerprint are held. A
  severity escalation or a state change (active → recovered) bypasses it.
* **Nothing new, no update:** after the cooldown an update is only sent when
  the incident gained events since the last send.
* **Self-healed:** a group whose entities already recovered never opens a
  ticket.
* **Global rate limit** (``max_tickets_per_hour``): excess sends are deferred
  to a later tick, not dropped. Send attempts (failed ones too) are kept in the
  state DB, so a restart does not reset the limiter; critical incidents are
  sent first, and among equal severities the incident parked longest goes first.
* **Shares of the budget:** one syslog sender may use at most half of the hourly
  budget (``max_per_sender_per_hour``) and one device a fifth
  (``max_per_device_per_hour``), so a flood from one source, even of critical
  incidents under invented hostnames, cannot starve other devices' tickets. A
  sender may also keep only ``max_pending_per_sender`` incidents parked; the
  rest are dropped and counted (``dropped``).

Reliability:

* A tick drains the spool until it is empty or ``tick_budget_s`` elapses (then
  it re-polls immediately), so throughput is not capped at ``batch / poll_s``.
  Rows the spool pruned before this worker read them are counted (``gap_rows``).
* Cursors are committed after the tick's deliveries, and an undelivered
  incident (sink down, rate-limited) is persisted as a pending delivery, so a
  crash or lease takeover neither skips nor forgets it. A new active worker
  rebuilds its sliding window from the spool.
* Each sink has its own retry state (exponential backoff with jitter and a
  circuit breaker); a partial failure retries only the sinks that failed. The
  lease is checked between candidates and the tick aborts if it was lost.

Only one worker processes the spool at a time: a lease in the state DB
elects the active worker, so every Gunicorn worker can run the loop and the
others stay on standby. Ticket state (cooldowns, refs) lives in the
``triage_tickets`` table, so it survives restarts and is shared.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import random
import socket
import threading
import time
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from ai_log_analyzer import _shutdown, audit
from ai_log_analyzer.classifier import ClassifiedEvent, iter_classify
from ai_log_analyzer.hostnames import short_host
from ai_log_analyzer.itsm import IncidentEnrichmentPayload
from ai_log_analyzer.parsers import registry as parser_registry
from ai_log_analyzer.parsers.entities import valid_ip
from ai_log_analyzer.sanitize import sanitize
from ai_log_analyzer.state_store import LeaseLost

log = logging.getLogger(__name__)

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_LEASE = "triage-worker"
_SYSTEM_ACTOR = audit.Actor("triage-worker", "system")
_VENDOR_OS = {
    "frr": "frr", "paloalto": "paloalto_panos", "cisco_sdwan": "cisco_sdwan", "fortinet": "fortinet_fortios",
    "juniper": "juniper_junos", "arista": "arista_eos", "cisco_ios": "cisco_ios", "cisco_nxos": "cisco_nxos",
}
_DRAINABLE = frozenset({"interface", "lag", "optical"})


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class TriageConfig:
    window_s: float = 300.0
    poll_s: float = 15.0
    cooldown_s: float = 900.0
    min_severity: str = "high"
    max_tickets_per_hour: int = 30
    max_per_sender_per_hour: int = 0     # share of the hourly budget one sender may use (0 = half, at least 2)
    max_per_device_per_hour: int = 0     # share one device may use (0 = a fifth, at least 2)
    max_pending_per_sender: int = 100    # parked incidents one sender may keep (0 = no limit)
    batch: int = 5000
    max_window_events: int = 20_000
    dedup_s: float = 5.0
    site: str = "default"
    use_llm: bool = False
    sources: tuple[str, ...] = ()
    lease_ttl_s: float = 60.0
    tick_budget_s: float = 10.0          # max time one tick spends draining the spool before re-polling
    sink_backoff_s: float = 30.0         # first retry delay of a failing sink (doubles, with jitter)
    sink_backoff_max_s: float = 900.0
    sink_breaker_threshold: int = 5      # consecutive failures that open a sink's circuit breaker
    pending_ttl_s: float = 86_400.0      # give up on an undeliverable incident after this long
    retention_days: float = 30.0         # prune resolved ticket rows older than this (0 = keep)

    def sender_share(self) -> int:
        """Tickets per hour one sender may use: configured, else half the budget (at least 2)."""
        cap = self.max_tickets_per_hour
        return min(cap, self.max_per_sender_per_hour or max(2, -(-cap // 2)))

    def device_share(self) -> int:
        """Tickets per hour one device may use: configured, else a fifth of the budget (at least 2)."""
        cap = self.max_tickets_per_hour
        return min(cap, self.max_per_device_per_hour or max(2, cap // 5))

    @classmethod
    def from_env(cls) -> TriageConfig:
        e = os.environ.get
        sev = (e("AI_LOG_ANALYZER_TRIAGE_MIN_SEVERITY", "") or "high").strip().lower()
        return cls(
            window_s=_env_float("AI_LOG_ANALYZER_TRIAGE_WINDOW_S", 300.0),
            poll_s=_env_float("AI_LOG_ANALYZER_TRIAGE_POLL_S", 15.0),
            cooldown_s=_env_float("AI_LOG_ANALYZER_TRIAGE_COOLDOWN_S", 900.0),
            min_severity=sev if sev in SEV_RANK else "high",
            max_tickets_per_hour=int(_env_float("AI_LOG_ANALYZER_TRIAGE_MAX_TICKETS_PER_HOUR", 30)),
            max_per_sender_per_hour=int(_env_float("AI_LOG_ANALYZER_TRIAGE_MAX_PER_SENDER_PER_HOUR", 0)),
            max_per_device_per_hour=int(_env_float("AI_LOG_ANALYZER_TRIAGE_MAX_PER_DEVICE_PER_HOUR", 0)),
            max_pending_per_sender=int(_env_float("AI_LOG_ANALYZER_TRIAGE_MAX_PENDING_PER_SENDER", 100)),
            site=(e("AI_LOG_ANALYZER_TRIAGE_SITE", "") or "default").strip(),
            use_llm=(e("AI_LOG_ANALYZER_TRIAGE_USE_LLM", "") or "").strip().lower() in ("1", "true", "yes"),
            sources=tuple(s.strip() for s in (e("AI_LOG_ANALYZER_TRIAGE_SOURCES", "") or "").split(",")
                          if s.strip()),
            tick_budget_s=_env_float("AI_LOG_ANALYZER_TRIAGE_TICK_BUDGET_S", 10.0),
            retention_days=_env_float("AI_LOG_ANALYZER_TRIAGE_RETENTION_DAYS", 30.0),
        )


@dataclass
class TriageIncidentPayload(IncidentEnrichmentPayload):
    """ITSM payload keyed by site, device and layer only.

    The streaming view of one incident changes from tick to tick: a plain
    alert group can become a suppression root, a second interface can join,
    the root entity can be a tunnel rather than a port. Keeping the entity
    out of the key keeps one ticket per device and layer through all of
    that; the interface still drives the remediation plan and is shown in
    the ticket.
    """

    @property
    def fingerprint(self) -> str:
        raw = f"{self.site}|{self.root_device.lower()}|{self.root_layer}|triage"
        return "NETLOG-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()


# ─────────────────────────────────────────────────────────────────────────────
# Sinks
# ─────────────────────────────────────────────────────────────────────────────

class TicketSink(Protocol):
    name: str

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]: ...


class MemorySink:
    """Dry-run sink: keeps the last ``cap`` payloads in memory."""

    name = "dry-run"

    def __init__(self, cap: int = 200) -> None:
        self.sent: deque[dict[str, Any]] = deque(maxlen=cap)

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        action = "updated" if any(s["fingerprint"] == payload.fingerprint for s in self.sent) else "created"
        self.sent.append({"fingerprint": payload.fingerprint, "action": action,
                          "title": payload.summary_title, "body": payload.to_markdown_body(),
                          "devices": list(payload.affected_devices)})
        return {"action": action, "ref": payload.fingerprint}


class WebhookSink:
    """Posts each open/update as JSON (generic) or a Slack message."""

    name = "webhook"

    def __init__(self, url: str, fmt: str = "generic", timeout_s: float = 5.0) -> None:
        self.url = url
        self.fmt = fmt
        self.timeout_s = timeout_s

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        import requests

        title = sanitize(f"[{payload.site}] {payload.summary_title} ({payload.root_device})", mask_pii=True)[0]
        body = sanitize(payload.to_markdown_body(), mask_pii=True)[0]
        if self.fmt == "slack":
            safe = (title + "\n" + body[:2500]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            data: dict[str, Any] = {"text": safe}
        else:
            data = {"event": "netlog.incident", "fingerprint": payload.fingerprint, "title": title,
                    "site": payload.site, "devices": list(payload.affected_devices), "markdown": body,
                    "idempotency_key": payload.fingerprint}
        r = requests.post(self.url, json=data, timeout=self.timeout_s,
                          headers={"Idempotency-Key": payload.fingerprint})
        if r.status_code >= 300:
            raise RuntimeError(f"webhook answered HTTP {r.status_code}")
        return {"action": "posted", "ref": payload.fingerprint}


class _ItsmSink:
    def __init__(self, name: str, client: Any) -> None:
        self.name = name
        self.client = client

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        # Same redaction the webhook sink applies: tickets leave the host. The fingerprint
        # (site, device, layer) is unchanged, so the clients keep correlating on it.
        clean = dataclasses.replace(
            payload, summary_title=sanitize(payload.summary_title, mask_pii=True)[0],
            rca_rationale=sanitize(payload.rca_rationale, mask_pii=True)[0],
            attachments={k: sanitize(v, mask_pii=True)[0] for k, v in payload.attachments.items()})
        res = self.client.upsert_incident(clean)
        return {**res, "ref": res.get("issue_key") or res.get("number") or payload.fingerprint}


def sinks_from_env() -> list[Any]:
    """Sinks named in ``AI_LOG_ANALYZER_TRIAGE_SINKS`` (jira, servicenow, webhook,
    dry-run). Defaults to the dry-run sink so nothing external happens by accident."""
    from ai_log_analyzer.itsm import JiraITSMClient, ServiceNowITSMClient

    names = [n.strip().lower() for n in (os.environ.get("AI_LOG_ANALYZER_TRIAGE_SINKS", "") or "dry-run")
             .split(",") if n.strip()]
    sinks: list[Any] = []
    for name in names:
        try:
            if name == "jira":
                sinks.append(_ItsmSink("jira", JiraITSMClient.from_env()))
            elif name == "servicenow":
                e = os.environ.get
                url = e("SERVICENOW_URL") or e("SNOW_URL") or ""
                user = e("SERVICENOW_USER") or e("SNOW_USER") or ""
                pwd = e("SERVICENOW_PASSWORD") or e("SNOW_PASSWORD") or ""
                if not (url and user and pwd):
                    raise ValueError("SERVICENOW_URL, SERVICENOW_USER and SERVICENOW_PASSWORD are required")
                sinks.append(_ItsmSink("servicenow", ServiceNowITSMClient(url, user, pwd)))
            elif name == "webhook":
                url = os.environ.get("AI_LOG_ANALYZER_WEBHOOK_URL", "").strip()
                if not url:
                    raise ValueError("AI_LOG_ANALYZER_WEBHOOK_URL is required")
                sinks.append(WebhookSink(url, os.environ.get("AI_LOG_ANALYZER_WEBHOOK_FORMAT", "generic")))
            elif name in ("dry-run", "dryrun", "memory"):
                sinks.append(MemorySink())
            else:
                log.warning("unknown triage sink %r ignored", name)
        except ValueError as exc:
            log.warning("triage sink %s not configured: %s", name, exc)
    return sinks or [MemorySink()]


# ─────────────────────────────────────────────────────────────────────────────
# Worker
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Windowed:
    received_at: float
    event: ClassifiedEvent
    dups: int = 0   # exact repeats the dedup folded into this entry


@dataclass
class _Seen:
    """Dedup marker for one (host, message): when it was first kept and the window entry it became."""
    first_at: float
    windowed: _Windowed | None = None
    extra: int = 0
    last_at: float = 0.0

    def bump(self, at: float) -> None:
        """A duplicate was dropped: keep the incident's window entry fresh and counted."""
        if self.windowed is not None:
            self.windowed.dups += 1
            self.windowed.received_at = max(self.windowed.received_at, at)
        else:
            self.extra += 1
            self.last_at = max(self.last_at, at)


class _LeaseGone(Exception):
    """The triage lease was taken over mid-tick."""


class StreamingTriageWorker:
    """See module docstring. ``run_once`` is the deterministic unit; ``start``
    runs it on a daemon thread every ``poll_s`` seconds."""

    def __init__(self, db: Any, sinks: Iterable[Any] | None = None, config: TriageConfig | None = None, *,
                 topology: Any = None, rag_index: Any = None, clock: Any = time.time,
                 owner: str | None = None) -> None:
        from ai_log_analyzer.suppression import load_topology

        self.db = db
        self.sinks = list(sinks) if sinks is not None else sinks_from_env()
        self.config = config or TriageConfig.from_env()
        self.topology = topology if topology is not None else load_topology()
        self.rag_index = rag_index
        self.clock = clock
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}:{id(self):x}"
        self._window: deque[_Windowed] = deque()
        self._recent: dict[tuple[str, str], _Seen] = {}
        self._send_times: deque[float] = deque()      # persisted in kv so a restart keeps the limiter
        self._send_log: deque[tuple[float, str, str]] = deque()   # (time, sender, device) of the same attempts
        self._cursor_pending: dict[str, int] = {}     # read this tick, committed after its deliveries
        self._gap_pending: dict[str, int] = {}
        self._warmed: set[str] = set()
        self._mismatch_seen: set[tuple[str, str]] = set()   # (sender, claimed host) already logged
        self._state_loaded = False
        self._sink_state: dict[str, dict[str, float]] = {}
        self._last_prune = 0.0
        self._last_renew = 0.0
        self._explicit_now: float | None = None
        self._rand = random.random
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.role = "idle"
        self.last_tick: dict[str, Any] = {}
        self.totals: Counter = Counter()

    # ── cursors ─────────────────────────────────────────────────────────────
    def _cursors(self) -> dict[str, int]:
        return {k[len("cursor:"):]: int(v) for k, v in self.db.kv_get_all("triage").items()
                if k.startswith("cursor:")}

    def _sources(self) -> list[str]:
        return list(self.config.sources) or self.db.spool_sources()

    def _reset_active_state(self) -> None:
        """Forget what only a lease holder knows; the next active tick reloads it from the DB."""
        self._window.clear()
        self._recent.clear()
        self._cursor_pending.clear()
        self._gap_pending.clear()
        self._warmed.clear()
        self._state_loaded = False

    def _load_state(self) -> None:
        if self._state_loaded:
            return
        state = self.db.kv_get_all("triage")
        self._send_times = deque(sorted(float(t) for t in state.get("send_times") or []))
        try:
            rows = state.get("send_log") or []
            self._send_log = deque(sorted((float(t), str(s), str(d)) for t, s, d in rows))
        except (TypeError, ValueError):
            self._send_log = deque()
        self._state_loaded = True

    def _commit(self) -> None:
        """Persist read positions, only after the tick's deliveries were decided."""
        for source, cursor in self._cursor_pending.items():
            self.db.kv_set("triage", f"cursor:{source}", cursor)
        for source, gap in self._gap_pending.items():
            self.db.kv_set("triage", f"gapseen:{source}", gap)
        self._cursor_pending.clear()
        self._gap_pending.clear()

    # ── ingest ──────────────────────────────────────────────────────────────
    def _known_hosts(self) -> set[str]:
        """Every device the dependency map / inventory names (short, lowercase)."""
        t = self.topology
        return {*t.ips.values(), *t.children, *(c for kids in t.children.values() for c in kids),
                *t.ha_peer, *t.roles}

    def _attribute(self, ev: Any, sender: str, known: set[str]) -> Any:
        """Pin a line to the device the inventory says sent it.

        The hostname inside a syslog line is whatever the sender wrote. When the dependency map maps
        the sender address to one host and the line names a *different* device the map knows, the line
        is attributed to its sender (the claimed name is kept in ``attrs["claimed_host"]``), so it can
        not open, update or recover that other device's incident. Unmapped senders, listed relays and
        names the map does not know are left as they are: nothing to check them against.
        """
        topo = self.topology
        ip = valid_ip(sender)
        owner = topo.ips.get(ip)
        claimed = short_host(ev.hostname)
        if not owner or ip in topo.relays or claimed == owner or claimed not in known:
            return ev
        self.totals["hostname_mismatch"] += 1
        if len(self._mismatch_seen) < 256 and (ip, claimed) not in self._mismatch_seen:
            self._mismatch_seen.add((ip, claimed))
            log.warning("triage: %s is %s in the inventory but sent a line naming %s; attributed to %s",
                        ip, owner, claimed, owner)
        return dataclasses.replace(ev, hostname=owner, attrs={**ev.attrs, "claimed_host": ev.hostname})

    def _process(self, rows: list[tuple[int, float, str, str]], source: str, horizon: float) -> int:
        """Parse, dedup and classify spool rows into the window; returns entries added."""
        events, stamps, seens = [], [], []
        dedup_s = self.config.dedup_s
        known = self._known_hosts() if self.topology.ips else set()
        for _id, received_at, sender, line in rows:
            if received_at < horizon:
                continue  # backlog older than the window: nothing left to triage
            ev = parser_registry.parse(line, default_host=sender or source)
            if ev is None:
                continue
            if sender:
                ev = dataclasses.replace(ev, attrs={**ev.attrs, "sender_ip": sender})
                if known:
                    ev = self._attribute(ev, sender, known)
            key = (ev.hostname, ev.message)
            seen = self._recent.get(key)
            # The interval is fixed from the first kept copy: a steady repeat is re-admitted every
            # dedup_s instead of being swallowed for as long as it keeps repeating.
            if seen is not None and received_at - seen.first_at <= dedup_s:
                self.totals["duplicates_dropped"] += 1
                seen.bump(received_at)
                continue
            seen = self._recent[key] = _Seen(received_at)
            events.append(ev)
            stamps.append(received_at)
            seens.append(seen)
        added = 0
        for received_at, ce, seen in zip(stamps, iter_classify(events), seens):
            if ce.severity in ("critical", "high", "medium") or ce.event_type:
                w = _Windowed(received_at, ce, dups=seen.extra)
                if seen.extra:
                    w.received_at = max(w.received_at, seen.last_at)
                seen.windowed = w
                self._window.append(w)
                added += 1
        return added

    def _warm(self, source: str, cursor: int, horizon: float) -> None:
        """Rebuild the sliding window after a takeover or restart from rows already committed."""
        rows = [r for r in self.db.spool_before(source, cursor, self.config.max_window_events)
                if r[1] >= horizon]
        if rows:
            self.totals["window_rebuilt"] += self._process(rows, source, horizon)

    def _ingest(self, now: float, deadline: float) -> tuple[int, bool, int]:
        """Read the spool until it is drained or ``deadline`` (monotonic) passes.

        Returns (fresh window entries, backlog remains, rows pruned unread since last tick).
        """
        state = self.db.kv_get_all("triage")
        horizon = now - self.config.window_s
        fresh = gap_rows = 0
        backlog = False
        batch = max(1, int(self.config.batch))
        for source in self._sources():
            cursor = self._cursor_pending.get(source, int(state.get(f"cursor:{source}", 0)))
            lost = self.db.spool_gap(source)["lost_unread"]
            seen_lost = self._gap_pending.get(source, int(state.get(f"gapseen:{source}", 0)))
            if lost > seen_lost:
                gap_rows += lost - seen_lost
                self.totals["gap_rows"] += lost - seen_lost
                log.warning("triage: %d spool row(s) of %s were pruned before they were read "
                            "(spool cap too small for the ingest rate, or triage fell behind)",
                            lost - seen_lost, source)
                self._gap_pending[source] = lost
            if source not in self._warmed:
                self._warmed.add(source)
                if cursor > 0:
                    self._warm(source, cursor, horizon)
            while True:
                rows = self.db.spool_read(source, cursor, batch)
                if not rows:
                    break
                fresh += self._process(rows, source, horizon)
                cursor = int(rows[-1][0])
                self._cursor_pending[source] = cursor
                self.totals["lines_read"] += len(rows)
                if len(rows) < batch:
                    break
                if time.monotonic() >= deadline:
                    backlog = True
                    break
        while self._window and (self._window[0].received_at < horizon
                                or len(self._window) > self.config.max_window_events):
            self._window.popleft()
        keep = now - max(self.config.dedup_s, 1.0)
        self._recent = {k: v for k, v in self._recent.items() if v.first_at >= keep}
        return fresh, backlog, gap_rows

    # ── evaluation ──────────────────────────────────────────────────────────
    def _candidates(self) -> list[dict[str, Any]]:
        from ai_log_analyzer.analyzer import _group_actionable
        from ai_log_analyzer.entity_state import EntityStateTracker, group_state
        from ai_log_analyzer.suppression import suppress_alerts, suppressed_entity_map

        events = [w.event for w in self._window]
        latest_group: dict[tuple[str, str], float] = {}
        latest_pair: dict[tuple[str, str], float] = {}
        dups_group: dict[tuple[str, str], int] = {}    # repeats the dedup folded into window entries
        dups_pair: dict[tuple[str, str], int] = {}
        for w in self._window:
            e = w.event
            k = (e.severity, e.description)
            latest_group[k] = max(latest_group.get(k, 0.0), w.received_at)
            pk = (e.description, (e.hostname or "").lower())
            latest_pair[pk] = max(latest_pair.get(pk, 0.0), w.received_at)
            if w.dups:
                dups_group[k] = dups_group.get(k, 0) + w.dups
                dups_pair[pk] = dups_pair.get(pk, 0) + w.dups
        vendor_of: dict[str, str] = {}
        senders_of: dict[str, set[str]] = {}   # lowercased host → addresses the listener saw it come from
        display: dict[str, str] = {}       # lowercased host → name as logged
        category_of: dict[str, str] = {}   # description → classifier category
        iface_display: dict[str, str] = {}   # entity keys lowercase names; tickets show them as logged
        for e in events:
            if e.interface:
                iface_display.setdefault(e.interface.lower(), e.interface)
            if e.hostname:
                display.setdefault(e.hostname.lower(), e.hostname)
                if (e.attrs or {}).get("sender_ip"):
                    senders_of.setdefault(e.hostname.lower(), set()).add(e.attrs["sender_ip"])
                if e.vendor:
                    vendor_of.setdefault(e.hostname.lower(), e.vendor)
            category_of.setdefault(e.description, e.category)
        seen: dict = {}
        tracker = EntityStateTracker()
        for seq, e in enumerate(events):
            _group_actionable(e, seen, seq, tracker.add(e, seq))
        report = tracker.report()
        supp = suppress_alerts([e for e in events if e.event_type], self.topology,
                               window_s=self.config.window_s)
        smap = suppressed_entity_map(supp)
        min_rank = SEV_RANK[self.config.min_severity]
        out: list[dict[str, Any]] = []
        covered: set[tuple[str, str]] = set()   # (description, host) alerts a root already explains
        for g in supp["groups"]:
            members = [g["root"], *g["children"]]
            pairs = {(m.get("description", ""), (m.get("hostname") or "").lower()) for m in members}
            covered |= pairs
            for h in g["root_hosts"]:
                covered.add((g["label"], h.lower()))
            sev = min((m.get("severity") or "medium" for m in members), key=lambda s: SEV_RANK.get(s, 5))
            if SEV_RANK.get(sev, 5) > min_rank:
                continue
            root_host = display.get(g["root_hosts"][0].lower(), g["root_hosts"][0])
            root_desc = g["root"].get("description") or g["label"]
            category = category_of.get(root_desc, g["kind"])
            out.append({
                "kind": "root", "severity": sev, "category": category, "root_kind": g["kind"],
                "description": root_desc, "summary": g["summary"], "root_device": root_host,
                # Same fingerprint inputs as the plain group of this alert (device,
                # category, entity): an incident that gains dependents keeps its ticket.
                "layer": category,
                # The root entity is a port only when it names a logged interface.
                "interface": iface_display.get((g["root"].get("entity") or "").lower()),
                "devices": sorted({display.get(h.lower(), h) for h in [*g["root_hosts"], *g["child_devices"]]}),
                "suppressed": g["suppressed_count"],
                "count": 1 + g["suppressed_count"] + sum(dups_pair.get(pk, 0) for pk in pairs),
                "messages": [f"{m.get('hostname', '')}: {m.get('description', '')}" for m in members[:5]],
                "state": "active", "vendor": g["root"].get("vendor") or vendor_of.get(root_host.lower(), ""),
                "root_id": g["id"], "confidence": 0.75 if g.get("inferred") else 0.9,
                "senders": sorted(senders_of.get(root_host.lower(), ())),
                "latest": max((latest_pair.get(pk, 0.0) for pk in pairs), default=0.0),
            })
        for (_sev, _desc), b in seen.items():
            if SEV_RANK.get(b["severity"], 5) > min_rank:
                continue
            ents = b.get("entities") or set()
            if ents and None not in {smap.get(e) for e in ents}:
                continue  # every entity is a dependent alert: its root carries the ticket
            state, _ = group_state(ents, report)
            # Devices whose instance of this alert a root already explains are
            # dropped; a group left with no device is fully covered.
            devices = sorted(d for d in b["devices"] if (b["description"], d.lower()) not in covered)
            if b["devices"] and not devices:
                continue
            devices = devices or ["unknown"]
            ifaces = sorted({iface_display.get(e[2], e[2]) for e in ents if e[1] in ("intf", "lag")})
            n_events = b["count"] + dups_group.get((b["severity"], b["description"]), 0)
            out.append({
                "kind": "group", "severity": b["severity"], "category": b["category"],
                "description": b["description"], "summary": f"{b['description']} ({n_events} event(s))",
                "root_device": devices[0], "layer": b["category"],
                "interface": ifaces[0] if len(ifaces) == 1 else None, "devices": devices,
                "suppressed": 0, "count": n_events,
                "messages": [m for _, _, m in sorted(b["msg_heap"], reverse=True)],
                "state": state or "active", "vendor": vendor_of.get(devices[0].lower(), ""), "confidence": 0.7,
                "latest": latest_group.get((b["severity"], b["description"]), 0.0),
                "senders": sorted(senders_of.get(devices[0].lower(), ())),
            })
        return out

    def _payload(self, c: dict[str, Any]) -> IncidentEnrichmentPayload:
        from ai_log_analyzer import rag
        from ai_log_analyzer.analyzer import deep_analyze

        evidence = (rag.retrieve_evidence(self.rag_index, " ".join([c["description"], c["category"],
                                                                       *c["messages"][:3]]),
                                          hosts=c["devices"]) if self.rag_index is not None else None)
        deep = deep_analyze(c["category"], c["description"], c["devices"], c["count"], c["messages"],
                            skip_llm=not self.config.use_llm, evidence=evidence)
        plan, attachments = None, {}
        phases = []
        for phase in deep.get("phases") or []:
            cmds = [f"`{cli}`" for a in phase.get("actions") or [] for cli in (a.get("cli") or {}).values() if cli]
            if cmds:
                phases.append(f"- **{phase.get('name', '')}:** " + "; ".join(cmds[:4]))
        attachments["RCA playbook"] = "\n".join(
            [f"**Root cause:** {deep.get('root_cause', '')}", f"**Risk:** {deep.get('risk', '')}", *phases[:5]])
        if deep.get("evidence"):
            attachments["Evidence"] = "\n".join(f"- [{e['id']}] {e['citation']}" for e in deep["evidence"])
        attachments["Sample events"] = "\n".join(
            f"- `{sanitize(m, mask_pii=False)[0][:200]}`" for m in c["messages"][:5])
        vos = _VENDOR_OS.get(c["vendor"] or "")
        if vos and c["interface"] and (c["category"] in _DRAINABLE or c["kind"] == "root"):
            from ai_log_analyzer.remediation import RemediationGenerator, SafetyViolationError, VendorOS
            from ai_log_analyzer.remediation_export import ExportUnsupportedError, export_plan
            try:
                plan = RemediationGenerator().build_graceful_link_drain(
                    device=c["root_device"], vendor=VendorOS(vos), interface=c["interface"],
                    rationale=f"Proposed by streaming triage for: {c['description']}. Review before applying.")
                attachments["Ansible (run with --check --diff first)"] = (
                    "```yaml\n" + export_plan(plan, "ansible") + "\n```")
            except (ExportUnsupportedError, SafetyViolationError, ValueError) as exc:
                attachments["Automation export"] = f"Not exported: {exc}"
        if c.get("related"):
            attachments["Related alerts"] = "\n".join(f"- {r}" for r in c["related"][:20])
        return TriageIncidentPayload(
            site=self.config.site, root_device=c["root_device"], root_layer=c["layer"],
            root_interface=c["interface"],
            summary_title=c["description"] if c["kind"] == "group" else c["summary"],
            rca_rationale=deep.get("root_cause") or c["summary"], confidence=c["confidence"],
            affected_devices=c["devices"], suppressed_symptom_count=c["suppressed"],
            remediation_plan=plan, attachments=attachments)

    def _fingerprint(self, c: dict[str, Any]) -> str:
        return TriageIncidentPayload(site=self.config.site, root_device=c["root_device"], root_layer=c["layer"],
                                     root_interface=c["interface"], summary_title="", rca_rationale="",
                                     confidence=0.0).fingerprint

    def _merge(self, cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """One incident per triage fingerprint (same device and layer)."""
        merged: dict[str, dict[str, Any]] = {}
        for c in cands:
            fp = self._fingerprint(c)
            c0 = merged.get(fp)
            if c0 is None:
                merged[fp] = {**c, "fingerprint": fp, "related": []}
                continue
            c0["count"] += c["count"]
            c0["suppressed"] += c["suppressed"]
            c0["latest"] = max(c0["latest"], c["latest"])
            if SEV_RANK.get(c["severity"], 5) < SEV_RANK.get(c0["severity"], 5):
                c0["severity"] = c["severity"]
            if c["state"] == "active":
                c0["state"] = "active"
            c0["devices"] = sorted(set(c0["devices"]) | set(c["devices"]))
            c0["senders"] = sorted({*c0.get("senders", ()), *c.get("senders", ())})
            c0["related"].append(c["summary"])
        return list(merged.values())

    def _origin(self, c: dict[str, Any]) -> tuple[str, str]:
        """(sender, device) an incident's budget is charged to.

        The device is the incident's root device. The sender is the address the listener saw that
        device's lines come from (the least used one, so a line forged from elsewhere cannot make a
        genuine device share its sender's cap); "" when nothing is known (file sources, inferred roots).
        """
        senders = [s for s in c.get("senders") or [] if s]
        sender = min(senders, key=lambda s: (sum(1 for _, x, _d in self._send_log if x == s), s), default="")
        return sender, (c.get("root_device") or "").lower()

    def _rate_block(self, now: float, sender: str = "", device: str = "") -> str:
        """Why this incident may not be sent now: "global", "sender", "device"; "" when it may."""
        while self._send_times and self._send_times[0] < now - 3600:
            self._send_times.popleft()
        while self._send_log and self._send_log[0][0] < now - 3600:
            self._send_log.popleft()
        cfg = self.config
        if len(self._send_times) >= cfg.max_tickets_per_hour:
            return "global"
        if sender and sum(1 for _, s, _d in self._send_log if s == sender) >= cfg.sender_share():
            return "sender"
        if device and sum(1 for _, _s, d in self._send_log if d == device) >= cfg.device_share():
            return "device"
        return ""

    def _note_attempt(self, now: float, sender: str = "", device: str = "") -> None:
        """Count one delivery attempt (failed ones too) toward the hourly limits, durably."""
        self._send_times.append(now)
        self._send_log.append((now, sender, device))
        self.db.kv_set("triage", "send_times", list(self._send_times))
        self.db.kv_set("triage", "send_log", [list(row) for row in self._send_log])

    def _decide(self, rec: dict[str, Any] | None, c: dict[str, Any], now: float) -> str:
        if rec is None:
            return "skip_recovered" if c["state"] in ("recovered", "up") else "open"
        escalated = SEV_RANK.get(c["severity"], 5) < SEV_RANK.get(rec.get("severity") or "info", 5)
        state_changed = bool(rec.get("state")) and c["state"] != rec.get("state")
        if escalated or state_changed:
            return "update"
        if now - float(rec["last_sent"]) < self.config.cooldown_s:
            return "hold"
        # Only events that arrived after the last send justify an update; the
        # window count is no signal (it shrinks as old events slide out).
        return "update" if c["latest"] > float(rec.get("last_event_at") or 0.0) else "hold"

    # ── sinks: per-sink retry state ─────────────────────────────────────────
    def _sink_ready(self, name: str, now: float) -> bool:
        return now >= self._sink_state.get(name, {}).get("next_try", 0.0)

    def _sink_failed(self, name: str, now: float) -> None:
        cfg = self.config
        st = self._sink_state.setdefault(name, {"fails": 0, "next_try": 0.0})
        st["fails"] += 1
        delay = min(cfg.sink_backoff_s * 2 ** min(int(st["fails"]) - 1, 20), cfg.sink_backoff_max_s)
        if st["fails"] >= cfg.sink_breaker_threshold:
            delay = cfg.sink_backoff_max_s      # breaker open: one probe per maximum interval
        st["next_try"] = now + delay * (0.8 + 0.4 * self._rand())

    def _now(self) -> float:
        return self.clock() if self._explicit_now is None else self._explicit_now

    def _still_leader(self) -> bool:
        """Check (and renew when due) the lease; False once another worker took it over."""
        t = self._now()
        if not self.db.lease_valid(_LEASE, self.owner, t):
            return False
        if t - self._last_renew >= self.config.lease_ttl_s / 4:
            if not self.db.lease_acquire(_LEASE, self.owner, self.config.lease_ttl_s, now=t):
                return False
            self._last_renew = t
        return True

    def _send(self, payload: IncidentEnrichmentPayload, sinks: list[Any],
              now: float) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Deliver to each sink; returns (results, error texts, names that failed)."""
        results, errors, failed = [], [], []
        for sink in sinks:
            if not self._still_leader():
                raise _LeaseGone()
            try:
                res = sink.upsert_incident(payload)
            except Exception as exc:  # network / HTTP / auth errors must not stop the loop
                errors.append(f"{sink.name}: {str(exc)[:200]}")
                failed.append(sink.name)
                self._sink_failed(sink.name, now)
                st = self._sink_state[sink.name]
                log.warning("triage sink %s failed (%d in a row, next try in %.0f s): %s", sink.name,
                            st["fails"], st["next_try"] - now, str(exc)[:200])
                continue
            self._sink_state.pop(sink.name, None)
            results.append({"sink": sink.name, "action": res.get("action", ""), "ref": str(res.get("ref", ""))})
        return results, errors, failed

    # ── pending deliveries (durable) ────────────────────────────────────────
    def _park(self, c: dict[str, Any], action: str, sinks: list[str], pend: dict[str, Any] | None,
              now: float, nowhere: bool = False, sender: str = "") -> bool:
        """Remember an undelivered incident so a crash or takeover still delivers it.

        A new incident of ``sender`` is refused (False) once that sender already keeps
        ``max_pending_per_sender`` incidents parked: one source cannot choose how much waits.
        """
        cap = self.config.max_pending_per_sender
        if pend is None and sender and cap > 0:
            held = sum(1 for p in self.db.kv_get_all("triage_pending").values()
                       if sender in ((p.get("c") or {}).get("senders") or ()))
            if held >= cap:
                self.totals["dropped"] += 1
                return False
        self.db.kv_set("triage_pending", c["fingerprint"], {
            "c": c, "action": action, "sinks": sorted(sinks), "since": (pend or {}).get("since", now),
            "attempts": int((pend or {}).get("attempts", 0)) + 1, "nowhere": nowhere})
        return True

    def _put(self, rec: dict[str, Any]) -> None:
        self.db.triage_put(rec, fence=(_LEASE, self.owner), now=self._now())

    def run_once(self, now: float | None = None) -> dict[str, Any]:
        """One tick. Returns a report; safe to call from tests or a scheduler."""
        with self._lock:
            self._explicit_now = now
            now = self.clock() if now is None else now
            if not self.db.lease_acquire(_LEASE, self.owner, self.config.lease_ttl_s, now=now):
                self.role = "standby"
                self._reset_active_state()   # a successor owns the cursor now: re-read it when we are back
                self.last_tick = {"role": "standby", "at": now}
                return self.last_tick
            self.role = "active"
            self._last_renew = now
            self._load_state()
            tick: dict[str, Any] = {"role": "active", "at": now, "new_events": 0, "window_events": 0,
                                    "opened": [], "updated": [], "held": 0, "deferred": 0, "capped": 0,
                                    "dropped": 0, "backoff": 0, "skipped_recovered": 0, "errors": [],
                                    "gap_rows": 0, "backlog": False, "aborted": False}
            try:
                self._run_active(now, tick)
            except (_LeaseGone, LeaseLost):
                tick["aborted"] = True
                self.role = "standby"
                self._reset_active_state()   # nothing is committed: the successor replays from its cursor
                log.warning("triage lease lost mid-tick; aborting without committing cursors")
            tick["window_events"] = len(self._window)
            tick["candidates"] = len(tick["opened"]) + len(tick["updated"]) + tick["held"] + tick["deferred"]
            for k in ("held", "deferred", "capped", "skipped_recovered"):
                self.totals[k] += tick[k]
            self.totals["opened"] += len(tick["opened"])
            self.totals["updated"] += len(tick["updated"])
            self.totals["ticks"] += 1
            self.last_tick = tick
            return tick

    def _run_active(self, now: float, tick: dict[str, Any]) -> None:
        cfg = self.config
        fresh, backlog, gap = self._ingest(now, time.monotonic() + cfg.tick_budget_s)
        tick.update(new_events=fresh, backlog=backlog, gap_rows=gap, window_events=len(self._window))
        names = {s.name for s in self.sinks}
        pending: dict[str, dict[str, Any]] = {}
        for fp, p in self.db.kv_get_all("triage_pending").items():
            p["sinks"] = [n for n in p.get("sinks", []) if n in names]   # a removed sink is no longer owed
            if not p["sinks"] and p.get("nowhere"):
                p["sinks"] = sorted(names)   # sinks were reconfigured and nobody has this incident yet
            if not p["sinks"] or not isinstance(p.get("c"), dict):
                self.db.kv_delete("triage_pending", fp)
            elif now - float(p.get("since", now)) > cfg.pending_ttl_s:
                log.warning("triage: giving up on undelivered incident %s after %.0f h", fp, cfg.pending_ttl_s / 3600)
                self.db.kv_delete("triage_pending", fp)
            else:
                pending[fp] = p
        fresh_cands = {c["fingerprint"]: c for c in self._merge(self._candidates())} if fresh else {}
        items = [(c, pending.get(fp), False) for fp, c in fresh_cands.items()]
        items += [(p["c"], p, True) for fp, p in pending.items() if fp not in fresh_cands]
        # Critical first, so the hourly limit never spends its budget on lower severities; within a
        # severity the incident parked longest goes first, so newer ones cannot overtake it for ever.
        items.sort(key=lambda it: (SEV_RANK.get(it[0]["severity"], 5), float((it[1] or {}).get("since", now)),
                                   it[0]["fingerprint"]))
        for c, pend, orphan in items:
            if not self._still_leader():
                raise _LeaseGone()
            self._handle(c, pend, orphan, now, tick)
        if tick["dropped"]:
            log.warning("triage: dropped %d incident(s) from senders that already keep %d parked",
                        tick["dropped"], cfg.max_pending_per_sender)
        self._commit()
        if cfg.retention_days > 0 and now - self._last_prune >= 3600:
            self._last_prune = now
            pruned = self.db.triage_prune(cfg.retention_days * 86400.0, now=now)
            if pruned:
                log.info("triage: pruned %d resolved ticket row(s) older than %g day(s)", pruned, cfg.retention_days)

    def _handle(self, c: dict[str, Any], pend: dict[str, Any] | None, orphan: bool, now: float,
                tick: dict[str, Any]) -> None:
        fp = c["fingerprint"]
        rec = self.db.triage_get(fp)
        owed: set[str] | None = None            # None: every sink; else only the sinks still owed this incident
        if orphan:                              # nothing fresh in the window: deliver what is owed
            action = "update" if rec is not None else "open"
            owed = set(pend["sinks"])           # type: ignore[index]
        else:
            action = self._decide(rec, c, now)
            if action == "skip_recovered":
                if pend is not None:
                    self.db.kv_delete("triage_pending", fp)
                tick["skipped_recovered"] += 1
                return
            if action == "hold" and pend is not None:
                action = "update" if rec is not None else "open"
                owed = set(pend["sinks"])
        base = rec or {"fingerprint": fp, "first_seen": now, "last_sent": 0.0, "sends": 0, "held": 0,
                       "event_count": 0, "last_event_at": 0.0, "refs": [], "severity": c["severity"],
                       "state": c["state"]}
        if action == "hold":
            self._put({**base, "last_seen": now, "held": int(base["held"]) + 1})
            tick["held"] += 1
            return
        targets = [s for s in self.sinks if owed is None or s.name in owed]
        sender, device = self._origin(c)
        blocked = self._rate_block(now, sender, device)
        if blocked:
            tick["deferred"] += 1
            tick["capped"] += blocked != "global"
            names = [s.name for s in targets]
            if not self._park(c, action, names, pend, now, nowhere=rec is None, sender=sender):
                tick["dropped"] += 1
            return
        ready = [s for s in targets if self._sink_ready(s.name, now)]
        if not ready:                           # every owed sink is backing off: wait, do not spend the limit
            tick["backoff"] += 1
            self._park(c, action, [s.name for s in targets], pend, now, nowhere=rec is None)
            return
        payload = self._payload(c)   # RCA, evidence and remediation only for incidents being sent
        if action == "update" and c["state"] in ("recovered", "up"):
            payload.attachments["Status"] = "All affected entities have recovered; verify and close."
        results, errors, failed = self._send(payload, ready, now)
        self._note_attempt(now, sender, device)
        tick["errors"].extend(errors)
        undelivered = failed + [s.name for s in targets if s not in ready]
        if not results:
            self._park(c, action, undelivered, pend, now, nowhere=rec is None)   # all failed: retry later
            return
        refs = list(dict.fromkeys([*base.get("refs", []), *(f"{r['sink']}:{r['ref']}" for r in results)]))
        self._put({**base, "last_seen": now, "last_sent": now, "severity": c["severity"],
                   "event_count": c["count"], "last_event_at": c["latest"],
                   "sends": int(base["sends"]) + 1, "state": c["state"],
                   "title": payload.summary_title[:300], "refs": refs})
        if undelivered:                         # a sink that took it does not hide one that did not
            self._park(c, action, undelivered, pend, now)
        elif pend is not None:
            self.db.kv_delete("triage_pending", fp)
        entry = {"fingerprint": fp, "title": payload.summary_title, "severity": c["severity"],
                 "devices": payload.affected_devices, "sinks": results}
        tick["opened" if action == "open" else "updated"].append(entry)
        audit.record(f"triage.ticket.{action}", target=fp, actor=_SYSTEM_ACTOR,
                     detail={"severity": c["severity"], "devices": payload.affected_devices[:20],
                             "sinks": results, "errors": errors})

    # ── lifecycle ───────────────────────────────────────────────────────────
    def start(self) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netlog-triage", daemon=True)
        self._thread.start()
        _shutdown.register(self, "stop")   # release the lease on SIGTERM / exit instead of holding it for the TTL
        return True

    def _next_wait(self) -> float:
        """Sleep between ticks; none (a short yield) while the spool still has a backlog."""
        return 0.05 if self.last_tick.get("backlog") else self.config.poll_s

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                with audit.actor_scope(_SYSTEM_ACTOR):   # LLM calls made by the worker are attributed to it
                    self.run_once()
            except Exception:  # keep the loop alive; the next tick retries
                log.exception("triage tick failed")
            self._stop.wait(self._next_wait())

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self._thread = None
        try:
            self.db.lease_release(_LEASE, self.owner)
        except Exception as exc:
            log.warning("could not release triage lease: %s", exc)
        self.role = "idle"

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        return {"running": self.running, "role": self.role, "owner": self.owner,
                "config": dataclasses.asdict(self.config), "sinks": [s.name for s in self.sinks],
                "window_events": len(self._window), "cursors": self._cursors(),
                "last_tick": self.last_tick, "totals": dict(self.totals),
                "spool_gap_rows": {src: n for src in self._sources()
                                   if (n := self.db.spool_gap(src)["lost_unread"])},
                "pending_deliveries": len(self.db.kv_get_all("triage_pending")),
                "sink_state": {name: {"fails": int(st["fails"]),
                                      "open": st["fails"] >= self.config.sink_breaker_threshold,
                                      "retry_in_s": max(0.0, round(st["next_try"] - self.clock(), 1))}
                               for name, st in self._sink_state.items()}}


_WORKER: StreamingTriageWorker | None = None
_WORKER_LOCK = threading.Lock()


def get_worker(create: bool = True) -> StreamingTriageWorker | None:
    """Process-wide worker on the shared state DB (None without one)."""
    global _WORKER
    from ai_log_analyzer.state_store import get_state_db

    with _WORKER_LOCK:
        if _WORKER is None and create:
            db = get_state_db()
            if db is None:
                return None
            from ai_log_analyzer import rag
            _WORKER = StreamingTriageWorker(db, rag_index=rag.get_index())
        return _WORKER


def reset_worker() -> None:
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is not None:
            _WORKER.stop()
        _WORKER = None
