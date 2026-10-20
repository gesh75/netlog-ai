"""Continuous streaming triage: spool → sliding window → RCA → tickets.

The syslog listener writes every line to the SQLite WAL spool. This worker
tails that spool on its own, without waiting for anyone to upload logs to
``/api/analyze``, and on each tick:

1. reads new spool rows oldest-first from a persisted cursor (restarts
   resume, and a worker that falls behind catches up instead of skipping);
2. parses and classifies them, drops exact duplicates (relay echoes) and
   keeps a sliding window (``window_s``) of classified events;
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
  to a later tick, not dropped.

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
import socket
import threading
import time
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from ai_log_analyzer import audit
from ai_log_analyzer.classifier import ClassifiedEvent, iter_classify
from ai_log_analyzer.itsm import IncidentEnrichmentPayload
from ai_log_analyzer.parsers import registry as parser_registry
from ai_log_analyzer.sanitize import sanitize

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
    batch: int = 5000
    max_window_events: int = 20_000
    dedup_s: float = 5.0
    site: str = "default"
    use_llm: bool = False
    sources: tuple[str, ...] = ()
    lease_ttl_s: float = 60.0

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
            site=(e("AI_LOG_ANALYZER_TRIAGE_SITE", "") or "default").strip(),
            use_llm=(e("AI_LOG_ANALYZER_TRIAGE_USE_LLM", "") or "").strip().lower() in ("1", "true", "yes"),
            sources=tuple(s.strip() for s in (e("AI_LOG_ANALYZER_TRIAGE_SOURCES", "") or "").split(",")
                          if s.strip()),
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
                    "site": payload.site, "devices": list(payload.affected_devices), "markdown": body}
        r = requests.post(self.url, json=data, timeout=self.timeout_s)
        if r.status_code >= 300:
            raise RuntimeError(f"webhook answered HTTP {r.status_code}")
        return {"action": "posted", "ref": payload.fingerprint}


class _ItsmSink:
    def __init__(self, name: str, client: Any) -> None:
        self.name = name
        self.client = client

    def upsert_incident(self, payload: IncidentEnrichmentPayload) -> dict[str, Any]:
        res = self.client.upsert_incident(payload)
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
        self._recent: dict[tuple[str, str], float] = {}
        self._send_times: deque[float] = deque()
        self._retry = False   # a deferred or failed send re-evaluates next tick without new events
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

    # ── ingest ──────────────────────────────────────────────────────────────
    def _ingest(self, now: float) -> int:
        cursors = self._cursors()
        horizon = now - self.config.window_s
        fresh = 0
        for source in self._sources():
            rows = self.db.spool_read(source, cursors.get(source, 0), self.config.batch)
            if not rows:
                continue
            events, stamps = [], []
            for _id, received_at, sender, line in rows:
                if received_at < horizon:
                    continue  # backlog older than the window: nothing left to triage
                ev = parser_registry.parse(line, default_host=sender or source)
                if ev is None:
                    continue
                if sender:
                    ev = dataclasses.replace(ev, attrs={**ev.attrs, "sender_ip": sender})
                key = (ev.hostname, ev.message)
                last = self._recent.get(key)
                self._recent[key] = received_at
                if last is not None and received_at - last <= self.config.dedup_s:
                    self.totals["duplicates_dropped"] += 1
                    continue
                events.append(ev)
                stamps.append(received_at)
            for received_at, ce in zip(stamps, iter_classify(events)):
                if ce.severity in ("critical", "high", "medium") or ce.event_type:
                    self._window.append(_Windowed(received_at, ce))
                    fresh += 1
            self.db.kv_set("triage", f"cursor:{source}", int(rows[-1][0]))
            self.totals["lines_read"] += len(rows)
        while self._window and (self._window[0].received_at < horizon
                                or len(self._window) > self.config.max_window_events):
            self._window.popleft()
        self._recent = {k: t for k, t in self._recent.items() if t >= now - max(self.config.dedup_s, 1.0)}
        return fresh

    # ── evaluation ──────────────────────────────────────────────────────────
    def _candidates(self) -> list[dict[str, Any]]:
        from ai_log_analyzer.analyzer import _group_actionable
        from ai_log_analyzer.entity_state import EntityStateTracker, group_state
        from ai_log_analyzer.suppression import suppress_alerts, suppressed_entity_map

        events = [w.event for w in self._window]
        latest_group: dict[tuple[str, str], float] = {}
        latest_pair: dict[tuple[str, str], float] = {}
        for w in self._window:
            e = w.event
            k = (e.severity, e.description)
            latest_group[k] = max(latest_group.get(k, 0.0), w.received_at)
            pk = (e.description, (e.hostname or "").lower())
            latest_pair[pk] = max(latest_pair.get(pk, 0.0), w.received_at)
        vendor_of: dict[str, str] = {}
        display: dict[str, str] = {}       # lowercased host → name as logged
        category_of: dict[str, str] = {}   # description → classifier category
        iface_display: dict[str, str] = {}   # entity keys lowercase names; tickets show them as logged
        for e in events:
            if e.interface:
                iface_display.setdefault(e.interface.lower(), e.interface)
            if e.hostname:
                display.setdefault(e.hostname.lower(), e.hostname)
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
                "suppressed": g["suppressed_count"], "count": 1 + g["suppressed_count"],
                "messages": [f"{m.get('hostname', '')}: {m.get('description', '')}" for m in members[:5]],
                "state": "active", "vendor": g["root"].get("vendor") or vendor_of.get(root_host.lower(), ""),
                "root_id": g["id"], "confidence": 0.75 if g.get("inferred") else 0.9,
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
            out.append({
                "kind": "group", "severity": b["severity"], "category": b["category"],
                "description": b["description"], "summary": f"{b['description']} ({b['count']} event(s))",
                "root_device": devices[0], "layer": b["category"],
                "interface": ifaces[0] if len(ifaces) == 1 else None, "devices": devices,
                "suppressed": 0, "count": b["count"],
                "messages": [m for _, _, m in sorted(b["msg_heap"], reverse=True)],
                "state": state or "active", "vendor": vendor_of.get(devices[0].lower(), ""), "confidence": 0.7,
                "latest": latest_group.get((b["severity"], b["description"]), 0.0),
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
            c0["related"].append(c["summary"])
        return list(merged.values())

    def _rate_ok(self, now: float) -> bool:
        while self._send_times and self._send_times[0] < now - 3600:
            self._send_times.popleft()
        return len(self._send_times) < self.config.max_tickets_per_hour

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

    def _send(self, payload: IncidentEnrichmentPayload) -> tuple[list[dict[str, Any]], list[str]]:
        results, errors = [], []
        for sink in self.sinks:
            try:
                res = sink.upsert_incident(payload)
                results.append({"sink": sink.name, "action": res.get("action", ""), "ref": str(res.get("ref", ""))})
            except Exception as exc:  # network / HTTP / auth errors must not stop the loop
                errors.append(f"{sink.name}: {str(exc)[:200]}")
        return results, errors

    def run_once(self, now: float | None = None) -> dict[str, Any]:
        """One tick. Returns a report; safe to call from tests or a scheduler."""
        with self._lock:
            now = self.clock() if now is None else now
            if not self.db.lease_acquire(_LEASE, self.owner, self.config.lease_ttl_s, now=now):
                self.role = "standby"
                self.last_tick = {"role": "standby", "at": now}
                return self.last_tick
            self.role = "active"
            fresh = self._ingest(now)
            tick: dict[str, Any] = {"role": "active", "at": now, "new_events": fresh,
                                    "window_events": len(self._window), "opened": [], "updated": [],
                                    "held": 0, "deferred": 0, "skipped_recovered": 0, "errors": []}
            if fresh or self._retry:
                self._retry = False
                for c in self._merge(self._candidates()):
                    self._handle(c, now, tick)
                self._retry = bool(tick["deferred"]) or bool(tick["errors"])
            tick["candidates"] = len(tick["opened"]) + len(tick["updated"]) + tick["held"] + tick["deferred"]
            for k in ("held", "deferred", "skipped_recovered"):
                self.totals[k] += tick[k]
            self.totals["opened"] += len(tick["opened"])
            self.totals["updated"] += len(tick["updated"])
            self.totals["ticks"] += 1
            self.last_tick = tick
            return tick

    def _handle(self, c: dict[str, Any], now: float, tick: dict[str, Any]) -> None:
        fp = c["fingerprint"]
        rec = self.db.triage_get(fp)
        action = self._decide(rec, c, now)
        if action == "skip_recovered":
            tick["skipped_recovered"] += 1
            return
        base = rec or {"fingerprint": fp, "first_seen": now, "last_sent": 0.0, "sends": 0, "held": 0,
                       "event_count": 0, "last_event_at": 0.0, "refs": [], "severity": c["severity"],
                       "state": c["state"]}
        if action == "hold":
            self.db.triage_put({**base, "last_seen": now, "held": int(base["held"]) + 1})
            tick["held"] += 1
            return
        if not self._rate_ok(now):
            tick["deferred"] += 1
            return
        payload = self._payload(c)   # RCA, evidence and remediation only for incidents being sent
        if action == "update" and c["state"] in ("recovered", "up"):
            payload.attachments["Status"] = "All affected entities have recovered; verify and close."
        results, errors = self._send(payload)
        tick["errors"].extend(errors)
        if not results:
            return  # every sink failed: keep the old state so the next tick retries
        self._send_times.append(now)
        refs = list(dict.fromkeys([*base.get("refs", []), *(f"{r['sink']}:{r['ref']}" for r in results)]))
        self.db.triage_put({**base, "last_seen": now, "last_sent": now, "severity": c["severity"],
                            "event_count": c["count"], "last_event_at": c["latest"],
                            "sends": int(base["sends"]) + 1, "state": c["state"],
                            "title": payload.summary_title[:300], "refs": refs})
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
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                with audit.actor_scope(_SYSTEM_ACTOR):   # LLM calls made by the worker are attributed to it
                    self.run_once()
            except Exception:  # keep the loop alive; the next tick retries
                log.exception("triage tick failed")
            self._stop.wait(self.config.poll_s)

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
                "last_tick": self.last_tick, "totals": dict(self.totals)}


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
