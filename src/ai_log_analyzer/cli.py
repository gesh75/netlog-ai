"""CLI entrypoint — `ai-log-analyzer serve` or `ai-log-analyzer analyze <container>`."""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from pathlib import Path

from ai_log_analyzer.adapters import frr
from ai_log_analyzer.adapters.file import parse_file, parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.deep_report import run_deep_report
from ai_log_analyzer.servicenow_sync import ServiceNowClient
from ai_log_analyzer.sources import SourceError, registry
from ai_log_analyzer.sources.manager import SourceManager

# Event vendor tag -> remediation VendorOS value (see parsers / triage_worker).
_EVENT_VENDOR_OS = {
    "frr": "frr", "paloalto": "paloalto_panos", "cisco_sdwan": "cisco_sdwan", "fortinet": "fortinet_fortios",
    "juniper": "juniper_junos", "arista": "arista_eos", "cisco_ios": "cisco_ios", "cisco_nxos": "cisco_nxos",
}


def serve_main() -> None:
    """Start the web UI (imported lazily so `--version` / `doctor` work without Flask)."""
    from ai_log_analyzer.web.app import main
    main()


def _events_from_source(kind_or_id: str, limit: int) -> list[LogEvent]:
    """Pull events for ``--source``. Matches a configured source id or kind."""
    mgr = SourceManager()
    mgr.load_from_env()
    for sid in mgr.list_ids():
        src = mgr.get(sid)
        if sid == kind_or_id or getattr(src, "kind", None) == kind_or_id:
            return mgr.fetch(sid, limit=limit)
    if registry.is_registered(kind_or_id):
        raise SourceError(
            f"source type {kind_or_id!r} is registered but not configured "
            f"(set NETLOG_SOURCE_<id>_TYPE={kind_or_id} and NETLOG_SOURCE_<id>_URL=..., "
            "or SOLARWINDS_URL / SOLARWINDS_TOKEN for solarwinds)"
        )
    raise SourceError(f"unknown source {kind_or_id!r}. Known: {registry.known()}")


def cmd_serve(_args: argparse.Namespace) -> int:
    serve_main()
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    # Chain lazy iterators — analyze() streams them, so multi-GB files run in
    # bounded memory (the web route caps size; the CLI is the big-file path).
    if (getattr(args, "snow_sync", False) and not getattr(args, "snow_dry_run", False)
            and not (os.environ.get("SERVICENOW_URL") or os.environ.get("SNOW_URL"))):
        print("error: --snow-sync needs SERVICENOW_URL (or SNOW_URL); "
              "use --snow-dry-run to preview the payload without a ServiceNow instance", file=sys.stderr)
        return 2
    streams: list = []
    if args.frr:
        for c in args.frr:
            streams.append(frr.frr_docker_logs(c, tail=args.tail))
    if args.file:
        for path in args.file:
            if not Path(path).is_file():
                reason = "is a directory" if Path(path).is_dir() else "no such file"
                print(f"error: cannot read {path}: {reason}", file=sys.stderr)
                return 2
            streams.append(parse_file(path))
    if args.stdin:
        streams.append(parse_lines(sys.stdin.readlines()))
    source = getattr(args, "source", None)
    if source:
        try:
            streams.append(_events_from_source(source, limit=getattr(args, "tail", 100) or 100))
        except SourceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    event_iter = itertools.chain.from_iterable(streams)
    try:
        first = next(event_iter)
    except StopIteration:
        print("error: no input — pass --frr, --file, --stdin, or --source", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    want_deep = bool(
        getattr(args, "deep_analytics", False)
        or getattr(args, "snow_changes_file", None)
        or getattr(args, "snow_sync", False)
        or getattr(args, "snow_dry_run", False)
    )
    want_remediation = bool(getattr(args, "remediation", False))
    if want_deep or want_remediation:   # both need a second look at the events
        try:
            events = [first, *event_iter]
        except OSError as exc:
            print(f"error: cannot read input: {exc}", file=sys.stderr)
            return 2
        source = iter(events)
    else:
        events = None
        source = itertools.chain([first], event_iter)
    try:
        result = analyze(
            source,
            use_llm=not args.no_llm,
            dedup=getattr(args, "dedup", False),
            evpn_causal=getattr(args, "evpn_causal", False) or None,
        )
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2
    res_dict = result.to_dict()
    if want_deep and events is not None:
        attached = _attach_deep_analytics(args, events)
        if attached is None:
            return 2
        res_dict.update(attached)
    if want_remediation and events is not None:
        plans, skipped = _remediation_plans(res_dict, events)
        res_dict["remediation_plans"] = plans
        if skipped:
            res_dict["remediation_skipped"] = skipped
            for sk in skipped:
                print(f"warning: no remediation plan for {sk['device']}: {sk['reason']}", file=sys.stderr)
    print(json.dumps(res_dict, indent=2))
    return 0


def _remediation_plans(res_dict: dict, events: list) -> tuple[list[dict], list[dict[str, str]]]:
    """Graceful-drain plans for the top action items, with vendor and interface taken from the
    events themselves. Devices whose vendor or interface cannot be determined, or whose plan is
    refused, are reported (not guessed, not silently dropped)."""
    from ai_log_analyzer.classifier import iter_classify
    from ai_log_analyzer.remediation import RemediationGenerator, VendorOS

    vendor_of: dict[str, str] = {}
    iface_of: dict[tuple[str, str], str] = {}     # (host, description) -> interface as logged
    for e in iter_classify(iter(events)):
        host = (e.hostname or "").lower()
        if e.vendor:
            vendor_of.setdefault(host, e.vendor)
        if e.interface:
            iface_of.setdefault((host, e.description), e.interface)
    gen = RemediationGenerator()
    plans: list[dict] = []
    skipped: list[dict[str, str]] = []
    for item in res_dict.get("action_items", [])[:3]:
        for dev in item.get("devices", [])[:2]:
            host = dev.lower()
            vos = _EVENT_VENDOR_OS.get(vendor_of.get(host, ""))
            intf = iface_of.get((host, item.get("description")))
            if not vos:
                skipped.append({"device": dev, "reason": "vendor not identified from the events"})
                continue
            if not intf:
                skipped.append({"device": dev, "reason": "no interface named in the events for this alert"})
                continue
            try:
                plans.append(gen.build_graceful_link_drain(
                    device=dev, vendor=VendorOS(vos), interface=intf,
                    rationale=f"Auto-generated remediation for {item.get('description', 'incident')}",
                ).to_dict())
            except ValueError as exc:      # SafetyViolationError / PlanInputError
                skipped.append({"device": dev, "reason": str(exc)})
    return plans, skipped


def _attach_deep_analytics(args: argparse.Namespace, events: list) -> dict | None:
    """Return JSON keys for deep analytics and optional ServiceNow sync."""
    changes: list = []
    path = getattr(args, "snow_changes_file", "") or ""
    if path:
        try:
            loaded = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: snow changes file: {exc}", file=sys.stderr)
            return None
        if not isinstance(loaded, list):
            print("error: snow changes file must be a JSON array", file=sys.stderr)
            return None
        changes = loaded
    bundle = run_deep_report(events=events, changes=changes)
    out: dict = {}
    if getattr(args, "deep_analytics", False) or changes:
        out["deep_analytics"] = bundle.payload
    if getattr(args, "snow_sync", False) or getattr(args, "snow_dry_run", False):
        instance = os.environ.get("SERVICENOW_URL") or os.environ.get("SNOW_URL") or ""
        dry_run = bool(getattr(args, "snow_dry_run", False))
        if not dry_run and not instance:
            print("error: --snow-sync needs SERVICENOW_URL (or SNOW_URL); "
                  "use --snow-dry-run to preview the payload without a ServiceNow instance", file=sys.stderr)
            return None
        client = ServiceNowClient(
            instance_url=instance,
            username=os.environ.get("SERVICENOW_USER") or os.environ.get("SNOW_USER") or "",
            password=os.environ.get("SERVICENOW_PASSWORD") or os.environ.get("SNOW_PASSWORD") or "",
            bearer_token=os.environ.get("SERVICENOW_TOKEN") or "",
        )
        synced = client.sync_incident(
            bundle.summary,
            blast_radius=bundle.blast,
            change_report=bundle.changes,
            flap_report=bundle.flap,
            dry_run=dry_run,
        )
        out["servicenow_sync"] = synced.to_dict()
        if "deep_analytics" not in out:
            out["deep_analytics"] = bundle.payload
    return out


def cmd_containers(_args: argparse.Namespace) -> int:
    for name in frr.list_lab_containers():
        print(name)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Zero-setup demo: analyze a deterministic synthetic incident storyline.

    --serve additionally starts the web UI with a local syslog listener and a
    feeder thread replaying the storyline, so the Live Tail panel streams
    events in real time — no lab or devices needed.
    """
    import os

    from ai_log_analyzer.adapters.file import parse_lines
    from ai_log_analyzer.demo import generate_demo_lines, start_udp_feeder

    lines = generate_demo_lines()
    result = analyze(parse_lines(lines), use_llm=args.llm)

    d = result.to_dict()
    print(f"Demo storyline : {len(lines)} synthetic log lines, 6 devices, 4 vendor dialects")
    print(f"Health score   : {d['score']}/100 (grade {d['grade']} — {d['grade_label']})")
    print(f"Fabric stability: {d['stability']['fabric_score']}/100")
    print()
    print("Executive summary:")
    for b in d["executive_summary"]:
        print(f"  • {b}")
    print()
    print("Top action items:")
    for a in d["action_items"][:5]:
        devs = ", ".join(a["devices"][:3])
        print(f"  [{a['severity'].upper():8}] {a['description']} ({a['count']}× on {devs})")
    up = d["unknown_patterns"]
    if up["top_templates"]:
        print()
        print(f"Unknown patterns ({up['template_count']} templates from {up['total_unclassified']} unmatched lines):")
        for t in up["top_templates"][:3]:
            flag = "⚠ " if t["severity_hint"] != "info" else "  "
            print(f"  {flag}{t['count']:>3}× {t['template'][:90]}")

    if not args.serve:
        print("\nRun `ai-log-analyzer demo --serve` to watch this stream live in the UI.")
        return 0

    port = int(os.environ.get("NETLOG_DEMO_SYSLOG_PORT", "5514"))
    os.environ.setdefault("NETLOG_SOURCE_demo_TYPE", "syslog")
    os.environ.setdefault("NETLOG_SOURCE_demo_URL", "udp://127.0.0.1")
    os.environ.setdefault("NETLOG_SOURCE_demo_PORT", str(port))
    os.environ.setdefault("NETLOG_SOURCE_demo_BIND", "127.0.0.1")
    start_udp_feeder(port)
    print(f"\nDemo feeder streaming to udp://127.0.0.1:{port} — open the UI,")
    print("expand '🔴 Live Tail' in the Logs tab, pick source 'demo', press Start.")
    serve_main()
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Score playbook quality with the LLM-as-Judge harness.

    Default: self-test every rule-based KB playbook (the quality floor with
    the LLM off). --file scores a saved /api/analyze JSON result instead.
    --min-score turns the run into a CI gate (exit 1 below threshold).
    """
    from ai_log_analyzer import judge

    if args.golden:
        return _cmd_eval_golden(args)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                result = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
        report = judge.judge_analysis_result(result, use_llm=args.use_llm)
    else:
        report = judge.judge_kb(use_llm=args.use_llm)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Playbooks scored : {report['playbooks_scored']}")
        print(f"Overall quality  : {report['overall']}/10")
        print()
        for v in report["verdicts"][: args.show]:
            s = v["scores"]
            label = v.get("description") or v.get("category", "")
            print(f"  {s['overall']:>4}/10  [{v.get('judge')}] {label[:70]}")
            print(f"          action={s['actionability']} safety={s['safety']} "
                  f"grounding={s['grounding']} complete={s['completeness']}")
            for note in v.get("notes", [])[:2]:
                print(f"          ! {note}")

    if args.min_score and report["overall"] < args.min_score:
        print(f"\nFAIL: overall {report['overall']} < required {args.min_score}",
              file=sys.stderr)
        return 1
    return 0


def _cmd_eval_golden(args: argparse.Namespace) -> int:
    """Replay the labeled golden incidents and score RCA accuracy,
    de-tokenization, guardrail compliance and evidence (0-1 each)."""
    from ai_log_analyzer import judge

    report = judge.run_eval(judge.load_cases(args.cases))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Golden incidents : {report['cases']}")
        print("Scores           : " + "  ".join(f"{k}={v:.2f}" for k, v in report["scores"].items()))
        print()
        for r in report["results"]:
            s = r["scores"]
            print(f"  {s['overall']:.2f}  {r['id']}  (top item: {r['top_item']}; "
                  f"playbook {r['playbook_quality']}/10)")
            for note in r["notes"][:4]:
                print(f"        ! {note}")
    overall = report["scores"].get("overall", 0.0)
    if args.min_golden and overall < args.min_golden:
        print(f"\nFAIL: golden overall {overall} < required {args.min_golden}", file=sys.stderr)
        return 1
    return 0


def cmd_rag(args: argparse.Namespace) -> int:
    """Build or query the local retrieval index (configs, drift, topology, runbooks, incidents)."""
    from ai_log_analyzer import rag
    from ai_log_analyzer.state_store import open_db

    if args.rag_cmd == "drift":
        with open(args.running, encoding="utf-8") as fh_r, open(args.golden_file, encoding="utf-8") as fh_g:
            print(json.dumps(rag.config_drift(fh_r.read(), fh_g.read()), indent=2))
        return 0
    index = rag.RagIndex(open_db(args.db)) if args.db else rag.get_index()
    if index is None:
        print("error: no index — pass --db or set AI_LOG_ANALYZER_RAG_DB / AI_LOG_ANALYZER_STATE_DB",
              file=sys.stderr)
        return 2
    if args.rag_cmd == "index":
        sites = args.sites or os.environ.get("AI_LOG_ANALYZER_SITES_DIR", "") or \
            str(Path(__file__).resolve().parent / "data" / "sites")
        golden = args.golden or os.environ.get("AI_LOG_ANALYZER_GOLDEN_DIR", "") or None
        report = rag.build_default_index(index, sites_dir=sites, golden_dir=golden, netbox=args.netbox)
        print(json.dumps(report, indent=2))
        return 0
    if args.rag_cmd == "search":
        hosts = [h for h in (args.hosts or "").split(",") if h]
        hits = index.search(args.query, k=args.k, hosts=hosts)
        if args.json:
            print(json.dumps(hits, indent=2))
        else:
            for h in hits:
                print(f"{h['score']:>7.2f}  {h['citation']}")
        return 0
    print(json.dumps(index.stats(), indent=2))
    return 0


def cmd_triage_worker(args: argparse.Namespace) -> int:
    """Run the streaming triage loop in the foreground (systemd / container entrypoint)."""
    from ai_log_analyzer import rag
    from ai_log_analyzer.state_store import get_state_db
    from ai_log_analyzer.triage_worker import StreamingTriageWorker

    db = get_state_db()
    if db is None:
        print("error: AI_LOG_ANALYZER_STATE_DB must point at the syslog spool database", file=sys.stderr)
        return 2
    worker = StreamingTriageWorker(db, rag_index=rag.get_index())
    if args.once:
        print(json.dumps(worker.run_once(), indent=2, default=str))
        return 0
    worker.start()
    try:
        while worker.running:
            worker._thread.join(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
    return 0


def cmd_remediation(args: argparse.Namespace) -> int:
    """Generate vendor-safe remediation plan with automatic rollback timer."""
    from ai_log_analyzer.remediation import (
        PlanInputError,
        RemediationActionType,
        RemediationGenerator,
        SafetyGuardrail,
        SafetyViolationError,
        VendorOS,
    )

    fmt_arg = getattr(args, "format", None)
    if getattr(args, "json", False) and fmt_arg in ("ansible", "nornir"):
        print(f"error: --json cannot be combined with --format {fmt_arg}; use one of them", file=sys.stderr)
        return 2
    lo, hi = SafetyGuardrail.MIN_ROLLBACK_MINUTES, SafetyGuardrail.MAX_ROLLBACK_MINUTES
    if not isinstance(args.rollback_minutes, int) or not lo <= args.rollback_minutes <= hi:
        print(f"error: --rollback-minutes must be an integer from {lo} to {hi}", file=sys.stderr)
        return 2
    try:
        vendor = VendorOS(args.vendor)
    except ValueError:
        valid_vendors = ", ".join(v.value for v in VendorOS)
        print(f"error: unknown vendor {args.vendor!r}. Choose from: {valid_vendors}", file=sys.stderr)
        return 2

    gen = RemediationGenerator(default_rollback_minutes=args.rollback_minutes)
    try:
        if args.action in ("drain", RemediationActionType.GRACEFUL_LINK_DRAIN.value):
            plan = gen.build_graceful_link_drain(
                device=args.device,
                vendor=vendor,
                interface=args.interface or "Ethernet1",
                bgp_neighbor_ip=args.bgp_neighbor,
                rollback_minutes=args.rollback_minutes,
                rationale=args.rationale or "Drain traffic gracefully prior to physical maintenance.",
            )
        elif args.action in ("copp", RemediationActionType.QOS_COPP_CONTROL_PLANE_BOOST.value):
            plan = gen.build_qos_copp_remediation(
                device=args.device,
                vendor=vendor,
                interface=args.interface or "Ethernet1",
                rollback_minutes=args.rollback_minutes,
                rationale=args.rationale or "Prioritize control plane traffic.",
            )
        else:
            print(f"error: unsupported action {args.action!r}", file=sys.stderr)
            return 2
    except PlanInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SafetyViolationError as exc:
        print(f"error: safety violation: {exc}", file=sys.stderr)
        return 1

    fmt = "json" if args.json else (fmt_arg or "markdown")
    from ai_log_analyzer.remediation_export import ExportUnsupportedError, export_plan
    try:
        print(export_plan(plan, fmt), end="" if fmt in ("ansible", "nornir") else "\n")
    except (ExportUnsupportedError, PlanInputError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except SafetyViolationError as exc:
        print(f"error: safety violation: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Local self-check (Python, packages, writable stores, environment); no network calls."""
    from ai_log_analyzer import doctor

    checks = doctor.run_checks()
    counts = doctor.summarize(checks)
    if getattr(args, "json", False):
        print(json.dumps({"checks": checks, "summary": counts}, indent=2))
    else:
        for c in checks:
            if c["status"] != "info" or getattr(args, "verbose", False):
                print(f"[{c['status']:>4}] {c['name']}: {c['detail']}")
        print(f"\n{counts['ok']} ok, {counts['warn']} warning(s), {counts['fail']} failure(s)")
    return 1 if counts["fail"] else 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP server (stdio by default) so Claude Code / Cursor / Continue
    can call netlog-ai tools directly."""
    try:
        from ai_log_analyzer.mcp_server import run_mcp_server
    except ImportError as exc:
        print(f"error: MCP server not available — {exc}", file=sys.stderr)
        print("Install with: pip install 'netlog-ai[mcp]'", file=sys.stderr)
        return 2
    try:
        run_mcp_server(transport=args.transport)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _rollback_minutes_arg(value: str) -> int:
    from ai_log_analyzer.remediation import SafetyGuardrail
    lo, hi = SafetyGuardrail.MIN_ROLLBACK_MINUTES, SafetyGuardrail.MAX_ROLLBACK_MINUTES
    try:
        minutes = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer (expected {lo}-{hi})") from None
    if not lo <= minutes <= hi:
        raise argparse.ArgumentTypeError(f"{minutes} is out of range (expected {lo}-{hi})")
    return minutes


def main() -> None:
    from ai_log_analyzer import __version__

    p = argparse.ArgumentParser(prog="ai-log-analyzer", description="AI-powered network log analyzer")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="Run the web UI on port ANALYZER_PORT (default 6060)")
    sp.set_defaults(func=cmd_serve)

    ap = sub.add_parser("analyze", help="Analyze logs and print JSON to stdout")
    ap.add_argument("--frr", nargs="*", help="FRR docker container names")
    ap.add_argument("--file", nargs="*", help="Syslog file path(s)")
    ap.add_argument("--stdin", action="store_true", help="Read log lines from stdin")
    ap.add_argument("--tail", type=int, default=500, help="Lines per FRR container (default 500)")
    ap.add_argument("--no-llm", action="store_true", help="Skip LLM, use rule-based KB only")
    ap.add_argument(
        "--dedup",
        action="store_true",
        help="Compress repeated syslog templates before classification (off by default)",
    )
    ap.add_argument(
        "--evpn-causal",
        action="store_true",
        help="Run protocol-aware EVPN causality (off by default)",
    )
    ap.add_argument(
        "--remediation",
        action="store_true",
        help="Generate rollback-guarded remediation plans for top action items",
    )
    ap.add_argument(
        "--source",
        default=None,
        metavar="KIND|ID",
        help=(
            "Pull events from a registered connector kind or source id "
            f"(kinds: {', '.join(registry.known())}). "
            "Configure via NETLOG_SOURCE_<id>_* or, for SolarWinds, "
            "SOLARWINDS_URL, SOLARWINDS_USERNAME, SOLARWINDS_PASSWORD, "
            "SOLARWINDS_TOKEN, SOLARWINDS_MODE, SOLARWINDS_VERIFY_SSL."
        ),
    )
    ap.add_argument(
        "--deep-analytics",
        action="store_true",
        help="Attach flap physics and topology blast radius under deep_analytics",
    )
    ap.add_argument(
        "--snow-changes-file",
        default="",
        help="Offline JSON file of ServiceNow change records to correlate",
    )
    ap.add_argument(
        "--snow-sync",
        action="store_true",
        help="Create or update a ServiceNow incident (requires SERVICENOW_URL; errors if unset)",
    )
    ap.add_argument(
        "--snow-dry-run",
        action="store_true",
        help="Preview the ServiceNow incident payload without a network call",
    )
    ap.set_defaults(func=cmd_analyze)

    cp = sub.add_parser("containers", help="List running FRR lab containers")
    cp.set_defaults(func=cmd_containers)

    dp = sub.add_parser("demo", help="Zero-setup demo: synthetic incident storyline through the full pipeline")
    dp.add_argument("--serve", action="store_true", help="Also start the web UI with a live syslog feeder (Live Tail demo)")
    dp.add_argument("--llm", action="store_true", help="Use the configured LLM (default: rule-based KB, fully offline)")
    dp.set_defaults(func=cmd_demo)

    ep = sub.add_parser("eval", help="Score playbook quality (LLM-as-Judge; KB self-test by default)")
    ep.add_argument("--file", help="Saved /api/analyze JSON result to score (default: score the built-in KB)")
    ep.add_argument("--use-llm", action="store_true", help="Blend in a real LLM judge (falls back to heuristic)")
    ep.add_argument("--json", action="store_true", help="Machine-readable output")
    ep.add_argument("--show", type=int, default=10, help="Verdicts to print, worst first (default 10)")
    ep.add_argument("--min-score", type=float, default=0.0, help="Exit 1 if overall quality is below this (CI gate)")
    ep.add_argument("--golden", action="store_true",
                    help="Replay the labeled golden incidents (RCA, de-tokenization, guardrail, evidence)")
    ep.add_argument("--cases", help="Directory or JSON file of golden cases (default: bundled set)")
    ep.add_argument("--min-golden", type=float, default=0.0,
                    help="With --golden: exit 1 if the overall 0-1 score is below this")
    ep.set_defaults(func=cmd_eval)

    rp = sub.add_parser("rag", help="Local retrieval index: build, search, stats, config drift")
    rp.add_argument("--db", help="Index database (default: AI_LOG_ANALYZER_RAG_DB / AI_LOG_ANALYZER_STATE_DB)")
    rsub = rp.add_subparsers(dest="rag_cmd", required=True)
    ri = rsub.add_parser("index", help="(Re)build: KB runbooks, site configs + golden drift, NetBox, incidents")
    ri.add_argument("--sites", help="Site bundles directory (default: bundled sites / AI_LOG_ANALYZER_SITES_DIR)")
    ri.add_argument("--golden", help="Golden configs directory (<site>/<host>.txt or <host>.txt)")
    ri.add_argument("--netbox", action="store_true", help="Also index NetBox devices and cables")
    rs = rsub.add_parser("search", help="BM25 search with citations")
    rs.add_argument("query")
    rs.add_argument("--hosts", help="Comma-separated devices to boost")
    rs.add_argument("-k", type=int, default=8)
    rs.add_argument("--json", action="store_true")
    rsub.add_parser("stats", help="Document counts per kind and source")
    rd = rsub.add_parser("drift", help="Diff a running config against its golden config")
    rd.add_argument("running")
    rd.add_argument("golden_file")
    rp.set_defaults(func=cmd_rag)

    tw = sub.add_parser("triage-worker", help="Run the streaming triage loop over the syslog spool")
    tw.add_argument("--once", action="store_true", help="Run one tick and print its report")
    tw.set_defaults(func=cmd_triage_worker)

    rem_p = sub.add_parser("remediation", help="Generate rollback-guarded vendor CLI change plan")
    rem_p.add_argument("--device", required=True, help="Target device name")
    rem_p.add_argument(
        "--vendor",
        required=True,
        choices=["arista_eos", "juniper_junos", "cisco_nxos", "cisco_ios", "frr",
                 "fortinet_fortios", "paloalto_panos", "cisco_sdwan"],
        help="Device vendor OS",
    )
    rem_p.add_argument("--action", choices=["drain", "copp"], default="drain", help="Remediation action type")
    rem_p.add_argument("--interface", default="Ethernet1", help="Target interface name (e.g. Ethernet1, xe-0/0/0)")
    rem_p.add_argument("--bgp-neighbor", default=None, help="Optional BGP neighbor IP for drain")
    rem_p.add_argument("--rollback-minutes", type=_rollback_minutes_arg, default=5,
                       help="Rollback timer in minutes (1-30). Only Junos, IOS-XE and EOS revert automatically; "
                            "other platforms get manual rollback commands")
    rem_p.add_argument("--rationale", default="", help="Engineering justification")
    rem_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    rem_p.add_argument("--format", choices=["markdown", "json", "ansible", "nornir"], default=None,
                       help="Export as CLI card (markdown, default), JSON, an Ansible playbook, or a Nornir/NAPALM "
                            "script (not combinable with --json)")
    rem_p.set_defaults(func=cmd_remediation)

    dr = sub.add_parser("doctor", help="Local self-check: Python, packages, writable stores, environment (no network)")
    dr.add_argument("--json", action="store_true", help="Machine-readable output")
    dr.add_argument("-v", "--verbose", action="store_true", help="Also list optional features that are not configured")
    dr.set_defaults(func=cmd_doctor)

    mp = sub.add_parser("mcp", help="Run as an MCP server (for Claude Code / Cursor / Continue)")
    mp.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"],
                    help="MCP transport (default: stdio)")
    mp.set_defaults(func=cmd_mcp)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
