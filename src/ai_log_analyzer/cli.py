"""CLI entrypoint — `ai-log-analyzer serve` or `ai-log-analyzer analyze <container>`."""
from __future__ import annotations

import argparse
import itertools
import json
import sys

from ai_log_analyzer.adapters import frr
from ai_log_analyzer.adapters.file import parse_file, parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources import SourceError, registry
from ai_log_analyzer.sources.manager import SourceManager
from ai_log_analyzer.web.app import main as serve_main


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
    streams: list = []
    if args.frr:
        for c in args.frr:
            streams.append(frr.frr_docker_logs(c, tail=args.tail))
    if args.file:
        for path in args.file:
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

    result = analyze(
        itertools.chain([first], event_iter),
        use_llm=not args.no_llm,
        dedup=getattr(args, "dedup", False),
        evpn_causal=getattr(args, "evpn_causal", False) or None,
    )
    res_dict = result.to_dict()
    if getattr(args, "remediation", False):
        from ai_log_analyzer.remediation import RemediationGenerator, VendorOS

        gen = RemediationGenerator()
        plans = []
        for item in res_dict.get("action_items", [])[:3]:
            for dev in item.get("devices", [])[:2]:
                try:
                    p = gen.build_graceful_link_drain(
                        device=dev,
                        vendor=VendorOS.ARISTA_EOS,
                        interface="Ethernet1",
                        rationale=f"Auto-generated remediation for {item.get('description', 'incident')}",
                    )
                    plans.append(p.to_dict())
                except Exception:
                    pass
        res_dict["remediation_plans"] = plans
    print(json.dumps(res_dict, indent=2))
    return 0


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


def cmd_remediation(args: argparse.Namespace) -> int:
    """Generate vendor-safe remediation plan with automatic rollback timer."""
    from ai_log_analyzer.remediation import (
        RemediationActionType,
        RemediationGenerator,
        SafetyViolationError,
        VendorOS,
    )

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
    except SafetyViolationError as exc:
        print(f"error: safety violation: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print(plan.to_markdown_card())
    return 0


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


def main() -> None:
    p = argparse.ArgumentParser(prog="ai-log-analyzer", description="AI-powered network log analyzer")
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
    ep.set_defaults(func=cmd_eval)

    rem_p = sub.add_parser("remediation", help="Generate rollback-guarded vendor CLI change plan")
    rem_p.add_argument("--device", required=True, help="Target device name")
    rem_p.add_argument(
        "--vendor",
        required=True,
        choices=["arista_eos", "juniper_junos", "cisco_nxos", "cisco_ios", "frr"],
        help="Device vendor OS",
    )
    rem_p.add_argument("--action", choices=["drain", "copp"], default="drain", help="Remediation action type")
    rem_p.add_argument("--interface", default="Ethernet1", help="Target interface name (e.g. Ethernet1, xe-0/0/0)")
    rem_p.add_argument("--bgp-neighbor", default=None, help="Optional BGP neighbor IP for drain")
    rem_p.add_argument("--rollback-minutes", type=int, default=5, help="Auto-rollback timer in minutes (1-30)")
    rem_p.add_argument("--rationale", default="", help="Engineering justification")
    rem_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    rem_p.set_defaults(func=cmd_remediation)

    mp = sub.add_parser("mcp", help="Run as an MCP server (for Claude Code / Cursor / Continue)")
    mp.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"],
                    help="MCP transport (default: stdio)")
    mp.set_defaults(func=cmd_mcp)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
