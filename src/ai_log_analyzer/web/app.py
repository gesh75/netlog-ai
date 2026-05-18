"""Flask app: ingests FRR / file logs, runs analyzer, exposes /api/analyze + UI."""
from __future__ import annotations

import os
from pathlib import Path

# Auto-load env from (in priority order): local .env, ~/.env, sibling DCN_Network_Tool .env.
# Loaded BEFORE any other ai_log_analyzer imports so llm.py picks up the keys.
try:
    from dotenv import load_dotenv
    _here = Path(__file__).resolve().parents[3]  # AI_Log_Analyzer/
    _candidates = [
        _here / ".env",
        Path.home() / ".env",
        _here.parent / "DCN_Network_Tool" / ".env",
        _here.parent / "DCN_AI_Intelligence" / ".env",
    ]
    for _p in _candidates:
        if _p.is_file():
            load_dotenv(_p, override=False)
except ImportError:
    pass

from functools import wraps  # noqa: E402

from flask import Flask, abort, jsonify, request, send_from_directory  # noqa: E402
from flask_cors import CORS  # noqa: E402

from ai_log_analyzer import llm  # noqa: E402
from ai_log_analyzer.adapters import frr, network_tool  # noqa: E402
from ai_log_analyzer.adapters.file import parse_lines  # noqa: E402
from ai_log_analyzer.analyzer import analyze, analyze_site, optimize_config  # noqa: E402
from ai_log_analyzer.classifier import LogEvent  # noqa: E402
from ai_log_analyzer import (compliance as comp_engine, copilot, diff as diff_mod,  # noqa: E402
                              postmortem, reports, runbook, site_doc,
                              site_optimize, topology as topo_mod)
from ai_log_analyzer.sources import SourceConfig, SourceError, registry  # noqa: E402
from ai_log_analyzer.sources.manager import manager as source_manager  # noqa: E402

STATIC_DIR = Path(__file__).parent / "static"
SAMPLES_DIR = Path(__file__).resolve().parents[3] / "samples"
SITES_DIR = Path(__file__).resolve().parents[3] / "sites"


# ── Security helpers ─────────────────────────────────────────────────────────

API_TOKEN: str = os.environ.get("AI_LOG_ANALYZER_API_TOKEN", "")


class BadCommand(ValueError):
    """Raised when /api/run receives a command we won't translate to argv."""


def require_api_token(fn):
    """Require X-API-Token header when AI_LOG_ANALYZER_API_TOKEN is set.

    When the env var is empty (dev mode + bound to 127.0.0.1) this decorator
    is a no-op. Once set, every mutating route must present the token.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not API_TOKEN:
            return fn(*args, **kwargs)
        supplied = request.headers.get("X-API-Token", "")
        if supplied != API_TOKEN:
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


def _parse_bool(value, default: bool = False) -> bool:
    """Strict boolean coercion — `"false"` becomes False, not True."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _load_site_devices(safe_site_id: str) -> tuple[list[dict] | None, dict | None]:
    """Helper: load all devices in a site bundle. Returns (devices, manifest)
    or (None, None) if the bundle is missing."""
    site_dir = SITES_DIR / safe_site_id
    manifest_path = site_dir / "manifest.json"
    if not manifest_path.is_file():
        return None, None
    import json as _json
    try:
        manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError:
        return None, None
    devices: list[dict] = []
    for d in manifest.get("devices", []):
        fpath = site_dir / d["file"]
        if not fpath.is_file():
            continue
        devices.append({
            "hostname": d.get("hostname", fpath.stem),
            "function": d.get("function", "unknown"),
            "platform": d.get("platform") or manifest.get("vendor", "junos").lower().split(" ")[0],
            "config_text": fpath.read_text(encoding="utf-8", errors="replace"),
        })
    return devices, manifest


def _parse_frr_command(raw: str) -> list[str]:
    """Convert a user-typed CLI string into argv for `docker exec`.

    Common forms we accept:
      "vtysh -c 'show ip bgp summary'"    → ["vtysh", "-c", "show ip bgp summary"]
      "show ip bgp summary"                → ["vtysh", "-c", "show ip bgp summary"]
      "ping -c 5 10.0.0.1"                 → ["ping", "-c", "5", "10.0.0.1"]
      "ip link show eth0"                   → ["ip", "link", "show", "eth0"]

    We NEVER invoke a shell — unbalanced quotes raise BadCommand instead of
    falling back to `sh -c`. The shell fallback was the only injection vector
    in this code path; rejecting the input is the safe option.
    """
    import shlex
    raw = raw.strip()
    if not raw:
        raise BadCommand("empty command")

    # `iptables` removed from the allowlist — it can rewrite firewall rules
    # inside the lab container and isn't needed for read-only diagnostics.
    known_prefixes = {
        "vtysh", "ping", "ip", "ethtool", "ss", "cat", "tail",
        "head", "grep", "ls", "dmesg", "journalctl", "uptime",
        "free", "chronyc", "ntpq", "true",
    }
    first = raw.split(None, 1)[0]
    if first in known_prefixes:
        try:
            return shlex.split(raw)
        except ValueError as exc:
            raise BadCommand(f"malformed command quoting: {exc}") from exc

    # Default: treat as a vtysh command (no shell, no fallback)
    return ["vtysh", "-c", raw]


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
    # Restrict CORS to specific origins by default. Override via
    # AI_LOG_ANALYZER_CORS_ORIGINS=https://your-host,https://other-host
    allowed_origins = [
        o.strip() for o in os.environ.get(
            "AI_LOG_ANALYZER_CORS_ORIGINS",
            "http://localhost:6060,http://127.0.0.1:6060",
        ).split(",") if o.strip()
    ]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

    # ── UI ────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(str(STATIC_DIR), "index.html")

    # ── Health + LLM control ──────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "ok": True,
            "version": "0.2.0",
            "network_tool_available": network_tool.is_available(),
        })

    @app.route("/api/llm/status", methods=["GET"])
    def llm_status():
        return jsonify(llm.get_state())

    @app.route("/api/llm/provider", methods=["POST"])
    @require_api_token
    def llm_set_provider():
        body = request.get_json(silent=True) or {}
        ok, msg = llm.set_provider(body.get("provider", ""))
        if not ok:
            return jsonify({"ok": False, "error": msg}), 400
        return jsonify({"ok": True, "provider": msg})

    @app.route("/api/llm/toggle", methods=["POST"])
    @require_api_token
    def llm_toggle():
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", True))
        return jsonify({"ok": True, "enabled": llm.set_enabled(enabled)})

    # ── Inventory ─────────────────────────────────────────────────────────
    @app.route("/api/lab/containers", methods=["GET"])
    def lab_containers():
        return jsonify({"containers": frr.list_lab_containers()})

    @app.route("/api/network-tool/devices", methods=["GET"])
    def network_tool_devices():
        return jsonify({
            "available": network_tool.is_available(),
            "devices": network_tool.list_devices(),
        })

    # ── Real-config samples (Junos / EOS production gear — sanitized) ─────
    @app.route("/api/samples", methods=["GET"])
    def api_samples():
        """List available sanitized real-device sample configs."""
        manifest_path = SAMPLES_DIR / "_manifest.json"
        if not manifest_path.is_file():
            return jsonify({"samples": [], "samples_dir": str(SAMPLES_DIR)})
        import json as _json
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError:
            manifest = []
        return jsonify({"samples": manifest, "samples_dir": str(SAMPLES_DIR)})

    # ── Site bundles (whole-site cross-device analysis) ───────────────────
    @app.route("/api/sites", methods=["GET"])
    def api_sites():
        """List available site bundles (each is a directory under sites/)."""
        if not SITES_DIR.is_dir():
            return jsonify({"sites": [], "sites_dir": str(SITES_DIR)})
        out: list[dict] = []
        for site_dir in sorted(p for p in SITES_DIR.iterdir() if p.is_dir()):
            manifest_path = site_dir / "manifest.json"
            if not manifest_path.is_file():
                continue
            import json as _json
            try:
                manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
            except _json.JSONDecodeError:
                continue
            out.append({
                "id": site_dir.name,
                "site": manifest.get("site", site_dir.name.upper()),
                "vendor": manifest.get("vendor", "unknown"),
                "device_count": len(manifest.get("devices", [])),
                "total_redactions": sum(d.get("redacted", 0) for d in manifest.get("devices", [])),
                "total_bytes": sum(d.get("sanitized_bytes", 0) for d in manifest.get("devices", [])),
                "devices": manifest.get("devices", []),
            })
        return jsonify({"sites": out, "sites_dir": str(SITES_DIR)})

    # ── Topology + diagrams ───────────────────────────────────────────────
    @app.route("/api/topology/<site_id>", methods=["GET"])
    def api_topology(site_id: str):
        """Build a topology graph from a site bundle. Optional ?findings_id=...
        to overlay severities on the nodes."""
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        devices, manifest = _load_site_devices(safe)
        if devices is None:
            return jsonify({"error": f"site bundle not found: {safe}"}), 404
        topo = topo_mod.build_topology(safe.upper(), devices)
        fmt = request.args.get("format", "json").lower()
        if fmt == "mermaid":
            return topo_mod.to_mermaid(topo), 200, {"content-type": "text/plain; charset=utf-8"}
        if fmt in ("dot", "graphviz"):
            return topo_mod.to_graphviz(topo), 200, {"content-type": "text/plain; charset=utf-8"}
        return jsonify(topo.to_dict())

    # ── Site-wide strategic optimization advisor ──────────────────────────
    @app.route("/api/optimize/site-wide/<site_id>", methods=["POST"])
    @require_api_token
    def api_optimize_site_wide(site_id: str):
        """Strategic gap analysis for the whole site.

        Different from /api/optimize/site (which finds drift / inconsistencies)
        — this asks "what does this site NEED to be production-grade?"
        Returns: maturity score, tier classification, ranked gaps, best-practices
        already applied, and a phased 30/90/180/365-day roadmap.
        """
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        devices, _ = _load_site_devices(safe)
        if devices is None:
            return jsonify({"error": f"site bundle not found: {safe}"}), 404
        # NOTE: no early-return on LLM off — site_optimize.analyze_site_wide now
        # falls back to deterministic rule-based advice automatically.
        result = site_optimize.analyze_site_wide(safe.upper(), devices)
        return jsonify(result)

    # ── Comprehensive site documentation (PEER-D-style) ─────────────────────
    @app.route("/api/sitedoc/<site_id>", methods=["GET"])
    def api_sitedoc(site_id: str):
        """Generate a comprehensive site documentation report.

        Query params:
          format: md | html | pdf   (default: md)
          llm:    0 | 1             (default: 1 — use LLM for exec summary)
          diagram: 0 | 1            (default: 1)
          compliance: 0 | 1         (default: 1)
        """
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        devices, _ = _load_site_devices(safe)
        if devices is None:
            return jsonify({"error": f"site bundle not found: {safe}"}), 404

        fmt = (request.args.get("format") or "md").lower()
        use_llm = request.args.get("llm", "1") not in ("0", "false", "no")
        include_diagram = request.args.get("diagram", "1") not in ("0", "false", "no")
        include_compliance = request.args.get("compliance", "1") not in ("0", "false", "no")

        if fmt in ("md", "markdown"):
            text = site_doc.render_site_doc(
                safe.upper(), devices,
                include_diagram=include_diagram,
                include_compliance=include_compliance,
                use_llm_summary=use_llm,
            )
            return text, 200, {"content-type": "text/markdown; charset=utf-8"}

        if fmt == "html":
            html_text = site_doc.render_site_doc_html(
                safe.upper(), devices,
                include_diagram=include_diagram,
                include_compliance=include_compliance,
                use_llm_summary=use_llm,
            )
            return html_text, 200, {"content-type": "text/html; charset=utf-8"}

        if fmt == "pdf":
            html_text = site_doc.render_site_doc_html(
                safe.upper(), devices,
                include_diagram=include_diagram,
                include_compliance=include_compliance,
                use_llm_summary=use_llm,
            )
            pdf_bytes = reports.to_pdf(html_text)
            if not pdf_bytes:
                return jsonify({
                    "error": "No PDF backend found",
                    "hint": ("Install weasyprint or wkhtmltopdf, or fetch ?format=html "
                             "and print from your browser."),
                }), 503
            from flask import Response
            return Response(
                pdf_bytes, mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={safe}-site-doc.pdf"},
            )

        return jsonify({"error": f"unknown format: {fmt}"}), 400

    # ── Compliance ────────────────────────────────────────────────────────
    @app.route("/api/compliance/<site_id>", methods=["GET"])
    def api_compliance(site_id: str):
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        devices, _ = _load_site_devices(safe)
        if devices is None:
            return jsonify({"error": f"site bundle not found: {safe}"}), 404
        return jsonify(comp_engine.check_bundle(devices))

    # ── Post-mortem fleet search ──────────────────────────────────────────
    @app.route("/api/postmortem/<site_id>", methods=["POST"])
    @require_api_token
    def api_postmortem(site_id: str):
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        body = request.get_json(silent=True) or {}
        pattern = (body.get("pattern") or "").strip()
        if not pattern:
            return jsonify({"error": "pattern required"}), 400
        devices, _ = _load_site_devices(safe)
        if devices is None:
            return jsonify({"error": f"site bundle not found: {safe}"}), 404
        return jsonify(postmortem.search_fleet(devices, pattern))

    # ── Snapshot diff ─────────────────────────────────────────────────────
    @app.route("/api/diff", methods=["POST"])
    @require_api_token
    def api_diff():
        body = request.get_json(silent=True) or {}
        before = body.get("before") or ""
        after = body.get("after") or ""
        if not before or not after:
            return jsonify({"error": "both 'before' and 'after' required"}), 400
        host = body.get("hostname", "")
        plat = body.get("platform", "junos")
        return jsonify(diff_mod.explain_diff(before, after, hostname=host, platform=plat))

    # ── AI Copilot ────────────────────────────────────────────────────────
    @app.route("/api/copilot", methods=["POST"])
    @require_api_token
    def api_copilot():
        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify({"error": "question required"}), 400
        # Source: site bundle OR single hostname OR raw config
        site_id = (body.get("site_id") or "").strip()
        hostname = (body.get("hostname") or "").strip()
        raw_cfg = body.get("config_text")
        context_blocks: list[dict] = []
        if site_id:
            safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
            devs, _ = _load_site_devices(safe)
            if devs:
                context_blocks = devs
        elif raw_cfg:
            context_blocks = [{"hostname": hostname or "device", "platform": body.get("platform", "junos"),
                               "config_text": raw_cfg}]
        if not context_blocks:
            return jsonify({"error": "no context — supply site_id or config_text"}), 400
        return jsonify(copilot.ask(question, context_blocks))

    # ── Runbook generator ─────────────────────────────────────────────────
    @app.route("/api/runbook", methods=["POST"])
    @require_api_token
    def api_runbook():
        body = request.get_json(silent=True) or {}
        finding = body.get("finding") or {}
        hostnames = body.get("hostnames") or []
        platform = (body.get("platform") or "junos").lower()
        fmt = (body.get("format") or "ansible").lower()
        if not finding:
            return jsonify({"error": "finding object required"}), 400
        if fmt == "ansible":
            text = runbook.to_ansible_playbook(finding, hostnames, platform_hint=platform)
            return text, 200, {"content-type": "text/yaml; charset=utf-8"}
        if fmt in ("python", "netmiko"):
            text = runbook.to_netmiko_script(finding, hostnames, platform_hint=platform)
            return text, 200, {"content-type": "text/x-python; charset=utf-8"}
        return jsonify({"error": f"unknown format: {fmt}"}), 400

    # ── Reports: Markdown / HTML / CSV / PDF ──────────────────────────────
    @app.route("/api/report/<site_id>", methods=["POST"])
    @require_api_token
    def api_report(site_id: str):
        body = request.get_json(silent=True) or {}
        fmt = (body.get("format") or "md").lower()
        result = body.get("analysis_result")
        if not result:
            return jsonify({"error": "analysis_result body required — POST a previous /api/optimize/site response"}), 400

        if fmt in ("md", "markdown"):
            text = reports.to_markdown_site(result) if "cross_device_findings" in result else reports.to_markdown_optimize(result)
            return text, 200, {"content-type": "text/markdown; charset=utf-8"}
        if fmt == "csv":
            return reports.to_csv_findings(result), 200, {"content-type": "text/csv; charset=utf-8"}
        if fmt == "html":
            # Embed Mermaid diagram if a site_id is provided
            mermaid = None
            if site_id:
                safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
                devs, _ = _load_site_devices(safe)
                if devs:
                    topo = topo_mod.build_topology(safe.upper(), devs)
                    topo_mod.overlay_findings(topo, result.get("cross_device_findings", []))
                    mermaid = topo_mod.to_mermaid(topo)
            return reports.to_html_site(result, mermaid_diagram=mermaid), 200, {"content-type": "text/html; charset=utf-8"}
        if fmt == "pdf":
            mermaid = None
            if site_id:
                safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
                devs, _ = _load_site_devices(safe)
                if devs:
                    topo = topo_mod.build_topology(safe.upper(), devs)
                    topo_mod.overlay_findings(topo, result.get("cross_device_findings", []))
                    mermaid = topo_mod.to_mermaid(topo)
            html_text = reports.to_html_site(result, mermaid_diagram=mermaid)
            pdf_bytes = reports.to_pdf(html_text)
            if not pdf_bytes:
                return jsonify({"error": "No PDF backend found",
                                "hint": "Install weasyprint (pip install weasyprint) or wkhtmltopdf, or use the HTML format and print from your browser."}), 503
            from flask import Response
            return Response(pdf_bytes, mimetype="application/pdf",
                            headers={"Content-Disposition": f"attachment; filename={site_id}-report.pdf"})
        return jsonify({"error": f"unknown format: {fmt}"}), 400

    @app.route("/api/optimize/site", methods=["POST"])
    @require_api_token
    def api_optimize_site():
        """Cross-device analysis on a site bundle."""
        body = request.get_json(silent=True) or {}
        site_id = (body.get("site_id") or "").strip()
        if not site_id:
            return jsonify({"error": "site_id required"}), 400
        safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
        if safe != site_id.lower():
            return jsonify({"error": "invalid site id"}), 400
        site_dir = SITES_DIR / safe
        manifest_path = site_dir / "manifest.json"
        if not manifest_path.is_file():
            return jsonify({"error": f"site bundle not found: {safe}"}), 404
        if not llm.get_state()["enabled"]:
            return jsonify({"error": "LLM is disabled — site analysis needs LLM"}), 400

        import json as _json
        manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        devices: list[dict] = []
        for d in manifest.get("devices", []):
            fpath = site_dir / d["file"]
            if not fpath.is_file():
                continue
            devices.append({
                "hostname": d.get("hostname", fpath.stem),
                "function": d.get("function", "unknown"),
                "platform": manifest.get("vendor", "junos").lower(),
                "config_text": fpath.read_text(encoding="utf-8", errors="replace"),
            })
        if not devices:
            return jsonify({"error": "no device configs found in bundle"}), 404

        result = analyze_site(safe.upper(), devices)
        result["device_count"] = len(devices)
        result["total_bytes"] = sum(len(d["config_text"]) for d in devices)
        return jsonify(result)

    @app.route("/api/samples/<sample_id>", methods=["GET"])
    def api_sample_preview(sample_id: str):
        """Return a snippet (first 200 lines) of a sample config for preview."""
        safe = "".join(c for c in sample_id if c.isalnum() or c in "-_")
        if not safe or safe != sample_id:
            return jsonify({"error": "invalid sample id"}), 400
        path = SAMPLES_DIR / f"{safe}.txt"
        if not path.is_file():
            return jsonify({"error": "sample not found"}), 404
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        return jsonify({
            "id": safe,
            "total_lines": len(lines),
            "total_chars": len(text),
            "preview": "\n".join(lines[:200]),
        })

    # ── Main analysis ─────────────────────────────────────────────────────
    @app.route("/api/analyze", methods=["POST"])
    @require_api_token
    def api_analyze():
        body = request.get_json(silent=True) or {}
        source = body.get("source", "frr")
        use_llm = _parse_bool(body.get("use_llm"), default=True)
        try:
            tail = max(1, min(10000, int(body.get("tail") or 500)))
        except (TypeError, ValueError):
            tail = 500
        events: list[LogEvent] = []

        if source == "frr":
            containers = body.get("containers") or frr.list_lab_containers()
            if not containers:
                return jsonify({"error": "No FRR containers found running"}), 404
            for c in containers:
                try:
                    events.extend(frr.frr_docker_logs(c, tail=tail))
                except Exception as e:
                    app.logger.warning("Failed to read logs for %s: %s", c, e)

        elif source == "raw":
            text = body.get("text", "")
            host = body.get("hostname", "")
            events = list(parse_lines(text.splitlines(), default_host=host))

        elif source == "file":
            path = body.get("path", "")
            if not path or not Path(path).is_file():
                return jsonify({"error": f"File not found: {path}"}), 404
            from ai_log_analyzer.adapters.file import parse_file
            events = list(parse_file(path))

        else:
            return jsonify({"error": f"Unknown source: {source}"}), 400

        if not events:
            return jsonify({"error": "No events ingested from source"}), 404

        result = analyze(events, use_llm=use_llm)
        return jsonify(result.to_dict())

    # ── Live CLI execution: DCN_Network_Tool SSH first, docker-exec fallback ──
    @app.route("/api/run", methods=["POST"])
    @require_api_token
    def api_run():
        """Execute a CLI command on a lab device.

        Path 1: POST through DCN_Network_Tool SSH proxy at :5757.
        Path 2 (fallback): `docker exec <container>` directly — used for FRR
        lab containers when SSH proxy is unavailable or errors out.
        """
        body = request.get_json(silent=True) or {}
        hostname = (body.get("hostname") or "").strip()
        command = (body.get("command") or body.get("raw") or "").strip()
        if not hostname or not command:
            return jsonify({"error": "hostname and command are required"}), 400

        # Try SSH proxy first
        if network_tool.is_available(timeout=1.0):
            result = network_tool.run_command(hostname, command)
            if result.ok:
                return jsonify(result.to_dict())
            # SSH failed — fall through to docker exec if it's a lab container

        # docker-exec fallback for FRR lab containers
        if hostname in frr.list_lab_containers():
            try:
                container_cmd = _parse_frr_command(command)
            except BadCommand as exc:
                return jsonify({"error": str(exc)}), 400
            result = network_tool.container_run(hostname, container_cmd)
            d = result.to_dict()
            d["transport"] = "docker-exec"
            return jsonify(d)

        return jsonify({
            "error": "Could not execute — SSH proxy down and not a FRR lab container",
            "hint": "Fix DCN_Network_Tool SSH key path or use a known lab container name",
        }), 503

    # ── Config-aware Optimization (LLM killer feature) ────────────────────
    @app.route("/api/optimize", methods=["POST"])
    @require_api_token
    def api_optimize():
        """Pull running config from a device and ask LLM for resilience improvements."""
        body = request.get_json(silent=True) or {}
        hostname = (body.get("hostname") or "").strip()
        platform = (body.get("platform") or "frr").lower()
        recent_events = body.get("recent_events") or []
        config_override = body.get("running_config")  # caller may supply config directly
        sample_id = (body.get("sample_id") or "").strip()

        # Sample-id mode: load config from the sanitized samples directory
        if sample_id:
            safe = "".join(c for c in sample_id if c.isalnum() or c in "-_")
            if safe != sample_id:
                return jsonify({"error": "invalid sample id"}), 400
            path = SAMPLES_DIR / f"{safe}.txt"
            if not path.is_file():
                return jsonify({"error": f"sample not found: {safe}"}), 404
            config_override = path.read_text(encoding="utf-8", errors="replace")
            # Pull platform + hostname hints from the manifest if not provided
            manifest_path = SAMPLES_DIR / "_manifest.json"
            if manifest_path.is_file():
                import json as _json
                try:
                    items = _json.loads(manifest_path.read_text(encoding="utf-8"))
                    match = next((i for i in items if i.get("id") == safe), None)
                    if match:
                        if not body.get("platform"):
                            platform = match.get("platform", platform)
                        if not hostname:
                            hostname = match.get("id", safe)
                except _json.JSONDecodeError:
                    pass

        if not hostname:
            return jsonify({"error": "hostname or sample_id required"}), 400

        running_config = config_override
        if not running_config:
            # fetch_running_config() tries DCN_Network_Tool first, then falls
            # back to `docker exec` for FRR lab containers. Don't 503 here
            # just because the SSH proxy is down — let the FRR fallback run.
            running_config = network_tool.fetch_running_config(hostname, platform=platform)
            if not running_config:
                return jsonify({
                    "error": f"Could not fetch running config from {hostname}",
                    "hint": ("Provide 'running_config' in the body, or start "
                             "DCN_Network_Tool at :5757 / use a FRR lab container."),
                }), 502

        if not llm.get_state()["enabled"]:
            return jsonify({"error": "LLM is disabled — optimization needs LLM",
                            "hint": "POST /api/llm/toggle with {\"enabled\": true}"}), 400

        result = optimize_config(
            hostname=hostname,
            platform=platform,
            running_config=running_config,
            recent_events=recent_events,
        )
        result["hostname"] = hostname
        result["platform"] = platform
        result["config_length"] = len(running_config)
        return jsonify(result)

    # ── External log sources (Kibana, Splunk, Loki, syslog, LibreNMS, ...) ────
    @app.route("/api/sources", methods=["GET"])
    def api_sources_list():
        """List configured sources + the connector kinds the registry knows."""
        return jsonify({
            "sources": source_manager.describe(),
            "known_kinds": source_manager.known_kinds(),
        })

    @app.route("/api/sources", methods=["POST"])
    @require_api_token
    def api_sources_add():
        """Register a new source. Body: {id, type, url, api_token?, username?,
        password?, auth_methods?, extra?, verify_tls?, timeout_seconds?}."""
        body = request.get_json(silent=True) or {}
        src_id = (body.get("id") or "").strip()
        stype = (body.get("type") or "").strip()
        url = (body.get("url") or "").strip()
        if not src_id or not stype or not url:
            return jsonify({"ok": False, "error": "id, type, url are required"}), 400
        if not registry.is_registered(stype):
            return jsonify({"ok": False, "error": f"unknown type {stype!r}",
                            "known": source_manager.known_kinds()}), 400
        try:
            auth_methods = tuple(body.get("auth_methods") or ())
            cfg = SourceConfig(
                id=src_id,
                type=stype,
                url=url,
                auth_methods=auth_methods,
                api_token=body.get("api_token", ""),
                username=body.get("username", ""),
                password=body.get("password", ""),
                cookies=dict(body.get("cookies") or {}),
                extra={str(k): str(v) for k, v in (body.get("extra") or {}).items()},
                verify_tls=_parse_bool(body.get("verify_tls", True), default=True),
                timeout_seconds=float(body.get("timeout_seconds", 30.0)),
            )
            source_manager.add(cfg)
        except SourceError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except (TypeError, ValueError) as exc:
            return jsonify({"ok": False, "error": f"bad config: {exc}"}), 400
        return jsonify({"ok": True, "id": src_id})

    @app.route("/api/sources/<source_id>", methods=["DELETE"])
    @require_api_token
    def api_sources_remove(source_id: str):
        removed = source_manager.remove(source_id)
        return jsonify({"ok": removed})

    @app.route("/api/sources/<source_id>/test", methods=["POST"])
    def api_sources_test(source_id: str):
        return jsonify(source_manager.healthcheck(source_id))

    @app.route("/api/sources/<source_id>/fetch", methods=["POST"])
    def api_sources_fetch(source_id: str):
        """Pull a batch of events from a registered source. Body:
        {since_seconds, limit, host_filter}."""
        body = request.get_json(silent=True) or {}
        try:
            events = source_manager.fetch(
                source_id,
                since_seconds=int(body.get("since_seconds", 3600)),
                limit=int(body.get("limit", 1000)),
                host_filter=str(body.get("host_filter", "")),
            )
        except SourceError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({
            "ok": True,
            "count": len(events),
            "events": [
                {
                    "timestamp": e.timestamp, "hostname": e.hostname,
                    "appname": e.appname, "severity_raw": e.severity_raw,
                    "message": e.message,
                }
                for e in events
            ],
        })

    @app.route("/api/sources/<source_id>/analyze", methods=["POST"])
    @require_api_token
    def api_sources_analyze(source_id: str):
        """Fetch + run the full analyzer (classifier → dedup → optional LLM)."""
        body = request.get_json(silent=True) or {}
        try:
            events = source_manager.fetch(
                source_id,
                since_seconds=int(body.get("since_seconds", 3600)),
                limit=int(body.get("limit", 5000)),
                host_filter=str(body.get("host_filter", "")),
            )
        except SourceError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        if not events:
            return jsonify({"ok": True, "count": 0, "result": None,
                            "message": "no events in window"})
        result = analyze(events, use_llm=_parse_bool(body.get("use_llm", True), default=True))
        return jsonify({"ok": True, "count": len(events), "result": result.to_dict()})

    # Auto-load env-configured sources on app boot (idempotent).
    try:
        source_manager.load_from_env()
    except Exception:  # noqa: BLE001
        # Never let a misconfigured source crash the app.
        pass

    return app


def main() -> None:
    app = create_app()
    port = int(os.environ.get("ANALYZER_PORT", "6060"))
    # Bind localhost by default — operators must opt-in to external exposure
    # via ANALYZER_HOST=0.0.0.0, and should set AI_LOG_ANALYZER_API_TOKEN
    # before doing so.
    host = os.environ.get("ANALYZER_HOST", "127.0.0.1")
    if host == "0.0.0.0" and not API_TOKEN:
        print("[WARN] Binding 0.0.0.0 without AI_LOG_ANALYZER_API_TOKEN — "
              "all routes are unauthenticated.")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
