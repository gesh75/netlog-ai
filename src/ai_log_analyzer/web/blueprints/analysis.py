"""Flask Blueprint: analysis routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

import itertools
import time
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import llm, metrics, webhooks
from ai_log_analyzer.adapters import frr, network_tool
from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import analyze, optimize_config
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.sources import SourceError
from ai_log_analyzer.web.app import (
    BadCommand,
    _allowed_dir_files,
    _body_fields,
    _events_from_registered_source,
    _parse_bool,
    _parse_frr_command,
    _path_allowed,
    _scrub_analysis,
    require_role,
)

bp = Blueprint('analysis', __name__)


# ── Classification rules ──────────────────────────────────────────────
@bp.route("/api/rules", methods=["GET"])
@require_role("viewer")
def api_rules_list():
    """Built-in rule count + the operator's custom classification rules."""
    from ai_log_analyzer import classifier as _clf
    return jsonify({
        "builtin_count": len(_clf._KB_PATTERNS),
        "custom": _clf.custom_rules(),
    })

@bp.route("/api/rules", methods=["POST"])
@require_role("admin", "config.rules.add", lambda: {"rules": [
    {k: r.get(k) for k in ("pattern", "severity", "category", "description")}
    for r in ((request.get_json(silent=True) or {}).get("rules") or [])[:20] if isinstance(r, dict)]})
def api_rules_add():
    """Register custom classification rules at runtime (non-persistent).

    Body: {"rules": [{"pattern": "...", "severity": "high",
                      "category": "...", "description": "..."}]}
    Persist across restarts by putting the same list in a JSON file and
    pointing AI_LOG_ANALYZER_CUSTOM_RULES at it.
    """
    from ai_log_analyzer import classifier as _clf
    body = request.get_json(silent=True) or {}
    rules = body.get("rules")
    if not isinstance(rules, list) or not rules:
        return jsonify({"error": "body must be {\"rules\": [...]} with ≥1 rule"}), 400
    added, errors = _clf.add_custom_rules(rules)
    status = 200 if added else 400
    return jsonify({"added": added, "errors": errors,
                    "custom_total": len(_clf.custom_rules())}), status

# ── Main analysis ─────────────────────────────────────────────────────
@bp.route("/api/analyze", methods=["POST"])
@require_role("operator")
def api_analyze():
    body = request.get_json(silent=True) or {}
    source = body.get("source", "frr")
    use_llm = _parse_bool(body.get("use_llm"), default=True)
    dedup = _parse_bool(body.get("dedup"), default=False)
    evpn_causal = _parse_bool(body.get("evpn_causal"), default=False)
    try:
        tail = max(1, min(10000, int(body.get("tail") or 500)))
    except (TypeError, ValueError):
        tail = 500
    events: list[LogEvent] = []

    if source == "frr":
        requested = body.get("containers")
        if requested is not None and not isinstance(requested, list):
            return jsonify({"error": "containers must be a list of names"}), 400
        if requested is not None and any(not frr.is_docker_name(c) for c in requested):
            return jsonify({"error": "containers must be a list of docker names"}), 400
        containers, rejected = frr.authorize_lab_containers(requested)
        if rejected:
            return jsonify({
                "error": "containers outside the lab allow-list",
                "rejected": rejected,
                "hint": "Only bundled FRR / containerlab nodes may be read via docker logs",
            }), 403
        if not containers:
            return jsonify({"error": "No FRR containers found running"}), 404
        for c in containers:
            try:
                events.extend(frr.frr_docker_logs(c, tail=tail))
            except Exception as e:
                current_app.logger.warning("Failed to read logs for %s: %s", c, e)

    elif source == "raw":
        text = body.get("text", "")
        host = body.get("hostname", "")
        events = list(parse_lines(text.splitlines(), default_host=host))

    elif source == "file":
        path = body.get("path", "")
        p = Path(path).expanduser() if path else None
        if p and not _path_allowed(p):
            return jsonify({
                "error": "Path outside allowed roots "
                         "(set AI_LOG_ANALYZER_FILE_ROOTS to extend)",
            }), 403
        if not p or not p.exists():
            return jsonify({"error": f"Path not found: {path}"}), 404
        from ai_log_analyzer.adapters.file import parse_file
        if p.is_dir():
            # Directory scan. Walk recursively for *.log files (overridable
            # via body.pattern). Cap at 500 files for safety; hidden and
            # credential-looking files are skipped even under an allowed root.
            pattern = body.get("pattern", "*.log")
            recursive = _parse_bool(body.get("recursive", True), default=True)
            try:
                files = _allowed_dir_files(p, pattern, recursive)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            if not files:
                return jsonify({
                    "error": f"No files matching {pattern!r} in {path}",
                }), 404
            # Generator — analyze() streams it in bounded memory
            events = itertools.chain.from_iterable(parse_file(f) for f in files)
        elif p.is_file():
            size_mb = p.stat().st_size / 1_048_576
            if size_mb > web_app.MAX_FILE_MB:
                return jsonify({
                    "error": f"File is {size_mb:.0f}MB — over the "
                             f"{web_app.MAX_FILE_MB:.0f}MB web limit (HTTP worker "
                             "timeout). Use the CLI for huge files: "
                             "ai-log-analyzer analyze --file <path>, or "
                             "raise AI_LOG_ANALYZER_MAX_FILE_MB.",
                }), 413
            # Generator — analyze() streams it in bounded memory
            events = parse_file(p)
        else:
            return jsonify({"error": f"Path is neither file nor dir: {path}"}), 400

    else:
        # Registered LogSource kind or id (kibana, splunk, solarwinds, …).
        try:
            events = _events_from_registered_source(source, limit=tail)
        except SourceError as exc:
            return jsonify({"error": str(exc)}), 400

    # Empty check that works for lists and generators alike: pull the
    # first event, then chain it back in front of the stream.
    event_iter = iter(events)
    try:
        first = next(event_iter)
    except StopIteration:
        return jsonify({"error": "No events ingested from source"}), 404
    events = itertools.chain([first], event_iter)

    _analyze_started = time.perf_counter()
    result = analyze(events, use_llm=use_llm, dedup=dedup, evpn_causal=evpn_causal)
    # P4: completed-run wall time, for /api/metrics. Only runs that reach
    # the analyzer count; early 4xx exits above are not analysis runs.
    metrics.observe_analysis(time.perf_counter() - _analyze_started)
    result_dict = _scrub_analysis(result.to_dict())
    webhooks.notify_analysis(result_dict, source)
    return jsonify(result_dict)

# ── Live CLI execution: lab network-tool SSH first, docker-exec fallback ──
@bp.route("/api/run", methods=["POST"])
@require_role("admin", "run.command", _body_fields("hostname", "command", "raw"))
def api_run():
    """Execute a CLI command on a lab device.

    Path 1: POST through the lab network-tool SSH proxy at :5757.
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

    # docker-exec fallback for FRR lab containers (off when DOCKER_EXEC_FALLBACK=false,
    # the container image default: no docker socket, no host-level exec).
    if network_tool.DOCKER_EXEC_FALLBACK and frr.is_lab_container(hostname):
        try:
            container_cmd = _parse_frr_command(command)
        except BadCommand as exc:
            return jsonify({"error": str(exc)}), 400
        result = network_tool.container_run(hostname, container_cmd)
        d = result.to_dict()
        d["transport"] = "docker-exec"
        return jsonify(d)

    return jsonify({
        "error": "Could not execute — SSH proxy down and no docker-exec fallback for this host",
        "hint": ("Fix the lab network-tool SSH key path, or use a known lab container name with "
                 "DOCKER_EXEC_FALLBACK=true"),
    }), 503

# ── Config-aware Optimization (LLM killer feature) ────────────────────
@bp.route("/api/optimize", methods=["POST"])
@require_role("operator")
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
        path = web_app.SAMPLES_DIR / f"{safe}.txt"
        if not path.is_file():
            return jsonify({"error": f"sample not found: {safe}"}), 404
        config_override = path.read_text(encoding="utf-8", errors="replace")
        # Pull platform + hostname hints from the manifest if not provided
        manifest_path = web_app.SAMPLES_DIR / "_manifest.json"
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
        # fetch_running_config() tries the lab network tool first, then falls
        # back to `docker exec` for FRR lab containers. Don't 503 here
        # just because the SSH proxy is down — let the FRR fallback run.
        running_config = network_tool.fetch_running_config(hostname, platform=platform)
        if not running_config:
            return jsonify({
                "error": f"Could not fetch running config from {hostname}",
                "hint": ("Provide 'running_config' in the body, or start the "
                         "lab network tool at :5757 / use a FRR lab container."),
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
