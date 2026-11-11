"""Flask Blueprint: sites routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer import compliance as comp_engine
from ai_log_analyzer import diff as diff_mod
from ai_log_analyzer import llm, postmortem, reports, runbook, site_doc, site_optimize
from ai_log_analyzer import topology as topo_mod
from ai_log_analyzer.adapters import frr, network_tool
from ai_log_analyzer.analyzer import analyze_site
from ai_log_analyzer.deep_report import run_deep_report
from ai_log_analyzer.web.app import _actor_allows, _load_site_devices, _topology_from_body, require_role

bp = Blueprint('sites', __name__)


# ── Inventory ─────────────────────────────────────────────────────────
@bp.route("/api/lab/containers", methods=["GET"])
@require_role("viewer")
def lab_containers():
    return jsonify({"containers": frr.list_lab_containers()})

@bp.route("/api/network-tool/devices", methods=["GET"])
@require_role("viewer")
def network_tool_devices():
    return jsonify({
        "available": network_tool.is_available(),
        "devices": network_tool.list_devices(),
    })

# ── Synthetic demo samples (Junos / EOS) ──────────────────────────────
@bp.route("/api/samples", methods=["GET"])
@require_role("viewer")
def api_samples():
    """List available synthetic demo sample configs (no server paths)."""
    manifest_path = web_app.SAMPLES_DIR / "_manifest.json"
    if not manifest_path.is_file():
        return jsonify({"samples": []})
    import json as _json
    try:
        manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError:
        manifest = []
    return jsonify({"samples": manifest})

# ── Site bundles (whole-site cross-device analysis) ───────────────────
@bp.route("/api/sites", methods=["GET"])
@require_role("viewer")
def api_sites():
    """List available site bundles (each is a directory under sites/)."""
    if not web_app.SITES_DIR.is_dir():
        return jsonify({"sites": []})
    out: list[dict] = []
    for site_dir in sorted(p for p in web_app.SITES_DIR.iterdir() if p.is_dir()):
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
    return jsonify({"sites": out})

# ── Topology + diagrams ───────────────────────────────────────────────
@bp.route("/api/topology/<site_id>", methods=["GET"])
@require_role("viewer")
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
    # Enrich nodes with manifest extras (tier/pop/rack/asn) so the renderer
    # can build the layered layout and POP compound groups.
    if manifest:
        topo_mod.apply_manifest_metadata(topo, manifest)
    fmt = request.args.get("format", "json").lower()
    if fmt == "mermaid":
        return topo_mod.to_mermaid(topo), 200, {"content-type": "text/plain; charset=utf-8"}
    if fmt in ("dot", "graphviz"):
        return topo_mod.to_graphviz(topo), 200, {"content-type": "text/plain; charset=utf-8"}
    return jsonify(topo.to_dict())

# ── Site-wide strategic optimization advisor ──────────────────────────
@bp.route("/api/optimize/site-wide/<site_id>", methods=["POST"])
@require_role("operator")
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
@bp.route("/api/sitedoc/<site_id>", methods=["GET"])
@require_role("viewer")
def api_sitedoc(site_id: str):
    """Generate a comprehensive site documentation report.

    Query params:
      format: md | html | pdf   (default: md)
      llm:    0 | 1             (default: 1 for operators, 0 for viewers; llm=1
                                 calls the paid LLM, so it needs the operator role)
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
    can_llm = _actor_allows("operator")
    use_llm = request.args.get("llm", "1" if can_llm else "0") not in ("0", "false", "no")
    if use_llm and not can_llm:
        return jsonify({"error": "llm=1 needs the operator role"}), 403
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
@bp.route("/api/compliance/<site_id>", methods=["GET"])
@require_role("viewer")
def api_compliance(site_id: str):
    safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
    if safe != site_id.lower():
        return jsonify({"error": "invalid site id"}), 400
    devices, _ = _load_site_devices(safe)
    if devices is None:
        return jsonify({"error": f"site bundle not found: {safe}"}), 404
    return jsonify(comp_engine.check_bundle(devices))

# ── Post-mortem fleet search ──────────────────────────────────────────
@bp.route("/api/postmortem/<site_id>", methods=["POST"])
@require_role("operator")
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
    result = postmortem.search_fleet(devices, pattern)
    # Invalid regex, oversized pattern or search timeout: the operator's input is at fault.
    return jsonify(result), (400 if result.get("error") else 200)

# ── Snapshot diff ─────────────────────────────────────────────────────
@bp.route("/api/diff", methods=["POST"])
@require_role("operator")
def api_diff():
    body = request.get_json(silent=True) or {}
    before = body.get("before") or ""
    after = body.get("after") or ""
    if not before or not after:
        return jsonify({"error": "both 'before' and 'after' required"}), 400
    host = body.get("hostname", "")
    plat = body.get("platform", "junos")
    return jsonify(diff_mod.explain_diff(before, after, hostname=host, platform=plat))

# ── Runbook generator ─────────────────────────────────────────────────
@bp.route("/api/runbook", methods=["POST"])
@require_role("operator")
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
@bp.route("/api/report/<site_id>", methods=["POST"])
@require_role("operator")
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

@bp.route("/api/optimize/site", methods=["POST"])
@require_role("operator")
def api_optimize_site():
    """Cross-device analysis on a site bundle."""
    body = request.get_json(silent=True) or {}
    site_id = (body.get("site_id") or "").strip()
    if not site_id:
        return jsonify({"error": "site_id required"}), 400
    safe = "".join(c for c in site_id if c.isalnum() or c in "-_").lower()
    if safe != site_id.lower():
        return jsonify({"error": "invalid site id"}), 400
    if not llm.get_state()["enabled"]:
        return jsonify({"error": "LLM is disabled — site analysis needs LLM"}), 400

    # Shared loader keeps per-device platform intact — the old inline loop
    # stamped every device with the manifest-level vendor string, which is
    # wrong on mixed-vendor sites (e.g. "multi (Nokia SRL + Arista cEOS…)").
    devices, _manifest = _load_site_devices(safe)
    if devices is None:
        return jsonify({"error": f"site bundle not found: {safe}"}), 404
    if not devices:
        return jsonify({"error": "no device configs found in bundle"}), 404

    result = analyze_site(safe.upper(), devices)
    result["device_count"] = len(devices)
    result["total_bytes"] = sum(len(d["config_text"]) for d in devices)
    return jsonify(result)

@bp.route("/api/samples/<sample_id>", methods=["GET"])
@require_role("viewer")
def api_sample_preview(sample_id: str):
    """Return a snippet (first 200 lines) of a sample config for preview."""
    safe = "".join(c for c in sample_id if c.isalnum() or c in "-_")
    if not safe or safe != sample_id:
        return jsonify({"error": "invalid sample id"}), 400
    path = web_app.SAMPLES_DIR / f"{safe}.txt"
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

@bp.route("/api/analytics/deep", methods=["POST"])
@require_role("operator")
def api_analytics_deep():
    """Flap physics, blast radius, change correlation, and config drift."""
    body = request.get_json(silent=True) or {}
    topology, error = _topology_from_body(body)
    if error:
        return jsonify({"error": error}), 400
    bundle = run_deep_report(
        log_text=str(body.get("log_text") or body.get("text") or ""),
        topology=topology,
        changes=body.get("changes") or [],
        config_before=str(body.get("config_before") or ""),
        config_after=str(body.get("config_after") or ""),
        incident_timestamp=body.get("incident_timestamp") or None,
    )
    return jsonify(bundle.payload)
