"""Flask Blueprint: remediation routes (moved verbatim from web/app.py).

Pure restructure — no behaviour change. Shared auth helpers and
app-module state (API_TOKEN, SAMPLES_DIR, ...) are reached through
`ai_log_analyzer.web.app` so tests that monkeypatch that module
keep working.
"""
from __future__ import annotations

import os

from flask import Blueprint, jsonify, request

import ai_log_analyzer.web.app as web_app
from ai_log_analyzer.deep_report import run_deep_report
from ai_log_analyzer.sources import SourceError
from ai_log_analyzer.web.app import _body_fields, _parse_bool, _topology_from_body, require_role

bp = Blueprint('remediation', __name__)


@bp.route("/api/remediation", methods=["POST"])
@require_role("operator")
def api_remediation():
    """Generate vendor-safe remediation plan with automatic rollback timer."""
    from ai_log_analyzer.remediation import (
        RemediationActionType,
        RemediationGenerator,
        SafetyViolationError,
        VendorOS,
    )

    body = request.get_json(silent=True) or {}
    device = (body.get("device") or "").strip()
    vendor_str = (body.get("vendor") or "").strip().lower()
    if not device or not vendor_str:
        return jsonify({"ok": False, "error": "device and vendor are required"}), 400

    try:
        vendor = VendorOS(vendor_str)
    except ValueError:
        return jsonify({
            "ok": False,
            "error": f"unknown vendor {vendor_str!r}",
            "supported_vendors": [v.value for v in VendorOS],
        }), 400

    action = (body.get("action") or body.get("action_type") or "drain").strip().lower()
    interface = (body.get("interface") or "").strip()
    bgp_neighbor_ip = body.get("bgp_neighbor_ip")
    rollback_minutes = body.get("rollback_minutes")
    if rollback_minutes is not None:
        try:
            rollback_minutes = int(rollback_minutes)
        except (ValueError, TypeError):
            return jsonify({"ok": False, "error": "rollback_minutes must be an integer"}), 400

    rationale = (body.get("rationale") or "").strip()
    commands = body.get("commands") or []
    pre_checks = body.get("pre_checks") or []
    post_checks = body.get("post_checks") or []

    gen = RemediationGenerator()
    try:
        if action in ("drain", RemediationActionType.GRACEFUL_LINK_DRAIN.value):
            plan = gen.build_graceful_link_drain(
                device=device,
                vendor=vendor,
                interface=interface or "Ethernet1",
                bgp_neighbor_ip=bgp_neighbor_ip,
                rollback_minutes=rollback_minutes,
                rationale=rationale or "Drain traffic gracefully prior to physical maintenance.",
            )
        elif action in ("copp", "qos", RemediationActionType.QOS_COPP_CONTROL_PLANE_BOOST.value):
            plan = gen.build_qos_copp_remediation(
                device=device,
                vendor=vendor,
                interface=interface or "Ethernet1",
                rollback_minutes=rollback_minutes,
                rationale=rationale or "Prioritize BFD/BGP control plane traffic.",
            )
        elif action in ("custom", RemediationActionType.CUSTOM_SAFE_CONFIG.value):
            if not commands:
                return jsonify({"ok": False, "error": "commands list required for custom action"}), 400
            plan = gen.build_custom_safe_plan(
                device=device,
                vendor=vendor,
                commands=commands,
                pre_checks=pre_checks,
                post_checks=post_checks,
                rationale=rationale or "Custom safe configuration plan.",
                rollback_minutes=rollback_minutes,
            )
        else:
            return jsonify({"ok": False, "error": f"unsupported action {action!r}"}), 400
    except SafetyViolationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    out = {"ok": True, "plan": plan.to_dict(), "markdown_card": plan.to_markdown_card()}
    export = (body.get("export") or "").strip().lower()
    if export:
        from ai_log_analyzer.remediation_export import ExportUnsupportedError, export_plan
        try:
            out["export"] = {"format": export, "content": export_plan(plan, export)}
        except (ExportUnsupportedError, SafetyViolationError) as exc:
            return jsonify({"ok": False, "error": str(exc), "plan": plan.to_dict()}), 400
    return jsonify(out)

@bp.route("/api/itsm/enrich", methods=["POST"])
@require_role("operator", "itsm.enrich", _body_fields("system", "dry_run", "site", "device"))
def api_itsm_enrich():
    """Format or dispatch two-way ITSM enrichment to Jira or ServiceNow."""
    from ai_log_analyzer.itsm import (
        IncidentEnrichmentPayload,
        JiraITSMClient,
        ServiceNowITSMClient,
    )
    from ai_log_analyzer.remediation import (
        RemediationActionType,
        RemediationPlan,
        VendorOS,
    )

    body = request.get_json(silent=True) or {}
    system = (body.get("system") or "").strip().lower()
    if system not in ("jira", "servicenow"):
        return jsonify({"ok": False, "error": "system must be 'jira' or 'servicenow'"}), 400

    device = (body.get("device") or "").strip()
    vendor = (body.get("vendor") or "").strip()
    root_cause = (body.get("root_cause_summary") or body.get("root_cause") or "").strip()
    if not (device and vendor and root_cause):
        return jsonify({"ok": False, "error": "device, vendor, and root_cause_summary required"}), 400

    site = (body.get("site") or "default").strip()
    layer = (body.get("layer") or "L1_PHYSICAL").strip()
    interface = (body.get("interface") or "").strip()
    confidence = float(body.get("confidence", 0.95))
    rollback_minutes = int(body.get("rollback_minutes", 5))
    pre_checks = body.get("pre_checks") or []
    config_commands = body.get("config_commands") or []
    post_checks = body.get("post_checks") or []
    suppressed_count = int(body.get("suppressed_symptoms_count", 0))
    affected_devices = body.get("affected_devices") or [device]
    affected_vnis = [int(v) for v in (body.get("affected_vnis") or [])]
    telemetry_summary = body.get("telemetry_summary") or None
    plan_id = (body.get("plan_id") or "").strip()
    dry_run = _parse_bool(body.get("dry_run", True), default=True)

    plan = None
    if plan_id or config_commands:
        try:
            vos = VendorOS(vendor.lower().strip())
        except ValueError:
            vos = VendorOS.ARISTA_EOS
        plan = RemediationPlan(
            plan_id=plan_id or f"REM-{device.upper()}",
            device=device,
            vendor=vos,
            action_type=RemediationActionType.GRACEFUL_LINK_DRAIN,
            rollback_minutes=rollback_minutes,
            rationale=root_cause,
            pre_checks=pre_checks,
            config_commands=config_commands,
            commit_with_timer_commands=[],
            post_checks=post_checks,
            confirm_commit_commands=[],
            manual_rollback_commands=[],
        )

    payload = IncidentEnrichmentPayload(
        site=site,
        root_device=device,
        root_layer=layer,
        root_interface=interface or None,
        summary_title=root_cause,
        rca_rationale=f"Diagnosed root cause on {device}: {root_cause}",
        confidence=confidence,
        affected_devices=affected_devices,
        affected_vnis=affected_vnis,
        suppressed_symptom_count=suppressed_count,
        telemetry_summary=telemetry_summary,
        remediation_plan=plan,
    )

    if dry_run:
        return jsonify({
            "ok": True,
            "dry_run": True,
            "system": system,
            "fingerprint": payload.fingerprint,
            "markdown_card": payload.to_markdown_body(),
            "jira_payload": payload.to_jira_issue_fields(body.get("project_key", "NET")),
            "servicenow_payload": payload.to_servicenow_record(),
        })

    # Live dispatch
    try:
        if system == "jira":
            env_url = (os.environ.get("JIRA_URL") or os.environ.get("JIRA_BASE_URL") or "").strip()
            base_url = (body.get("instance_url") or env_url).strip()
            # A body-supplied URL other than the configured one never inherits the
            # server's stored credentials (they would be sent to the caller's host).
            env_creds = base_url.rstrip("/") == env_url.rstrip("/")
            email = (body.get("email") or (os.environ.get("JIRA_EMAIL") if env_creds else "") or "").strip()
            token = (body.get("api_token") or (os.environ.get("JIRA_API_TOKEN") if env_creds else "") or "").strip()
            project = (body.get("project_key") or os.environ.get("JIRA_PROJECT_KEY") or "NET").strip()
            if not (base_url and email and token):
                return jsonify({"ok": False, "error": "missing Jira credentials (instance_url, email, api_token)"}), 400
            client = JiraITSMClient(base_url, email, token, project_key=project)
            res = client.enrich_incident(payload)
            return jsonify({"ok": True, "dry_run": False, "system": "jira", "result": res})
        else:
            env_url = (os.environ.get("SERVICENOW_URL") or os.environ.get("SNOW_URL") or "").strip()
            instance_url = (body.get("instance_url") or env_url).strip()
            env_creds = instance_url.rstrip("/") == env_url.rstrip("/")   # see the Jira branch
            user = (body.get("username") or (os.environ.get("SERVICENOW_USER") or os.environ.get("SNOW_USER")
                                             if env_creds else "") or "").strip()
            pwd = (body.get("password") or (os.environ.get("SERVICENOW_PASSWORD") or os.environ.get("SNOW_PASSWORD")
                                            if env_creds else "") or "").strip()
            if not (instance_url and user and pwd):
                return jsonify({"ok": False, "error": "missing ServiceNow credentials (instance_url, username, password)"}), 400
            client = ServiceNowITSMClient(instance_url, user, pwd)
            res = client.enrich_incident(payload)
            return jsonify({"ok": True, "dry_run": False, "system": "servicenow", "result": res})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

@bp.route("/api/itsm/servicenow/sync", methods=["POST"])
@require_role("operator", "itsm.servicenow.sync", _body_fields("dry_run", "instance_url"))
def api_servicenow_sync():
    """Preview or upsert one ServiceNow incident. Defaults to dry-run."""
    body = request.get_json(silent=True) or {}
    instance = str(body.get("instance_url") or "").strip()
    dry_run = _parse_bool(body.get("dry_run", True), default=True) or not instance
    topology, error = _topology_from_body(body)
    if error:
        return jsonify({"error": error}), 400
    bundle = run_deep_report(
        log_text=str(body.get("log_text") or body.get("text") or ""),
        topology=topology,
        changes=body.get("changes") or [],
        config_before=str(body.get("config_before") or ""),
        config_after=str(body.get("config_after") or ""),
    )
    try:
        client = web_app.ServiceNowClient(
            instance_url=instance,
            username=str(body.get("username") or ""),
            password=str(body.get("password") or ""),
            bearer_token=str(body.get("bearer_token") or ""),
            # Admin-controlled only: a request body must never relax the SSRF guard.
            allow_private=_parse_bool(os.environ.get("AI_LOG_ANALYZER_ITSM_ALLOW_PRIVATE"), default=False),
        )
        result = client.sync_incident(
            bundle.summary,
            blast_radius=bundle.blast,
            change_report=bundle.changes,
            flap_report=bundle.flap,
            dry_run=dry_run,
        )
    except (SourceError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(result.to_dict())
