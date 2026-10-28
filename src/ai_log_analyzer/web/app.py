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

import fnmatch
import itertools
import threading
from collections.abc import Callable
from functools import wraps

from flask import Flask, abort, jsonify, make_response, request, send_from_directory
from flask_cors import CORS

from ai_log_analyzer import (
    __version__,
    audit,
    copilot,
    llm,
    postmortem,
    rbac,
    reports,
    runbook,
    site_doc,
    site_optimize,
    webhooks,
)
from ai_log_analyzer import compliance as comp_engine
from ai_log_analyzer import diff as diff_mod
from ai_log_analyzer import topology as topo_mod
from ai_log_analyzer.adapters import frr, network_tool
from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import analyze, analyze_site, optimize_config
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.correlate import correlate_from_manager
from ai_log_analyzer.deep_report import load_site_topology, run_deep_report
from ai_log_analyzer.device_triage import triage_from_manager
from ai_log_analyzer.servicenow_sync import ServiceNowClient
from ai_log_analyzer.sources import SourceConfig, SourceError, registry
from ai_log_analyzer.sources.manager import manager as source_manager

STATIC_DIR = Path(__file__).parent / "static"


def _data_dir(env_var: str, name: str) -> Path:
    """Resolve a bundled-data directory (samples/ or sites/).

    Priority: explicit env override → packaged data (ships in the wheel, so
    pip/Docker installs get the demo bundles too) → legacy repo-root layout.
    """
    override = os.environ.get(env_var, "")
    if override:
        return Path(override).expanduser()
    packaged = Path(__file__).resolve().parents[1] / "data" / name
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / name


SAMPLES_DIR = _data_dir("AI_LOG_ANALYZER_SAMPLES_DIR", "samples")
SITES_DIR = _data_dir("AI_LOG_ANALYZER_SITES_DIR", "sites")


# ── Security helpers ─────────────────────────────────────────────────────────

API_TOKEN: str = os.environ.get("AI_LOG_ANALYZER_API_TOKEN", "")

def _default_file_roots() -> str:
    """/var/log plus the optional AI_LOG_ANALYZER_DATA_DIR. $HOME and the repo checkout are
    deliberately not roots: they hold credentials, .env files and this app's own state."""
    data_dir = os.environ.get("AI_LOG_ANALYZER_DATA_DIR", "").strip()
    return ":".join(["/var/log", *([data_dir] if data_dir else [])])


# Roots that POST /api/analyze {source:"file"} may read from. Colon-separated
# env override (AI_LOG_ANALYZER_FILE_ROOTS); default = /var/log + the optional
# AI_LOG_ANALYZER_DATA_DIR. Confines the file-ingest path so an exposed port
# can't read /etc/* or an operator's home directory.
FILE_ROOTS: list[Path] = [
    Path(p).expanduser().resolve()
    for p in os.environ.get("AI_LOG_ANALYZER_FILE_ROOTS", _default_file_roots()).split(":")
    if p.strip()
]

# Never served even inside an allowed root: dotfiles / dot-directories (.env, .ssh,
# .aws, .netrc, ...) and well-known credential and state-store filenames.
_DENIED_NAME_GLOBS = (
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.jks", "*.kdbx", "credentials*", "*rbac*", "shadow*", "htpasswd*",
    "*.db", "*.db-wal", "*.db-shm", "*.sqlite", "*.sqlite3",
)


# Web-route cap for single-file analysis. Streaming keeps memory bounded at
# any size, but classification CPU (~2.7 MB/s) must finish inside the HTTP
# worker timeout (120s) — bigger files belong on the CLI, which has no timeout.
MAX_FILE_MB: float = float(os.environ.get("AI_LOG_ANALYZER_MAX_FILE_MB", "200"))


def _events_from_registered_source(kind_or_id: str, *, limit: int) -> list[LogEvent]:
    """Pull events from a live SourceManager entry (kind or configured id)."""
    source_manager.load_from_env()
    for sid in source_manager.list_ids():
        src = source_manager.get(sid)
        if sid == kind_or_id or getattr(src, "kind", None) == kind_or_id:
            return source_manager.fetch(sid, limit=limit)
    if registry.is_registered(kind_or_id):
        extra = ""
        if kind_or_id == "solarwinds":
            extra = ", or SOLARWINDS_URL / SOLARWINDS_TOKEN"
        raise SourceError(
            f"source type {kind_or_id!r} is registered but not configured "
            f"(set NETLOG_SOURCE_<id>_TYPE={kind_or_id} and NETLOG_SOURCE_<id>_URL=...{extra})"
        )
    raise SourceError(f"Unknown source: {kind_or_id}")


def _path_allowed(p: Path) -> bool:
    """True when the resolved path sits under one of FILE_ROOTS and is not a hidden
    or credential-looking file (judged on the part below the root)."""
    try:
        resolved = p.resolve()
    except OSError:
        return False
    for root in FILE_ROOTS:
        if resolved.is_relative_to(root):
            parts = resolved.relative_to(root).parts
            return not any(
                part.startswith(".") or any(fnmatch.fnmatchcase(part.lower(), g) for g in _DENIED_NAME_GLOBS)
                for part in parts)
    return False


def _allowed_dir_files(directory: Path, pattern: str, recursive: bool) -> list[Path]:
    """Files a directory scan may read: the adapter's matches minus anything _path_allowed denies."""
    from ai_log_analyzer.adapters.file import _MAX_DIRECTORY_FILES, _matching_files
    allowed = (f for f in _matching_files(directory, pattern, recursive) if _path_allowed(f))
    return sorted(itertools.islice(allowed, _MAX_DIRECTORY_FILES))


_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class BadCommand(ValueError):
    """Raised when /api/run receives a command we won't translate to argv."""


def _token_supplied() -> str:
    """The API token from the request, from either accepted header form."""
    supplied = request.headers.get("X-API-Token", "")
    if not supplied:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[len("Bearer "):].strip()
    return supplied


def sanitize_line(line: str) -> str:
    from ai_log_analyzer.sanitize import sanitize
    return sanitize(line, mask_pii=False)[0]


def _scrub_text(value):
    """sanitize_line for str values; anything else passes through."""
    return sanitize_line(value) if isinstance(value, str) and value else value


def _scrub_event(d: dict) -> dict:
    """Run the free-text fields of one classified-event dict through the sanitizer."""
    for key in ("message", "sample_message", "description"):
        if key in d:
            d[key] = _scrub_text(d[key])
    return d


def _scrub_tree(node, memo: dict):
    """Copy of a JSON-like tree with every string of 8+ chars run through the sanitizer.

    ``memo`` dedups: logs repeat the same message thousands of times and the sanitizer
    costs ~45 us a call."""
    if isinstance(node, str):
        if len(node) < 8:
            return node
        hit = memo.get(node)
        if hit is None:
            hit = memo[node] = sanitize_line(node)
        return hit
    if isinstance(node, list):
        return [_scrub_tree(x, memo) for x in node]
    if isinstance(node, dict):
        return {k: _scrub_tree(v, memo) for k, v in node.items()}
    return node


def _scrub_analysis(result: dict) -> dict:
    """Sanitize raw log text in an analyze() result before it leaves the API.

    Event messages come straight from the log source (a secret in a log line, or in
    a file read through the file source, must not be echoed back) and also surface in
    sample messages, timelines, the sanitize preview and LLM evidence. A whole-tree
    pass catches every such place, including ones added later.
    """
    return _scrub_tree(result, {})


_SECRET_KEY_HINTS = ("token", "secret", "password", "passwd", "key", "cookie", "auth", "cred")


def _redact_url(url: str) -> str:
    """Drop userinfo (user:pass@) and sanitize the rest of a stored source URL."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(url)
        if parts.username is not None or parts.password is not None:
            host = parts.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            netloc = host + (f":{parts.port}" if parts.port else "")
            url = urlunsplit(parts._replace(netloc=netloc))
    except ValueError:
        pass
    return sanitize_line(url)


def _redact_source(src: dict) -> dict:
    """/api/sources view of one source: no URL userinfo, no ``extra`` values.

    ``extra`` holds connector-specific options (TLS key paths, API keys, bind
    addresses); viewers get the key names only.
    """
    out = dict(src)
    if isinstance(out.get("url"), str):
        out["url"] = _redact_url(out["url"])
    out["extra"] = {k: "***" for k in (out.get("extra") or {})}
    return out


def _tail_start_cursor(src) -> int:
    """Where a new live tail starts ("now"). Spool mode: the newest spool row id, since
    the cursor is a row id there (the in-process ingest counter is unrelated to it, and
    is 0 on reader workers). Memory mode: the monotonic ingest counter."""
    db = getattr(src, "_db", None)
    if db is not None:
        try:
            flush = getattr(src, "_flush", None)
            if callable(flush):
                flush()
            return int(db.spool_max_id(src.name))
        except Exception:   # sqlite3.Error: fall back to replaying from the start of the spool
            return 0
    return int(getattr(src, "_total_ingested", 0))


def _remote() -> str:
    return request.remote_addr or ""


def _host_only(host: str) -> str:
    """Host header without its port: ``Example.com:6060`` -> ``example.com``, ``[::1]:80`` -> ``[::1]``."""
    h = host.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[:end + 1] if end != -1 else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _allowed_hosts() -> set[str]:
    """Host values accepted when auth is off: AI_LOG_ANALYZER_ALLOWED_HOSTS (comma list, ``*`` = any)
    defaulting to loopback, plus the configured bind host."""
    raw = os.environ.get("AI_LOG_ANALYZER_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]")
    hosts = {_host_only(h) for h in raw.split(",") if h.strip()}
    bind = os.environ.get("ANALYZER_HOST", "").strip()
    if bind and bind not in ("0.0.0.0", "::"):
        hosts.add(_host_only(f"[{bind}]" if ":" in bind and not bind.startswith("[") else bind))
    return hosts


def _is_loopback_host(host: str) -> bool:
    import ipaddress
    h = host.strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _check_auth_config() -> bool:
    """Validate the auth configuration at startup; returns whether auth is on.

    A malformed token (too short) or an unusable ``AI_LOG_ANALYZER_RBAC_FILE`` (missing,
    unreadable, not JSON, no usable user) is an error, and ``AI_LOG_ANALYZER_REQUIRE_AUTH=1``
    (set by the Docker image) refuses to start with no token at all, so a container
    published on 0.0.0.0 can never come up as an open admin API.
    """
    try:
        rbac.principals(API_TOKEN)   # loads every configured credential source: a bad one raises
        enabled = rbac.auth_enabled(API_TOKEN)
    except rbac.RbacConfigError as exc:
        raise RuntimeError(f"invalid API token configuration: {exc}") from exc
    if rbac.auth_required() and not enabled:
        raise RuntimeError(
            "AI_LOG_ANALYZER_REQUIRE_AUTH is set but no API token is configured, so every route "
            "would be unauthenticated. Set AI_LOG_ANALYZER_API_TOKEN (>= 16 characters) or "
            "AI_LOG_ANALYZER_{VIEWER,OPERATOR,ADMIN}_TOKENS / AI_LOG_ANALYZER_RBAC_FILE "
            "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`).")
    return enabled


def current_principal() -> rbac.Principal | None:
    """The authenticated principal for this request.

    Tokens come from headers only, never the query string: URLs end up in
    proxy and access logs.
    """
    return rbac.authenticate(_token_supplied(), API_TOKEN)


def require_role(role: str, audit_action: str | None = None,
                 audit_detail: Callable[[], dict] | None = None):
    """Gate a route on a minimum role and optionally audit it.

    Dev mode (no token or RBAC principal configured) is a no-op gate, as
    before, and the actor is recorded as ``anonymous``. Otherwise a missing
    or unknown token is 401 and an insufficient role is 403. The principal
    is bound for the whole request, so external LLM calls the route makes
    are attributed to it in the audit log.
    """
    if role not in rbac.RANK:
        raise ValueError(f"unknown role {role!r}")

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if rbac.auth_enabled(API_TOKEN):
                principal = current_principal()
                if principal is None:
                    _audit_auth_failure()
                    abort(401)
                if not principal.allows(role):
                    audit.record("authz.denied", target=request.path, outcome="denied",
                                 actor=audit.Actor(principal.name, principal.role, _remote()),
                                 detail={"required": role, "method": request.method})
                    abort(403)
                actor = audit.Actor(principal.name, principal.role, _remote())
            else:
                actor = audit.Actor("anonymous", "dev", _remote())
            with audit.actor_scope(actor):
                try:
                    resp = fn(*args, **kwargs)
                except Exception as exc:   # abort() or a crash: the attempt is still audited
                    if audit_action:
                        _audit_route(audit_action, audit_detail, getattr(exc, "code", None) or 500)
                    raise
                if audit_action:
                    status = resp[1] if isinstance(resp, tuple) and len(resp) > 1 else \
                        getattr(resp, "status_code", 200)
                    _audit_route(audit_action, audit_detail, status)
                return resp
        return wrapper
    return deco


def _audit_auth_failure() -> None:
    """Audit a 401 (rate-limited per source address: anyone can generate these)."""
    supplied = bool(_token_supplied())
    audit.record_throttled(
        "authn.failed", key=_remote(), target=request.path, outcome="unauthorized",
        actor=audit.Actor("unknown", "none", _remote()),
        detail={"method": request.method, "token": "invalid" if supplied else "missing"})


def _actor_allows(role: str) -> bool:
    """Whether the current request's actor holds ``role`` (dev mode = everything)."""
    actor = audit.current_actor()
    return actor.role == "dev" or rbac.RANK.get(actor.role, 0) >= rbac.RANK[role]


def _audit_route(action: str, detail_fn: Callable[[], dict] | None, status: int) -> None:
    try:
        detail = detail_fn() if detail_fn else {}
    except Exception:  # a detail extractor must never fail the request
        detail = {}
    audit.record(action, target=request.path, outcome="ok" if int(status) < 400 else f"http_{status}",
                 detail={"method": request.method, **detail})


def require_api_token(fn):
    """Back-compat alias: the operator role (the legacy shared token is admin)."""
    return require_role("operator")(fn)


def _body_fields(*keys: str) -> Callable[[], dict]:
    """Audit-detail extractor: selected JSON body fields, never credentials."""
    def extract() -> dict:
        body = request.get_json(silent=True) or {}
        return {k: sanitize_line(v) if isinstance(v, str) else v for k, v in body.items() if k in keys}
    return extract


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


def _topology_from_body(body: dict) -> tuple[object | None, str | None]:
    """Load a site topology when the request names one. Missing bundles are skipped."""
    site = str(body.get("site") or "").strip()
    if not site:
        return None, None
    try:
        return load_site_topology(SITES_DIR, site), None
    except ValueError as exc:
        return None, str(exc)


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
    _check_auth_config()
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
    # Request bodies are JSON only (no uploads); refuse anything huge before it is parsed.
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("AI_LOG_ANALYZER_MAX_CONTENT_LENGTH", str(16 * 1024 * 1024)))
    allowed_hosts = _allowed_hosts()
    # Restrict CORS to specific origins by default. Override via
    # AI_LOG_ANALYZER_CORS_ORIGINS=https://your-host,https://other-host
    allowed_origins = [
        o.strip() for o in os.environ.get(
            "AI_LOG_ANALYZER_CORS_ORIGINS",
            "http://localhost:6060,http://127.0.0.1:6060",
        ).split(",") if o.strip()
    ]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

    # ── DNS-rebinding guard ───────────────────────────────────────────────
    # With auth off (loopback dev use) a hostile web page could re-point its own
    # name at 127.0.0.1 and drive the open API from the victim's browser. Such a
    # request carries the attacker's name in Host, so refuse unknown Host values.
    # With auth on, the token (which a rebinding page cannot know) is the gate.
    @app.before_request
    def _reject_unknown_host():
        if "*" in allowed_hosts or rbac.auth_enabled(API_TOKEN):
            return None
        host = request.host or ""   # HTTP/1.0 without Host cannot be a rebinding page
        if host and _host_only(host) not in allowed_hosts:
            return jsonify({"error": "host not allowed",
                            "hint": "set AI_LOG_ANALYZER_ALLOWED_HOSTS to the name you browse to"}), 400
        return None

    # ── Cross-site request guard ──────────────────────────────────────────
    # With auth off, a cross-site browser request is indistinguishable from the dashboard's, and the
    # Host check above only stops DNS rebinding. A page can still fire a "simple" request (a body-less
    # POST, or a form / text/plain body) that the handlers read as {} and act on. A simple request
    # cannot carry a JSON content type, a custom header or the token header (each forces a CORS
    # preflight, which the origin allow-list refuses), so every state-changing request must have one.
    # With auth on, a request without a token header is a plain 401 from the route gate.
    @app.before_request
    def _require_non_simple_request():
        if request.method not in _STATE_CHANGING:
            return None
        if request.is_json or request.headers.get("X-Requested-With") or _token_supplied():
            return None
        if rbac.auth_enabled(API_TOKEN):
            return None
        return jsonify({"error": "cross-site request refused",
                        "hint": "send Content-Type: application/json (or an X-Requested-With header)"}), 403

    @app.errorhandler(rbac.RbacConfigError)
    def _auth_config_unusable(_exc):
        # The RBAC file broke while the server runs. Auth stays on: refuse, never open up. The
        # detail is in the server log (rbac logs it once per change); the path is not echoed.
        return jsonify({"error": "authentication is configured but its credential store is unusable",
                        "hint": "an administrator must fix AI_LOG_ANALYZER_RBAC_FILE"}), 503

    @app.errorhandler(413)
    def _too_large(_exc):
        return jsonify({"error": "request body too large",
                        "hint": "raise AI_LOG_ANALYZER_MAX_CONTENT_LENGTH (bytes)"}), 413

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    # ── Cache headers for static HTML/JS/CSS ──────────────────────────────
    # The UI is a single-page Flask app — we ship layout/JS fixes by editing
    # index.html and app.js directly. Browsers cache these by default, which
    # means users see a stale UI until they hard-refresh. `no-cache` (without
    # `no-store`) forces revalidation via If-None-Match on every request, so
    # Flask's ETag answers 304 and the ~200KB of text assets are only
    # re-downloaded when they actually change. Binary assets stay cached.
    @app.after_request
    def _add_no_cache_for_text_assets(response):
        path = (request.path or "").lower()
        if (path == "/"
                or path.endswith(".html")
                or path.endswith(".js")
                or path.endswith(".css")
                or path.endswith(".json")):
            response.headers["Cache-Control"] = "no-cache"
        return response

    # ── UI ────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(str(STATIC_DIR), "index.html")

    # ── Health + LLM control ──────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "ok": True,
            "version": __version__,
            "network_tool_available": network_tool.is_available(),
            "auth": "rbac" if rbac.auth_enabled(API_TOKEN) else "dev",
            "audit": audit.is_enabled(),
        })

    @app.route("/api/llm/status", methods=["GET"])
    def llm_status():
        state = llm.get_state()
        # last_errors carries upstream HTTP error bodies — useful in the UI,
        # but on a token-protected deployment don't hand it to anonymous
        # callers. Dev mode (no token) keeps full output for the dashboard.
        if rbac.auth_enabled(API_TOKEN) and current_principal() is None:
            state = {k: v for k, v in state.items() if k != "last_errors"}
        return jsonify(state)

    @app.route("/api/llm/provider", methods=["POST"])
    @require_role("admin", "llm.provider.set", _body_fields("provider"))
    def llm_set_provider():
        body = request.get_json(silent=True) or {}
        ok, msg = llm.set_provider(body.get("provider", ""))
        if not ok:
            return jsonify({"ok": False, "error": msg}), 400
        return jsonify({"ok": True, "provider": msg})

    @app.route("/api/llm/toggle", methods=["POST"])
    @require_role("admin", "llm.toggle", _body_fields("enabled"))
    def llm_toggle():
        body = request.get_json(silent=True) or {}
        enabled = bool(body.get("enabled", True))
        return jsonify({"ok": True, "enabled": llm.set_enabled(enabled)})

    # ── Classification rules ──────────────────────────────────────────────
    @app.route("/api/rules", methods=["GET"])
    @require_role("viewer")
    def api_rules_list():
        """Built-in rule count + the operator's custom classification rules."""
        from ai_log_analyzer import classifier as _clf
        return jsonify({
            "builtin_count": len(_clf._KB_PATTERNS),
            "custom": _clf.custom_rules(),
        })

    @app.route("/api/rules", methods=["POST"])
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

    @app.route("/api/sanitize-diff", methods=["POST"])
    @require_role("operator")
    def api_sanitize_diff():
        """Preview the sanitize-before-LLM gate on pasted text.

        Body: {"text": "..."}. Returns original, sanitized, total, by_rule.
        """
        from ai_log_analyzer.sanitize import sanitize_report
        body = request.get_json(silent=True) or {}
        text = body.get("text")
        if not isinstance(text, str):
            return jsonify({"error": "body must be {\"text\": \"...\"}"}), 400
        # Bound the preview so a huge paste can't pin a worker.
        text = text[:200_000]
        report = sanitize_report(text, mask_pii=True)
        return jsonify({
            "original": text,
            "sanitized": report["sanitized"],
            "total": report["total"],
            "by_rule": report["by_rule"],
        })

    # ── Inventory ─────────────────────────────────────────────────────────
    @app.route("/api/lab/containers", methods=["GET"])
    @require_role("viewer")
    def lab_containers():
        return jsonify({"containers": frr.list_lab_containers()})

    @app.route("/api/network-tool/devices", methods=["GET"])
    @require_role("viewer")
    def network_tool_devices():
        return jsonify({
            "available": network_tool.is_available(),
            "devices": network_tool.list_devices(),
        })

    # ── Real-config samples (Junos / EOS production gear — sanitized) ─────
    @app.route("/api/samples", methods=["GET"])
    @require_role("viewer")
    def api_samples():
        """List available sanitized real-device sample configs (no server paths)."""
        manifest_path = SAMPLES_DIR / "_manifest.json"
        if not manifest_path.is_file():
            return jsonify({"samples": []})
        import json as _json
        try:
            manifest = _json.loads(manifest_path.read_text(encoding="utf-8"))
        except _json.JSONDecodeError:
            manifest = []
        return jsonify({"samples": manifest})

    # ── Site bundles (whole-site cross-device analysis) ───────────────────
    @app.route("/api/sites", methods=["GET"])
    @require_role("viewer")
    def api_sites():
        """List available site bundles (each is a directory under sites/)."""
        if not SITES_DIR.is_dir():
            return jsonify({"sites": []})
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
        return jsonify({"sites": out})

    # ── Topology + diagrams ───────────────────────────────────────────────
    @app.route("/api/topology/<site_id>", methods=["GET"])
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
    @app.route("/api/optimize/site-wide/<site_id>", methods=["POST"])
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
    @app.route("/api/sitedoc/<site_id>", methods=["GET"])
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
    @app.route("/api/compliance/<site_id>", methods=["GET"])
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
    @app.route("/api/postmortem/<site_id>", methods=["POST"])
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
    @app.route("/api/diff", methods=["POST"])
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

    # ── AI Copilot ────────────────────────────────────────────────────────
    @app.route("/api/copilot", methods=["POST"])
    @require_role("operator")
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
    @app.route("/api/report/<site_id>", methods=["POST"])
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

    @app.route("/api/optimize/site", methods=["POST"])
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

    @app.route("/api/samples/<sample_id>", methods=["GET"])
    @require_role("viewer")
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
                    app.logger.warning("Failed to read logs for %s: %s", c, e)

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
                if size_mb > MAX_FILE_MB:
                    return jsonify({
                        "error": f"File is {size_mb:.0f}MB — over the "
                                 f"{MAX_FILE_MB:.0f}MB web limit (HTTP worker "
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

        result = analyze(events, use_llm=use_llm, dedup=dedup, evpn_causal=evpn_causal)
        result_dict = _scrub_analysis(result.to_dict())
        webhooks.notify_analysis(result_dict, source)
        return jsonify(result_dict)

    # ── Live CLI execution: DCN_Network_Tool SSH first, docker-exec fallback ──
    @app.route("/api/run", methods=["POST"])
    @require_role("admin", "run.command", _body_fields("hostname", "command", "raw"))
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
            "hint": ("Fix DCN_Network_Tool SSH key path, or use a known lab container name with "
                     "DOCKER_EXEC_FALLBACK=true"),
        }), 503

    # ── Config-aware Optimization (LLM killer feature) ────────────────────
    @app.route("/api/optimize", methods=["POST"])
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

    # ── Incident memory ────────────────────────────────────────────────────
    @app.route("/api/incidents/similar", methods=["GET"])
    @require_role("viewer")
    def api_incidents_similar():
        """Free-text search over the local incident journal.

        Requires AI_LOG_ANALYZER_INCIDENT_STORE; ?q=<text>&top=<n>.
        """
        from ai_log_analyzer.memory import get_store
        store = get_store()
        if store is None:
            return jsonify({"error": "incident store not configured — "
                            "set AI_LOG_ANALYZER_INCIDENT_STORE"}), 400
        q = (request.args.get("q") or "").strip()
        if not q:
            return jsonify({"error": "q parameter required"}), 400
        try:
            top = max(1, min(20, int(request.args.get("top") or 5)))
        except ValueError:
            top = 5
        return jsonify({"query": q, "journal_size": len(store),
                        "matches": store.find_similar(q, top_n=top)})

    # ── Live tail (SSE) ────────────────────────────────────────────────────
    sse_lock = threading.Lock()
    sse_active = [0]

    @app.route("/api/tail/<source_id>", methods=["GET"])
    def api_tail(source_id: str):
        """Server-Sent Events stream of classified events from a syslog source.

        Zero-dependency real time: EventSource in the browser, chunked
        response here — no websocket stack. The token goes in a header like
        every other route (the dashboard reads the stream with fetch(), since
        EventSource cannot set headers); it is never accepted in the URL.
        Optional ?min_severity=critical|high|medium|low filters server-side.
        """
        if rbac.auth_enabled(API_TOKEN) and current_principal() is None:
            _audit_auth_failure()
            abort(401)   # any role may watch the live tail
        src = source_manager.get(source_id)
        if src is None:
            return jsonify({"error": f"unknown source: {source_id}"}), 404
        if not hasattr(src, "fetch_new"):
            return jsonify({"error": "live tail supports syslog listener sources only"}), 400

        from ai_log_analyzer.classifier import SEV_ORDER
        min_sev = (request.args.get("min_severity") or "info").lower()
        max_rank = SEV_ORDER.get(min_sev, 4)
        try:
            poll_s = min(5.0, max(0.2, float(request.args.get("poll") or 1.0)))
        except ValueError:
            return jsonify({"error": "poll must be a number of seconds"}), 400
        cursor0 = _tail_start_cursor(src)   # start at "now"

        # Every open stream pins a worker for its whole life: cap them so a couple
        # of viewers cannot starve the API. The slot is freed when the response closes.
        try:
            max_streams = max(1, int(os.environ.get("AI_LOG_ANALYZER_MAX_SSE", "8")))
        except ValueError:
            max_streams = 8
        with sse_lock:
            if sse_active[0] >= max_streams:
                return jsonify({"error": f"too many live tail streams (max {max_streams})",
                                "hint": "close another tail or raise AI_LOG_ANALYZER_MAX_SSE"}), 503
            sse_active[0] += 1

        def stream():
            import json as _json
            import time as _time

            from ai_log_analyzer.classifier import iter_classify
            cursor = cursor0
            yield "event: hello\ndata: {}\n\n"
            idle = 0.0
            while True:
                events, cursor = src.fetch_new(cursor)
                sent = False
                for ce in iter_classify(iter(events)):
                    if SEV_ORDER.get(ce.severity, 4) <= max_rank:
                        yield f"data: {_json.dumps(_scrub_event(ce.to_dict()))}\n\n"
                        sent = True
                if sent:
                    idle = 0.0
                else:
                    idle += poll_s
                    if idle >= 15.0:  # keep proxies from timing the stream out
                        yield ": keepalive\n\n"
                        idle = 0.0
                _time.sleep(poll_s)

        resp = app.response_class(
            stream(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

        def release() -> None:
            with sse_lock:
                sse_active[0] -= 1
        resp.call_on_close(release)
        return resp

    # ── External log sources (Kibana, Splunk, Loki, syslog, LibreNMS, SolarWinds, ...) ────
    @app.route("/api/sources", methods=["GET"])
    @require_role("viewer")
    def api_sources_list():
        """List configured sources + the connector kinds the registry knows.

        URL userinfo and ``extra`` values are redacted (key names only)."""
        return jsonify({
            "sources": [_redact_source(x) for x in source_manager.describe()],
            "known_kinds": source_manager.known_kinds(),
        })

    @app.route("/api/sources", methods=["POST"])
    @require_role("admin", "config.sources.add", _body_fields("id", "type", "url"))
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
            source_manager.add(cfg, trusted=False)
        except SourceError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except (TypeError, ValueError) as exc:
            return jsonify({"ok": False, "error": f"bad config: {exc}"}), 400
        return jsonify({"ok": True, "id": src_id})

    @app.route("/api/sources/<source_id>", methods=["DELETE"])
    @require_role("admin", "config.sources.remove")
    def api_sources_remove(source_id: str):
        removed = source_manager.remove(source_id)
        return jsonify({"ok": removed})

    @app.route("/api/sources/<source_id>/test", methods=["POST"])
    @require_role("operator")
    def api_sources_test(source_id: str):
        return jsonify(source_manager.healthcheck(source_id))

    @app.route("/api/sources/<source_id>/fetch", methods=["POST"])
    @require_role("operator")
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
                    "message": _scrub_text(e.message),
                }
                for e in events
            ],
        })

    @app.route("/api/sources/<source_id>/analyze", methods=["POST"])
    @require_role("operator")
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
        result = analyze(
            events,
            use_llm=_parse_bool(body.get("use_llm", True), default=True),
            dedup=_parse_bool(body.get("dedup"), default=False),
            evpn_causal=_parse_bool(body.get("evpn_causal"), default=False),
        )
        result_dict = _scrub_analysis(result.to_dict())
        webhooks.notify_analysis(result_dict, f"source:{source_id}")
        return jsonify({"ok": True, "count": len(events), "result": result_dict})

    @app.route("/api/correlate", methods=["POST"])
    @require_role("operator")
    def api_correlate():
        """Cross-source device correlation: which hosts surface actionable
        events from >=2 sources (confirmed) vs 1 (suspected). Thin wrapper
        over correlate_from_manager(); never raises for a single bad source."""
        body = request.get_json(silent=True) or {}
        # None => all registered sources; an explicit list selects a subset.
        raw_ids = body.get("source_ids")
        source_ids = [str(s) for s in raw_ids] if isinstance(raw_ids, list) else None
        min_severity = (body.get("min_severity") or "medium").strip().lower()
        try:
            result = correlate_from_manager(
                source_ids,
                since_seconds=int(body.get("since_seconds", 3600)),
                limit=int(body.get("limit", 5000)),
                min_severity=min_severity,
            )
        except ValueError as exc:  # unknown min_severity label
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify(result)

    @app.route("/api/triage", methods=["POST"])
    @require_role("operator")
    def api_triage():
        """Per-device deep triage: verdict + health score + severity histogram
        + top processes + deduped error patterns for one host. Thin wrapper
        over triage_from_manager(); never raises for a single bad source."""
        body = request.get_json(silent=True) or {}
        hostname = (body.get("hostname") or "").strip()
        if not hostname:
            return jsonify({"ok": False, "error": "hostname required"}), 400
        raw_ids = body.get("source_ids")
        source_ids = [str(s) for s in raw_ids] if isinstance(raw_ids, list) else None
        result = triage_from_manager(
            hostname,
            source_ids,
            since_seconds=int(body.get("since_seconds", 86_400)),
            limit=int(body.get("limit", 5000)),
        )
        return jsonify(result)

    @app.route("/api/remediation", methods=["POST"])
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

    @app.route("/api/itsm/enrich", methods=["POST"])
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

    @app.route("/api/analytics/deep", methods=["POST"])
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

    @app.route("/api/itsm/servicenow/sync", methods=["POST"])
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
            client = ServiceNowClient(
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

    # Auto-load env-configured sources on app boot (idempotent).
    # ── Dashboard status bar ──────────────────────────────────────────────
    @app.route("/api/status/overview", methods=["GET"])
    @require_role("viewer")
    def api_status_overview():
        """One cheap poll for the header: spool depth, triage worker, LLM egress
        policy and vault stats, and who the caller is. No provider probing."""
        import time as _time

        from ai_log_analyzer.state_store import get_state_db
        from ai_log_analyzer.triage_worker import get_worker

        now = _time.time()
        db = get_state_db()
        spool: dict = {"enabled": db is not None, "sources": []}
        if db is not None:
            try:
                for row in db.spool_stats():
                    row["age_s"] = round(now - row["last_received_at"], 1) if row["last_received_at"] else None
                    spool["sources"].append(row)
                spool["rows"] = sum(r["rows"] for r in spool["sources"])
            except Exception as exc:   # sqlite3.Error — the bar must still render
                spool["error"] = str(exc)[:200]
        for sid in source_manager.list_ids():
            src = source_manager.get(sid)
            if hasattr(src, "stats"):
                try:
                    spool.setdefault("listeners", []).append({"id": sid, **src.stats()})
                except Exception:
                    pass
        worker = get_worker(create=False)
        triage: dict = {"configured": db is not None, "running": False}
        if worker is not None:
            st = worker.status()
            triage.update(running=st["running"], role=st["role"], sinks=st["sinks"],
                          window_events=st["window_events"], totals=st["totals"],
                          last_tick_at=(st.get("last_tick") or {}).get("at"),
                          spool_gap_rows=st.get("spool_gap_rows", {}),
                          pending_deliveries=st.get("pending_deliveries", 0),
                          sink_state=st.get("sink_state", {}))
        if db is not None:
            try:
                triage["tickets"] = db.triage_count()
            except Exception:
                pass
        actor = audit.current_actor()
        return jsonify({
            "generated_at": now,
            "spool": spool,
            "triage": triage,
            "llm": llm.egress_policy(),
            "identity": {"name": actor.name, "role": actor.role,
                         "auth": "rbac" if rbac.auth_enabled(API_TOKEN) else "dev"},
            "audit": audit.is_enabled(),
        })

    # ── Identity + audit trail ────────────────────────────────────────────
    @app.route("/api/whoami", methods=["GET"])
    @require_role("viewer")
    def api_whoami():
        actor = audit.current_actor()
        return jsonify({"name": actor.name, "role": actor.role,
                        "auth": "rbac" if rbac.auth_enabled(API_TOKEN) else "dev"})

    @app.route("/api/audit", methods=["GET"])
    @require_role("admin")
    def api_audit():
        """Newest-first audit rows. Filters: ?actor=, ?action= (``*`` wildcard), ?since=, ?limit=."""
        if not audit.is_enabled():
            return jsonify({"enabled": False, "entries": [],
                            "hint": "set AI_LOG_ANALYZER_STATE_DB or AI_LOG_ANALYZER_AUDIT_DB"})
        try:
            since = float(request.args.get("since") or 0)
            limit = int(request.args.get("limit") or 100)
        except ValueError:
            return jsonify({"error": "since and limit must be numbers"}), 400
        return jsonify({"enabled": True, "entries": audit.query(
            limit=limit, actor=request.args.get("actor", ""), action=request.args.get("action", ""),
            since=since)})

    @app.route("/api/audit/verify", methods=["GET"])
    @require_role("admin")
    def api_audit_verify():
        return jsonify(audit.verify())

    # ── Incident resolution (feeds retrieval precedents) ──────────────────
    @app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
    @require_role("operator", "incident.resolve", _body_fields("resolution"))
    def api_incident_resolve(incident_id: str):
        from ai_log_analyzer.memory import get_store
        body = request.get_json(silent=True) or {}
        resolution = str(body.get("resolution") or "").strip()
        if not resolution:
            return jsonify({"error": "resolution is required"}), 400
        store = get_store()
        if store is None:
            return jsonify({"error": "incident store not configured"}), 400
        rec = store.resolve(incident_id, resolution, resolved_by=audit.current_actor().name)
        if rec is None:
            return jsonify({"error": f"unknown incident {incident_id}"}), 404
        return jsonify({"ok": True, "incident": rec})

    # ── Retrieval index (configs, drift, topology, runbooks, incidents) ───
    def _rag_or_400():
        from ai_log_analyzer import rag
        index = rag.get_index()
        if index is None:
            abort(make_response(jsonify({"error": "retrieval index not configured "
                                                  "(set AI_LOG_ANALYZER_RAG_DB or AI_LOG_ANALYZER_STATE_DB)"}), 400))
        return index

    @app.route("/api/rag/search", methods=["GET"])
    @require_role("viewer")
    def api_rag_search():
        from ai_log_analyzer import rag
        q = (request.args.get("q") or "").strip()
        if not q:
            return jsonify({"error": "q is required"}), 400
        hosts = [h for h in (request.args.get("hosts") or "").split(",") if h.strip()]
        kinds = [k for k in (request.args.get("kinds") or "").split(",") if k.strip()] or None
        try:
            k = min(int(request.args.get("k") or 8), 50)
        except ValueError:
            return jsonify({"error": "k must be an integer"}), 400
        hits = _rag_or_400().search(q, k=k, kinds=kinds, hosts=hosts)
        return jsonify({"query": q, "hits": rag.public_evidence(
            [{**h, "id": f"S{i}"} for i, h in enumerate(hits, 1)])})

    @app.route("/api/rag/stats", methods=["GET"])
    @require_role("viewer")
    def api_rag_stats():
        return jsonify(_rag_or_400().stats())

    @app.route("/api/rag/reindex", methods=["POST"])
    @require_role("admin", "rag.reindex", _body_fields("netbox"))
    def api_rag_reindex():
        from ai_log_analyzer import rag
        body = request.get_json(silent=True) or {}
        golden = os.environ.get("AI_LOG_ANALYZER_GOLDEN_DIR", "").strip() or None
        report = rag.build_default_index(_rag_or_400(), sites_dir=SITES_DIR, golden_dir=golden,
                                         netbox=_parse_bool(body.get("netbox"), default=False))
        return jsonify({"ok": True, **report})

    @app.route("/api/rag/drift", methods=["POST"])
    @require_role("operator")
    def api_rag_drift():
        """Running vs golden config drift. Body: {running, golden} or {site, hostname} with
        AI_LOG_ANALYZER_GOLDEN_DIR / <site>/golden/ holding the golden file."""
        from ai_log_analyzer import rag
        body = request.get_json(silent=True) or {}
        running, golden = body.get("running"), body.get("golden")
        if not (isinstance(running, str) and isinstance(golden, str)):
            site, host = str(body.get("site") or ""), str(body.get("hostname") or "")
            safe_site = Path(site).name
            devices, manifest = _load_site_devices(safe_site) if safe_site else (None, None)
            dev = next((d for d in devices or [] if d.get("hostname") == host), None)
            file_of = {d.get("hostname"): d.get("file") for d in (manifest or {}).get("devices", [])}
            if dev is None:
                return jsonify({"error": "give running+golden text, or a known site + hostname"}), 400
            gdir = os.environ.get("AI_LOG_ANALYZER_GOLDEN_DIR", "").strip()
            candidates = [SITES_DIR / safe_site / "golden"] + ([Path(gdir) / safe_site, Path(gdir)] if gdir else [])
            golden = None
            for d in candidates:
                for name in (file_of.get(host) or "", f"{host}.txt", f"{host}.cfg"):
                    if name and (d / Path(name).name).is_file():
                        golden = (d / Path(name).name).read_text(encoding="utf-8", errors="replace")
                        break
                if golden is not None:
                    break
            if golden is None:
                return jsonify({"error": f"no golden config found for {host}"}), 404
            running = dev.get("config_text") or ""
        drift = rag.config_drift(running, golden)
        for h in drift["hunks"]:   # never echo secrets that differ between the two files
            h["added"] = [sanitize_line(x) for x in h["added"]]
            h["removed"] = [sanitize_line(x) for x in h["removed"]]
        return jsonify(drift)

    # ── Streaming triage worker ───────────────────────────────────────────
    def _worker_or_400():
        from ai_log_analyzer.triage_worker import get_worker
        worker = get_worker()
        if worker is None:
            abort(make_response(jsonify({"error": "streaming triage needs AI_LOG_ANALYZER_STATE_DB "
                                                  "(the syslog spool)"}), 400))
        return worker

    @app.route("/api/triage/stream/status", methods=["GET"])
    @require_role("viewer")
    def api_triage_stream_status():
        from ai_log_analyzer.triage_worker import get_worker
        worker = get_worker(create=False)
        if worker is None:
            from ai_log_analyzer.state_store import get_state_db
            return jsonify({"running": False, "configured": get_state_db() is not None})
        try:
            limit = max(1, min(int(request.args.get("limit") or 50), 500))
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400
        tickets = worker.db.triage_all(limit=limit)
        status = worker.status()
        if not _actor_allows("admin"):   # sink error text is for admins; everyone else gets the count
            last = status.get("last_tick") or {}
            status["last_tick"] = {**last, "errors": [], "error_count": len(last.get("errors") or [])}
        return jsonify({**status, "tickets": tickets})

    @app.route("/api/triage/stream/start", methods=["POST"])
    @require_role("admin", "triage.worker.start")
    def api_triage_stream_start():
        worker = _worker_or_400()
        return jsonify({"ok": True, "started": worker.start(), **worker.status()})

    @app.route("/api/triage/stream/stop", methods=["POST"])
    @require_role("admin", "triage.worker.stop")
    def api_triage_stream_stop():
        worker = _worker_or_400()
        worker.stop()
        return jsonify({"ok": True, **worker.status()})

    @app.route("/api/triage/stream/tick", methods=["POST"])
    @require_role("admin", "triage.worker.tick")
    def api_triage_stream_tick():
        """Run one triage tick now (useful for cron-style deployments)."""
        return jsonify(_worker_or_400().run_once())

    if _parse_bool(os.environ.get("AI_LOG_ANALYZER_TRIAGE_WORKER"), default=False):
        from ai_log_analyzer.triage_worker import get_worker
        worker = get_worker()
        if worker is not None:
            worker.start()   # every Gunicorn worker may start it; the lease keeps one active

    try:
        source_manager.load_from_env()
    except Exception:
        # Never let a misconfigured source crash the app.
        pass

    return app


def main() -> None:
    port = int(os.environ.get("ANALYZER_PORT", "6060"))
    # Bind localhost by default — operators must opt in to external exposure via
    # ANALYZER_HOST, and must configure an API token before doing so.
    host = os.environ.get("ANALYZER_HOST", "127.0.0.1")
    allow_noauth = _parse_bool(os.environ.get("AI_LOG_ANALYZER_ALLOW_NOAUTH"), default=False)
    try:
        rbac.principals(API_TOKEN)   # a configured but unusable credential source is fatal
        auth_on = rbac.auth_enabled(API_TOKEN)
    except rbac.RbacConfigError as exc:
        raise SystemExit(f"[ERROR] invalid API token configuration: {exc}") from exc
    if not _is_loopback_host(host) and not auth_on:
        if not allow_noauth:
            raise SystemExit(
                f"[ERROR] Refusing to bind {host!r} without authentication: every route, including "
                "/api/run, would be open to the network. Set AI_LOG_ANALYZER_API_TOKEN (>= 16 "
                "characters) or AI_LOG_ANALYZER_{VIEWER,OPERATOR,ADMIN}_TOKENS, bind 127.0.0.1, or "
                "set AI_LOG_ANALYZER_ALLOW_NOAUTH=1 to accept the risk.")
        print(f"[WARN] Binding {host} with no authentication (AI_LOG_ANALYZER_ALLOW_NOAUTH=1): "
              "all routes are unauthenticated.")
    app = create_app()
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
