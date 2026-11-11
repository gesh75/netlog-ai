"""Flask app: ingests FRR / file logs, runs analyzer, exposes /api/analyze + UI."""
from __future__ import annotations

import os
from pathlib import Path

# Auto-load env from (in priority order): local .env, ~/.env, sibling lab-tool .env.
# Loaded BEFORE any other ai_log_analyzer imports so llm.py picks up the keys.
try:
    from dotenv import load_dotenv
    _here = Path(__file__).resolve().parents[3]
    _candidates = [
        _here / ".env",
        Path.home() / ".env",
        _here.parent / "network-tool" / ".env",
        _here.parent / "log-intelligence" / ".env",
    ]
    for _p in _candidates:
        if _p.is_file():
            load_dotenv(_p, override=False)
except ImportError:
    pass

import fnmatch
import itertools
from collections.abc import Callable
from functools import wraps

from flask import Flask, abort, jsonify, request
from flask_cors import CORS

# Re-exported for tests (and only for tests): test modules reach these
# subsystems as attributes of ai_log_analyzer.web.app
# (e.g. web_app.site_doc.render_site_doc, patch.object(web_app.frr, ...)).
# They are NOT used by the handlers left in this module — do not let
# ruff --fix remove them.
from ai_log_analyzer import (
    audit,
    rbac,
    site_doc,  # noqa: F401
)
from ai_log_analyzer.adapters import frr, network_tool  # noqa: F401
from ai_log_analyzer.classifier import LogEvent

# Kept as a web.app attribute: tests patch ai_log_analyzer.web.app
# .correlate_from_manager and the incidents blueprint calls it via web_app.*.
from ai_log_analyzer.correlate import correlate_from_manager  # noqa: F401
from ai_log_analyzer.deep_report import load_site_topology

# Kept as a web.app attribute: tests patch ai_log_analyzer.web.app
# .triage_from_manager and the triage blueprint calls it via web_app.*.
from ai_log_analyzer.device_triage import triage_from_manager  # noqa: F401

# Same for ServiceNowClient: tests monkeypatch web_app.ServiceNowClient and
# the remediation blueprint constructs it via web_app.* at request time.
from ai_log_analyzer.servicenow_sync import ServiceNowClient  # noqa: F401
from ai_log_analyzer.sources import SourceError, registry
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

    A malformed token (too short) is an error, and ``AI_LOG_ANALYZER_REQUIRE_AUTH=1``
    (set by the Docker image) refuses to start with no token at all, so a container
    published on 0.0.0.0 can never come up as an open admin API.
    """
    try:
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

    # ── Blueprints ────────────────────────────────────────────────────────
    # Route handlers live in ai_log_analyzer.web.blueprints (one module
    # per area). Imported here, inside the factory, so the blueprint
    # modules can import the shared helpers from this module without a
    # circular import at package import time.
    from ai_log_analyzer.web.blueprints import (
        admin,
        analysis,
        auth,
        core,
        incidents,
        rag,
        remediation,
        sites,
        sources,
        triage,
    )
    from ai_log_analyzer.web.blueprints import llm as llm_bp
    app.register_blueprint(admin.bp)
    app.register_blueprint(analysis.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(core.bp)
    app.register_blueprint(incidents.bp)
    app.register_blueprint(llm_bp.bp)
    app.register_blueprint(rag.bp)
    app.register_blueprint(remediation.bp)
    app.register_blueprint(sites.bp)
    app.register_blueprint(sources.bp)
    app.register_blueprint(triage.bp)

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
