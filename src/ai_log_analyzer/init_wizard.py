"""Interactive setup wizard — ``netlog-ai init``.

Asks for the essentials a fresh install needs (state DB, server bind,
syslog/SNMP sources, LLM provider, RAG embeddings, backup) and writes a
working ``.env`` file. Non-destructive: an existing file is never
overwritten without an explicit ``--force`` (or an interactive "yes").

Design notes:

* Only environment variables the app already reads are written — no new
  knobs (see ``docs/ENVIRONMENT.md``). Defaults come from the current
  environment first, so ``--non-interactive`` replays whatever is already
  set and fills the rest with the documented defaults.
* Secrets (cloud API keys, the API token) are read with ``getpass`` when
  prompting on a real terminal, are never echoed back, and land in a file
  chmodded ``0600`` when one is present.
* Everything prompt-shaped takes ``input_fn`` / ``print_fn`` so the flow
  is testable with mocked input; the CLI wires the builtins.
"""
from __future__ import annotations

import getpass
import ipaddress
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlparse

# LLM providers the gateway accepts (see llm._VALID_PROVIDERS). "claude-only"
# is a mode, not a provider a fresh install should pick, so it is not offered.
PROVIDERS = ("ollama", "local", "claude", "grok", "openai")

# Provider -> env var holding its API key (empty for the local providers).
PROVIDER_KEY_ENV = {"claude": "ANTHROPIC_API_KEY", "grok": "XAI_API_KEY", "openai": "OPENAI_API_KEY"}

DEFAULT_STATE_DB = "~/.local/share/netlog-ai/state.db"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6060
DEFAULT_SYSLOG_BIND = "127.0.0.1"
DEFAULT_SYSLOG_PORT = 5514
DEFAULT_SNMP_BIND = "0.0.0.0"
DEFAULT_SNMP_PORT = 162
DEFAULT_SNMP_COMMUNITY = "public"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:latest"
DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_HYBRID_ALPHA = 0.5
DEFAULT_BACKUP_KEEP = 7
MIN_API_TOKEN_LEN = 16

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


# ── Validators (raise ValueError with a human message, or return the value) ──

def validate_port(raw: str) -> int:
    try:
        port = int(raw.strip())
    except ValueError:
        raise ValueError(f"{raw!r} is not a number") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def validate_host(raw: str) -> str:
    host = raw.strip()
    if not host:
        raise ValueError("host must not be empty")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if len(host) > 253 or not _HOST_RE.match(host):
        raise ValueError(f"{host!r} is not a valid hostname or IP address")
    return host


def validate_url(raw: str) -> str:
    url = raw.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"{url!r} is not an http(s) URL (e.g. http://localhost:11434)")
    return url


def validate_path(raw: str) -> str:
    """An expandable file path whose parent can be created or is writable."""
    path = Path(raw.strip()).expanduser()
    if not str(path):
        raise ValueError("path must not be empty")
    if path.exists() and path.is_dir():
        raise ValueError(f"{path} is a directory, expected a file path")
    ancestor = path.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if not ancestor.is_dir() or not os.access(ancestor, os.W_OK):
        raise ValueError(f"cannot write under {path.parent} (no writable directory above it)")
    return str(path)


def validate_cidr_list(raw: str) -> str:
    """Comma-separated IPs/CIDRs; empty means 'allow all'."""
    items = [item.strip() for item in raw.split(",") if item.strip()]
    for item in items:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError(f"{item!r} is not an IP address or CIDR") from None
    return ",".join(items)


def validate_alpha(raw: str) -> float:
    try:
        alpha = float(raw.strip())
    except ValueError:
        raise ValueError(f"{raw!r} is not a number") from None
    if not 0.0 <= alpha <= 1.0:
        raise ValueError(f"hybrid weight {alpha} is out of range (0.0-1.0)")
    return alpha


def validate_keep(raw: str) -> int:
    try:
        keep = int(raw.strip())
    except ValueError:
        raise ValueError(f"{raw!r} is not a number") from None
    if keep < 1:
        raise ValueError(f"keep {keep} is out of range (at least 1)")
    return keep


def validate_token(raw: str) -> str:
    token = raw.strip()
    if token and len(token) < MIN_API_TOKEN_LEN:
        raise ValueError(f"API token must be at least {MIN_API_TOKEN_LEN} characters")
    return token


def is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "localhost.localdomain")


# ── Config ───────────────────────────────────────────────────────────────────

@dataclass
class InitConfig:
    """Everything the wizard writes. Defaults mirror docs/ENVIRONMENT.md."""

    state_db: str = DEFAULT_STATE_DB
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    syslog_enabled: bool = True
    syslog_bind: str = DEFAULT_SYSLOG_BIND
    syslog_port: int = DEFAULT_SYSLOG_PORT
    syslog_allow: str = ""
    snmp_enabled: bool = False
    snmp_bind: str = DEFAULT_SNMP_BIND
    snmp_port: int = DEFAULT_SNMP_PORT
    snmp_community: str = DEFAULT_SNMP_COMMUNITY
    llm_provider: str = "ollama"
    ollama_url: str = DEFAULT_OLLAMA_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    cloud_api_key: str = ""
    allow_cloud_fallback: bool = False
    embeddings_enabled: bool = True
    embedding_model: str = DEFAULT_EMBEDDING_MODEL
    hybrid_alpha: float = DEFAULT_HYBRID_ALPHA
    triage_enabled: bool = False
    backup_keep: int = DEFAULT_BACKUP_KEEP
    api_token: str = ""

    @classmethod
    def from_env(cls) -> InitConfig:
        """Defaults from the current environment, else the documented defaults."""
        env = os.environ
        provider = env.get("LLM_PROVIDER", "ollama").strip().lower() or "ollama"
        if provider not in PROVIDERS:
            provider = "ollama"
        key_env = PROVIDER_KEY_ENV.get(provider, "")
        embeddings_raw = env.get("AI_LOG_ANALYZER_EMBEDDINGS", "auto").strip().lower()
        try:
            port = int(env.get("ANALYZER_PORT", str(DEFAULT_PORT)))
        except ValueError:
            port = DEFAULT_PORT
        try:
            syslog_port = int(env.get("NETLOG_SOURCE_syslog_PORT", str(DEFAULT_SYSLOG_PORT)))
        except ValueError:
            syslog_port = DEFAULT_SYSLOG_PORT
        try:
            snmp_port = int(env.get("NETLOG_SOURCE_traps_PORT", str(DEFAULT_SNMP_PORT)))
        except ValueError:
            snmp_port = DEFAULT_SNMP_PORT
        try:
            alpha = float(env.get("AI_LOG_ANALYZER_RAG_HYBRID_ALPHA", str(DEFAULT_HYBRID_ALPHA)))
        except ValueError:
            alpha = DEFAULT_HYBRID_ALPHA
        return cls(
            state_db=env.get("AI_LOG_ANALYZER_STATE_DB", "").strip() or DEFAULT_STATE_DB,
            host=env.get("ANALYZER_HOST", "").strip() or DEFAULT_HOST,
            port=port if 1 <= port <= 65535 else DEFAULT_PORT,
            syslog_bind=env.get("NETLOG_SOURCE_syslog_BIND", "").strip() or DEFAULT_SYSLOG_BIND,
            syslog_port=syslog_port if 1 <= syslog_port <= 65535 else DEFAULT_SYSLOG_PORT,
            syslog_allow=env.get("AI_LOG_ANALYZER_SYSLOG_ALLOW", "").strip(),
            snmp_enabled=bool(env.get("NETLOG_SOURCE_traps_TYPE", "").strip()),
            snmp_port=snmp_port if 1 <= snmp_port <= 65535 else DEFAULT_SNMP_PORT,
            snmp_community=env.get("AI_LOG_ANALYZER_SNMP_COMMUNITY", "").strip()
            or DEFAULT_SNMP_COMMUNITY,
            llm_provider=provider,
            ollama_url=env.get("OLLAMA_URL", "").strip() or DEFAULT_OLLAMA_URL,
            ollama_model=env.get("OLLAMA_MODEL", "").strip() or DEFAULT_OLLAMA_MODEL,
            cloud_api_key=env.get(key_env, "").strip() if key_env else "",
            embeddings_enabled=embeddings_raw not in ("0", "off", "false", "no"),
            embedding_model=env.get("AI_LOG_ANALYZER_EMBEDDING_MODEL", "").strip()
            or DEFAULT_EMBEDDING_MODEL,
            hybrid_alpha=alpha if 0.0 <= alpha <= 1.0 else DEFAULT_HYBRID_ALPHA,
            triage_enabled=env.get("AI_LOG_ANALYZER_TRIAGE_WORKER", "").strip().lower()
            in ("1", "true", "yes", "on"),
            api_token=env.get("AI_LOG_ANALYZER_API_TOKEN", "").strip(),
        )

    def validate(self) -> None:
        """Raise ValueError on the first invalid field (all fields are checked)."""
        validate_path(self.state_db)
        validate_host(self.host)
        validate_port(str(self.port))
        if self.syslog_enabled:
            validate_host(self.syslog_bind)
            validate_port(str(self.syslog_port))
            validate_cidr_list(self.syslog_allow)
        if self.snmp_enabled:
            validate_host(self.snmp_bind)
            validate_port(str(self.snmp_port))
        if self.llm_provider not in PROVIDERS:
            raise ValueError(f"unknown LLM provider {self.llm_provider!r} (choose: {', '.join(PROVIDERS)})")
        if self.llm_provider == "ollama":
            validate_url(self.ollama_url)
        validate_alpha(str(self.hybrid_alpha))
        validate_keep(str(self.backup_keep))
        validate_token(self.api_token)

    @property
    def has_secret(self) -> bool:
        return bool(self.cloud_api_key or self.api_token)


def render_env(cfg: InitConfig) -> str:
    """Render the config as a commented ``.env`` file (only documented vars)."""
    lines = [
        "# netlog-ai — generated by `netlog-ai init` (edit freely; see docs/ENVIRONMENT.md).",
        "# Start the server from this directory with: netlog-ai serve",
        "",
        "# ── Server ────────────────────────────────────────────────────────────────────",
        f"ANALYZER_HOST={cfg.host}",
        f"ANALYZER_PORT={cfg.port}",
        "",
        "# ── Shared state ────────────────────────────────────────────────────────────",
        "# One SQLite WAL file: syslog spool, incident memory, audit log, RAG index.",
        f"AI_LOG_ANALYZER_STATE_DB={cfg.state_db}",
        "",
    ]
    if cfg.api_token:
        lines += [
            "# ── Security ────────────────────────────────────────────────────────────────",
            "# Admin token (Bearer / X-API-Token). Required for a non-loopback bind.",
            f"AI_LOG_ANALYZER_API_TOKEN={cfg.api_token}",
            "",
        ]
    if cfg.syslog_enabled:
        lines += [
            "# ── Syslog source ───────────────────────────────────────────────────────────",
            "# Point devices at this UDP listener; allow-list senders on untrusted nets.",
            "NETLOG_SOURCE_syslog_TYPE=syslog",
            f"NETLOG_SOURCE_syslog_URL=udp://{cfg.syslog_bind}",
            f"NETLOG_SOURCE_syslog_BIND={cfg.syslog_bind}",
            f"NETLOG_SOURCE_syslog_PORT={cfg.syslog_port}",
        ]
        if cfg.syslog_allow:
            lines.append(f"NETLOG_SOURCE_syslog_ALLOW={cfg.syslog_allow}")
        lines.append("")
    if cfg.snmp_enabled:
        lines += [
            "# ── SNMP trap receiver ──────────────────────────────────────────────────────",
            "# UDP 162 is privileged: run as root, grant CAP_NET_BIND_SERVICE, or use an",
            "# unprivileged port and redirect 162 to it. authPriv traps are not supported.",
            "NETLOG_SOURCE_traps_TYPE=snmp",
            f"NETLOG_SOURCE_traps_URL=udp://{cfg.snmp_bind}:{cfg.snmp_port}",
            f"NETLOG_SOURCE_traps_BIND={cfg.snmp_bind}",
            f"NETLOG_SOURCE_traps_PORT={cfg.snmp_port}",
            f"NETLOG_SOURCE_traps_COMMUNITY={cfg.snmp_community}",
            "",
        ]
    lines += [
        "# ── LLM provider ────────────────────────────────────────────────────────────",
        f"LLM_PROVIDER={cfg.llm_provider}",
    ]
    if cfg.llm_provider == "ollama":
        lines += [
            f"OLLAMA_URL={cfg.ollama_url}",
            f"OLLAMA_MODEL={cfg.ollama_model}",
        ]
    if cfg.llm_provider == "local":
        lines.append("# Docker Model Runner on http://localhost:12434 (MODEL_RUNNER_URL).")
    key_env = PROVIDER_KEY_ENV.get(cfg.llm_provider, "")
    if key_env:
        if cfg.cloud_api_key:
            lines.append(f"{key_env}={cfg.cloud_api_key}")
        else:
            lines.append(f"# {key_env}=   # set your key (or export it); the provider stays")
            lines.append("# # unavailable in /api/llm/status until it is set.")
    if cfg.allow_cloud_fallback:
        lines.append("ALLOW_CLOUD_FALLBACK=true   # sanitized text may leave the site on local failure")
    lines.append("")
    lines += [
        "# ── Retrieval (RAG) ───────────────────────────────────────────────────────────",
        "# Semantic search blends BM25 with Ollama embeddings; without Ollama it is",
        "# exactly the BM25 ranking as before.",
        f"AI_LOG_ANALYZER_EMBEDDINGS={'auto' if cfg.embeddings_enabled else '0'}",
        f"AI_LOG_ANALYZER_EMBEDDING_MODEL={cfg.embedding_model}",
        f"AI_LOG_ANALYZER_RAG_HYBRID_ALPHA={cfg.hybrid_alpha}",
        "",
    ]
    if cfg.triage_enabled:
        lines += [
            "# ── Streaming triage ────────────────────────────────────────────────────────",
            "# Sinks default to dry-run; set AI_LOG_ANALYZER_TRIAGE_SINKS to send tickets.",
            "AI_LOG_ANALYZER_TRIAGE_WORKER=true",
            "",
        ]
    lines += [
        "# ── Backups ───────────────────────────────────────────────────────────────────",
        "# Nightly snapshot (see the cron line printed by `netlog-ai init`):",
        f"#   0 3 * * * netlog-ai backup --keep {cfg.backup_keep}",
        "",
    ]
    return "\n".join(lines)


def write_config(path: str | Path, text: str, force: bool,
                 confirm: Callable[[str], bool] | None = None) -> Path:
    """Write ``text`` to ``path`` (creating parents); never clobber silently.

    ``confirm`` is a ``(prompt) -> bool`` callable used when the file exists
    and ``force`` is False; without one, an existing file is refused.
    Returns the written path. Raises ``FileExistsError`` on refusal.
    """
    target = Path(path).expanduser()
    if target.exists() and not force:
        ok = False
        if confirm is not None:
            ok = confirm(f"{target} already exists — overwrite it?")
        if not ok:
            raise FileExistsError(f"refusing to overwrite existing config: {target} (use --force)")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    # A file holding a secret gets owner-only permissions; a plain config is
    # left at the default umask (the caller may tighten it afterwards).
    if any(line.split("=", 1)[0] in ("ANTHROPIC_API_KEY", "XAI_API_KEY", "OPENAI_API_KEY",
                                     "AI_LOG_ANALYZER_API_TOKEN")
           and "=" in line and line.split("=", 1)[1].strip()
           for line in text.splitlines() if not line.startswith("#")):
        os.chmod(target, 0o600)
    return target


def next_steps(cfg: InitConfig, path: str | Path) -> str:
    """Exact commands to start the server and verify it, for this config."""
    out_dir = str(Path(path).expanduser().parent)
    base = f"http://{cfg.host}:{cfg.port}"
    steps = [
        "",
        f"Wrote {path}",
    ]
    if out_dir not in (".", ""):
        steps.append(f"     (config directory: {out_dir})")
    steps.append("")
    steps.append("Next steps:")
    n = 0

    def step(text: str) -> str:
        nonlocal n
        n += 1
        return f"  {n}. {text}"

    steps += [
        step("Start the server (from this directory):"),
        "       netlog-ai serve",
        "     (Installed via pip rather than run from the checkout? Load the",
        f"      file first: set -a; source {path}; set +a)",
        step("Check it answers:"),
        f"       curl {base}/api/health",
        "     (expect HTTP 200 with {\"status\": \"ok\", ...})",
        step("Verify the whole setup:"),
        "       netlog-ai doctor",
    ]
    if cfg.syslog_enabled:
        steps.append(step(
            f"Point a device's syslog destination at {cfg.syslog_bind}:{cfg.syslog_port} "
            "(UDP), then watch Live Tail in the Logs tab."))
    if cfg.snmp_enabled:
        steps.append(step(
            f"Send traps to {cfg.snmp_bind}:{cfg.snmp_port} "
            f"(community {cfg.snmp_community!r}); see docs/OPERATIONS.md for a snmptrap test."))
    if cfg.llm_provider == "ollama" and cfg.embeddings_enabled:
        steps.append(step(
            "For semantic search, pull the embedding model once:"
            f" ollama pull {cfg.embedding_model}, then: netlog-ai rag index"))
    steps += [
        step("Nightly backup (cron):"),
        f"       0 3 * * * netlog-ai backup --keep {cfg.backup_keep}",
        "     (snapshots AI_LOG_ANALYZER_STATE_DB; restore with netlog-ai restore --force)",
        step("Prometheus scrape of the tool itself:"),
        "       metrics_path: /api/metrics",
        f"       targets: ['{cfg.host}:{cfg.port}']   # job_name: netlog-ai; add a",
        "       # viewer Bearer token under authorization: when RBAC is on",
        "       # (Grafana dashboard: grafana/netlog-ai.json)",
    ]
    return "\n".join(steps)


# ── Prompts (input_fn / print_fn are injectable for tests) ───────────────────

_T = TypeVar("_T")


def _ask(prompt: str, default: str, parse: Callable[[str], _T], input_fn, print_fn) -> _T:
    """One prompt: empty input takes ``default``; bad input re-prompts."""
    while True:
        shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
        try:
            raw = input_fn(shown)
        except EOFError:
            print_fn("(no input — using the default)")
            return parse(default) if default else parse("")
        raw = raw.strip()
        if not raw:
            return parse(default)
        try:
            return parse(raw)
        except ValueError as exc:
            print_fn(f"  invalid: {exc} — try again (Enter keeps [{default}])")


def _ask_yes_no(prompt: str, default: bool, input_fn, print_fn) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input_fn(f"{prompt} [{hint}]: ").strip().lower()
        except EOFError:
            print_fn("(no input — using the default)")
            return default
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print_fn("  please answer y or n")


def _ask_choice(prompt: str, choices: tuple[str, ...], default: str, input_fn, print_fn) -> str:
    numbered = ", ".join(f"{i + 1}={c}" for i, c in enumerate(choices))
    while True:
        try:
            raw = input_fn(f"{prompt} ({numbered}) [{default}]: ").strip().lower()
        except EOFError:
            print_fn("(no input — using the default)")
            return default
        if not raw:
            return default
        if raw in choices:
            return raw
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        print_fn(f"  choose one of: {', '.join(choices)} (or its number)")


def _ask_secret(prompt: str, input_fn, print_fn) -> str:
    """Secret prompt: getpass on a real terminal, the injected input in tests."""
    if input_fn is input:
        try:
            return getpass.getpass(f"{prompt} (hidden, Enter to skip): ").strip()
        except (EOFError, KeyboardInterrupt):
            print_fn("(no input — skipped)")
            return ""
    return input_fn(f"{prompt} (Enter to skip): ").strip()


def prompt_config(cfg: InitConfig, input_fn=input, print_fn=print) -> InitConfig:
    """Interactive walk-through; every question is skippable (Enter = default)."""
    print_fn("netlog-ai init — answer each question, or press Enter for the default.")
    print_fn("")
    cfg.state_db = _ask("State database path", cfg.state_db, validate_path, input_fn, print_fn)
    cfg.host = _ask("Server bind address", cfg.host, validate_host, input_fn, print_fn)
    cfg.port = _ask("Server port", str(cfg.port), validate_port, input_fn, print_fn)
    cfg.syslog_enabled = _ask_yes_no("Enable the syslog listener?", cfg.syslog_enabled, input_fn, print_fn)
    if cfg.syslog_enabled:
        cfg.syslog_bind = _ask("Syslog bind address", cfg.syslog_bind, validate_host, input_fn, print_fn)
        cfg.syslog_port = _ask("Syslog UDP port", str(cfg.syslog_port), validate_port, input_fn, print_fn)
        cfg.syslog_allow = _ask(
            "Syslog sender allow-list (IPs/CIDRs, comma-separated; empty = allow all)",
            cfg.syslog_allow, validate_cidr_list, input_fn, print_fn)
    cfg.snmp_enabled = _ask_yes_no("Also enable the SNMP trap receiver?", cfg.snmp_enabled, input_fn, print_fn)
    if cfg.snmp_enabled:
        cfg.snmp_bind = _ask("SNMP bind address", cfg.snmp_bind, validate_host, input_fn, print_fn)
        cfg.snmp_port = _ask("SNMP UDP port", str(cfg.snmp_port), validate_port, input_fn, print_fn)
        if cfg.snmp_port < 1024:
            print_fn("  note: ports below 1024 are privileged — run as root, grant")
            print_fn("  CAP_NET_BIND_SERVICE, or redirect 162 to an unprivileged port.")
        cfg.snmp_community = _ask("SNMPv2c community", cfg.snmp_community, str, input_fn, print_fn)
    cfg.llm_provider = _ask_choice("LLM provider", PROVIDERS, cfg.llm_provider, input_fn, print_fn)
    if cfg.llm_provider == "ollama":
        cfg.ollama_url = _ask("Ollama base URL", cfg.ollama_url, validate_url, input_fn, print_fn)
        cfg.ollama_model = _ask("Ollama chat model", cfg.ollama_model, str, input_fn, print_fn)
        cfg.allow_cloud_fallback = _ask_yes_no(
            "Allow cloud fallback if the local model fails?", cfg.allow_cloud_fallback,
            input_fn, print_fn)
    else:
        key_env = PROVIDER_KEY_ENV.get(cfg.llm_provider, "")
        if key_env:
            existing = "set" if cfg.cloud_api_key else "not set"
            print_fn(f"  {key_env} is currently {existing}; it is never echoed back.")
            key = _ask_secret(f"{key_env}", input_fn, print_fn)
            if key:
                cfg.cloud_api_key = key
            if not cfg.cloud_api_key:
                print_fn("  warning: no key — the provider will report unavailable in")
                print_fn("  /api/llm/status until the key is set (the server still starts).")
    cfg.embeddings_enabled = _ask_yes_no(
        "Enable semantic (hybrid) RAG search via Ollama embeddings?",
        cfg.embeddings_enabled, input_fn, print_fn)
    if cfg.embeddings_enabled:
        cfg.embedding_model = _ask("Embedding model", cfg.embedding_model, str, input_fn, print_fn)
        cfg.hybrid_alpha = _ask(
            "Hybrid weight for BM25 (0.0 = vector-only, 1.0 = keyword-only)",
            str(cfg.hybrid_alpha), validate_alpha, input_fn, print_fn)
    cfg.triage_enabled = _ask_yes_no(
        "Start the streaming triage worker with the web app?", cfg.triage_enabled,
        input_fn, print_fn)
    cfg.backup_keep = _ask("Backups to keep (nightly cron)", str(cfg.backup_keep), validate_keep,
                           input_fn, print_fn)
    if not is_loopback_host(cfg.host):
        print_fn("  warning: a non-loopback bind exposes the API to the network —")
        print_fn("  set an API token below (the server refuses to start without one).")
    token = _ask_secret("API token (admin)", input_fn, print_fn)
    if token:
        try:
            cfg.api_token = validate_token(token)
        except ValueError as exc:
            print_fn(f"  invalid: {exc} — leaving the token unset")
    return cfg


def run_init(output: str | Path, non_interactive: bool, force: bool,
             overrides: dict | None = None,
             input_fn=input, print_fn=print) -> int:
    """Run the wizard. Returns a process exit code (0 ok, 1 write refused, 2 bad input)."""
    cfg = InitConfig.from_env()
    for name, value in (overrides or {}).items():
        if value is not None:
            setattr(cfg, name, value)
    try:
        cfg.validate()
    except ValueError as exc:
        print_fn(f"error: invalid configuration: {exc}")
        return 2
    if not non_interactive:
        try:
            cfg = prompt_config(cfg, input_fn=input_fn, print_fn=print_fn)
        except KeyboardInterrupt:
            print_fn("\nAborted — nothing was written.")
            return 130
        cfg.validate()
    if cfg.llm_provider in PROVIDER_KEY_ENV and not cfg.cloud_api_key:
        print_fn(f"warning: {PROVIDER_KEY_ENV[cfg.llm_provider]} is not set — "
                 f"{cfg.llm_provider} will report unavailable until it is.")
    if not is_loopback_host(cfg.host) and not cfg.api_token:
        print_fn("warning: non-loopback bind with no API token — `netlog-ai serve` "
                 "will refuse to start until a token is set (or AI_LOG_ANALYZER_ALLOW_NOAUTH=1).")
    text = render_env(cfg)
    confirm = None if non_interactive else (
        lambda prompt: _ask_yes_no(prompt, False, input_fn, print_fn))
    try:
        written = write_config(output, text, force=force, confirm=confirm)
    except FileExistsError as exc:
        print_fn(f"error: {exc}")
        return 1
    except OSError as exc:
        print_fn(f"error: cannot write {output}: {exc}")
        return 1
    print_fn(next_steps(cfg, written))
    return 0
