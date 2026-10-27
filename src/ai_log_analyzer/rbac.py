"""Role-based API access: viewer < operator < admin.

=========  ==================================================================
viewer     read-only dashboards: incident history search, live tail, triage
           worker status, retrieval search, full ``/api/llm/status``
operator   analysis and incident work: analyze, correlate, triage, copilot,
           remediation plans, ITSM enrichment, incident resolution notes
admin      privileged actions: ``/api/run`` (executes commands on lab
           devices), LLM provider / toggle changes, source and rule
           configuration, triage worker start/stop, index rebuilds, audit log
=========  ==================================================================

Principals are configured from the environment; any of these turns auth on:

* ``AI_LOG_ANALYZER_API_TOKEN``: the legacy shared token, now the ``admin``
  role, so existing deployments keep working unchanged.
* ``AI_LOG_ANALYZER_VIEWER_TOKENS`` / ``_OPERATOR_TOKENS`` / ``_ADMIN_TOKENS``:
  comma-separated ``name:token`` pairs (a bare token gets a generated name).
* ``AI_LOG_ANALYZER_RBAC_FILE``: JSON
  ``{"users": [{"name": "alice", "role": "operator", "token_sha256": "<hex>"}]}``.
  Prefer ``token_sha256`` so the file holds no usable secret; ``token``
  (plaintext) is accepted too.

Tokens are compared in constant time and must be at least ``MIN_TOKEN_LEN``
(16) characters; a shorter one is a configuration error (``RbacConfigError``),
never silently dropped, because dropping the only token would switch auth off.
The same holds for ``AI_LOG_ANALYZER_RBAC_FILE``: once it is configured, auth is
on for good. A file that is missing, unreadable, not valid JSON or without a
usable user is a ``RbacConfigError``: the server refuses to start, and a file
that breaks while the server runs makes every request fail with 503 until it is
fixed (the file is re-read when it changes). It never falls back to dev mode.
With nothing configured the API runs in dev mode (no auth, bind to 127.0.0.1),
as before; set ``AI_LOG_ANALYZER_REQUIRE_AUTH=1`` to refuse that (the Docker
image does).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

ROLES = ("viewer", "operator", "admin")
RANK = {"viewer": 1, "operator": 2, "admin": 3}
MIN_TOKEN_LEN = 16


class RbacConfigError(ValueError):
    """A configured token or RBAC file is unusable; raised instead of failing open."""


def _check_len(token: str, where: str) -> str:
    if len(token) < MIN_TOKEN_LEN:
        raise RbacConfigError(
            f"{where}: token is {len(token)} characters; use at least {MIN_TOKEN_LEN} "
            "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`)")
    return token


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    token_sha256: str

    def allows(self, required: str) -> bool:
        return RANK.get(self.role, 0) >= RANK[required]


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _env_principals() -> list[Principal]:
    out: list[Principal] = []
    for role in ROLES:
        raw = os.environ.get(f"AI_LOG_ANALYZER_{role.upper()}_TOKENS", "")
        for i, item in enumerate(x.strip() for x in raw.split(",")):
            if not item:
                continue
            name, sep, token = item.partition(":")
            if not sep:
                name, token = f"{role}-{i + 1}", item
            token = token.strip()
            if token:
                label = name.strip() or f"{role}-{i + 1}"
                out.append(Principal(label, role, _digest(_check_len(token, f"AI_LOG_ANALYZER_{role.upper()}_TOKENS entry {label!r}"))))
    return out


def _rbac_path() -> str:
    return os.environ.get("AI_LOG_ANALYZER_RBAC_FILE", "").strip()


def _file_principals(path: str) -> list[Principal]:
    """Principals from the RBAC file. A configured file that cannot be used is an error, never an
    empty list: an empty list would read as "no auth configured" and open every route."""
    where = f"AI_LOG_ANALYZER_RBAC_FILE {path}"
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RbacConfigError(f"{where}: unreadable or not valid JSON ({exc})") from exc
    users = data.get("users") if isinstance(data, dict) else None
    if not isinstance(users, list):
        raise RbacConfigError(f'{where}: must be a JSON object {{"users": [...]}}')
    out: list[Principal] = []
    for u in users:
        if not isinstance(u, dict):
            log.warning("RBAC file entry skipped (not an object)")
            continue
        role = str(u.get("role", "")).lower()
        name = str(u.get("name", "")).strip()
        digest = str(u.get("token_sha256", "")).strip().lower()
        if not digest and u.get("token") and role in RANK and name:   # only usable entries are length-checked
            digest = _digest(_check_len(str(u["token"]), f"RBAC file entry {name!r}"))
        if role not in RANK or not name or len(digest) != 64:
            log.warning("RBAC file entry %r skipped (needs name, role in %s, token or token_sha256)",
                        name or "?", ROLES)
            continue
        out.append(Principal(name, role, digest))
    if not out:
        raise RbacConfigError(f"{where}: holds no usable user (each needs name, role in {ROLES} and "
                              "token or token_sha256)")
    return out


# Per configuration: the principal list, or the text of the RbacConfigError it produced (cached so a
# broken file is logged once per change, not once per request).
_CACHE: dict[tuple, list[Principal] | str] = {}


def principals(legacy_token: str = "") -> list[Principal]:
    """Configured principals; cached per configuration (env + legacy token + RBAC file state).

    Raises ``RbacConfigError`` when any configured credential source is unusable."""
    path = _rbac_path()
    stamp: tuple[int, int] = (0, 0)
    if path:
        try:
            st = Path(path).expanduser().stat()
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = (-1, -1)
    key = (legacy_token, path, stamp, *(os.environ.get(f"AI_LOG_ANALYZER_{r.upper()}_TOKENS", "") for r in ROLES))
    hit = _CACHE.get(key)
    if hit is None:
        try:
            hit = ([Principal("shared-token", "admin", _digest(_check_len(legacy_token, "AI_LOG_ANALYZER_API_TOKEN")))]
                   if legacy_token else [])
            hit += _env_principals() + (_file_principals(path) if path else [])
        except RbacConfigError as exc:
            hit = str(exc)
            log.error("%s; authentication stays ON and every request is refused until this is fixed", hit)
        _CACHE.clear()
        _CACHE[key] = hit
    if isinstance(hit, str):
        raise RbacConfigError(hit)
    return hit


def auth_enabled(legacy_token: str = "") -> bool:
    """Whether any credential source is configured. A configured RBAC file counts even while it is
    unusable, so a bad file can never read as "no auth"."""
    if _rbac_path():
        return True
    return bool(principals(legacy_token))


def auth_required() -> bool:
    """``AI_LOG_ANALYZER_REQUIRE_AUTH=1``: refuse to run without any token (fail closed)."""
    return os.environ.get("AI_LOG_ANALYZER_REQUIRE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}


def authenticate(token: str, legacy_token: str = "") -> Principal | None:
    """The principal owning ``token``, or None. Checks every entry (constant time)."""
    if not token:
        return None
    digest = _digest(token)
    found = None
    for p in principals(legacy_token):
        if hmac.compare_digest(p.token_sha256, digest) and found is None:
            found = p
    return found
