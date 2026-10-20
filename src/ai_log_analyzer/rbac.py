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

Tokens are compared in constant time. With nothing configured the API runs in
dev mode (no auth, bind to 127.0.0.1), as before.
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
            if token:
                out.append(Principal(name.strip() or f"{role}-{i + 1}", role, _digest(token.strip())))
    return out


def _file_principals(path: str) -> list[Principal]:
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.error("RBAC file %s unreadable: %s; no principals loaded from it", path, exc)
        return []
    out: list[Principal] = []
    for u in data.get("users") or []:
        role = str(u.get("role", "")).lower()
        name = str(u.get("name", "")).strip()
        digest = str(u.get("token_sha256", "")).strip().lower()
        if not digest and u.get("token"):
            digest = _digest(str(u["token"]))
        if role not in RANK or not name or len(digest) != 64:
            log.warning("RBAC file entry %r skipped (needs name, role in %s, token or token_sha256)",
                        name or "?", ROLES)
            continue
        out.append(Principal(name, role, digest))
    return out


_CACHE: dict[tuple, list[Principal]] = {}


def principals(legacy_token: str = "") -> list[Principal]:
    """Configured principals; cached per configuration (env + legacy token)."""
    path = os.environ.get("AI_LOG_ANALYZER_RBAC_FILE", "").strip()
    mtime = 0.0
    if path:
        try:
            mtime = Path(path).expanduser().stat().st_mtime
        except OSError:
            mtime = -1.0
    key = (legacy_token, path, mtime, *(os.environ.get(f"AI_LOG_ANALYZER_{r.upper()}_TOKENS", "") for r in ROLES))
    hit = _CACHE.get(key)
    if hit is None:
        hit = ([Principal("shared-token", "admin", _digest(legacy_token))] if legacy_token else [])
        hit += _env_principals() + (_file_principals(path) if path else [])
        _CACHE.clear()
        _CACHE[key] = hit
    return hit


def auth_enabled(legacy_token: str = "") -> bool:
    return bool(principals(legacy_token))


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
