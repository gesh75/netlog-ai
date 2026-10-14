"""Optional NetBox inventory enrichment.

Reads ``NETBOX_URL`` and ``NETBOX_TOKEN`` from the environment. When either is
unset the client is a no-op — no network calls, no exceptions. The token is
never written to logs, ``repr``, or exception messages.

Uses stdlib ``urllib`` only. No extra runtime dependency.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any
from urllib.request import Request

log = logging.getLogger(__name__)

_REDACTED = "***"


class NetBoxError(RuntimeError):
    """A NetBox REST call failed. Message never includes the API token."""


def is_enabled() -> bool:
    """True only when both NETBOX_URL and NETBOX_TOKEN are set."""
    return bool(_env("NETBOX_URL") and _env("NETBOX_TOKEN"))


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _nested_name(payload: Any, *keys: str) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict):
            name = (
                value.get("name")
                or value.get("model")
                or value.get("label")
                or value.get("slug")
                or ""
            )
            if name:
                return str(name)
        elif value:
            return str(value)
    return ""


class NetBoxClient:
    """Minimal NetBox REST client (devices + interfaces)."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        timeout: float = 10.0,
        opener: Any = None,
    ) -> None:
        self.url = (url if url is not None else _env("NETBOX_URL")).rstrip("/")
        self._token = token if token is not None else _env("NETBOX_TOKEN")
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def __repr__(self) -> str:
        return f"NetBoxClient(url={self.url!r}, token={_REDACTED})"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def configured(self) -> bool:
        return bool(self.url and self._token)

    def _request(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        if not self.configured:
            return {"results": []}
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        target = f"{self.url}{path}{query}"
        request = Request(
            target,
            headers={
                "Authorization": f"Token {self._token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise NetBoxError(f"NetBox HTTP {exc.code} for {path}") from None
        except urllib.error.URLError:
            raise NetBoxError(f"NetBox request failed for {path}") from None
        except TimeoutError:
            raise NetBoxError(f"NetBox timeout for {path}") from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetBoxError(f"NetBox returned non-JSON for {path}") from exc
        return payload if isinstance(payload, dict) else {"results": []}

    def lookup_device(self, hostname: str) -> dict[str, Any] | None:
        """Return a compact device record, or None if missing/disabled."""
        if not hostname or not self.configured:
            return None
        try:
            payload = self._request("/api/dcim/devices/", {"name": hostname})
        except NetBoxError as exc:
            log.warning("NetBox device lookup failed for %s: %s", hostname, exc)
            return None
        results = payload.get("results") or []
        if not results:
            return None
        device = results[0] if isinstance(results[0], dict) else {}
        primary = device.get("primary_ip") or device.get("primary_ip4") or {}
        address = ""
        if isinstance(primary, dict):
            address = str(primary.get("address") or "")
        return {
            "hostname": str(device.get("name") or hostname),
            "site": _nested_name(device, "site"),
            "role": _nested_name(device, "role", "device_role"),
            "status": _nested_name(device, "status") or str(device.get("status") or ""),
            "device_type": _nested_name(device, "device_type") or str(
                (device.get("device_type") or {}).get("model")
                if isinstance(device.get("device_type"), dict) else ""
            ),
            "primary_ip": address,
            "id": device.get("id"),
        }

    def lookup_interface(self, hostname: str, ifname: str) -> dict[str, Any] | None:
        """Return a compact interface record, or None if missing/disabled."""
        if not hostname or not ifname or not self.configured:
            return None
        try:
            payload = self._request(
                "/api/dcim/interfaces/",
                {"device": hostname, "name": ifname},
            )
        except NetBoxError as exc:
            log.warning("NetBox interface lookup failed for %s %s: %s", hostname, ifname, exc)
            return None
        results = payload.get("results") or []
        if not results:
            return None
        iface = results[0] if isinstance(results[0], dict) else {}
        return {
            "name": str(iface.get("name") or ifname),
            "enabled": bool(iface.get("enabled", True)),
            "type": _nested_name(iface, "type") or str(iface.get("type") or ""),
            "description": str(iface.get("description") or ""),
            "device": hostname,
        }

    def enrich(self, hostname: str, interface: str | None = None) -> dict[str, Any]:
        """Device (and optional interface) enrichment for one host."""
        if not self.configured:
            return {"configured": False, "hostname": hostname}
        record: dict[str, Any] = {"configured": True, "hostname": hostname}
        device = self.lookup_device(hostname)
        if device:
            record.update(device)
        else:
            record["found"] = False
            return record
        record["found"] = True
        if interface:
            iface = self.lookup_interface(hostname, interface)
            if iface:
                record["interface"] = iface
        return record


def enrich_host(hostname: str, interface: str | None = None) -> dict[str, Any]:
    """Enrich one hostname. No-op dict when NetBox is unset."""
    return NetBoxClient().enrich(hostname, interface)


def enrich_hosts(hostnames: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Enrich many hostnames. Empty dict when NetBox is unset (no network)."""
    if not is_enabled():
        return {}
    client = NetBoxClient()
    out: dict[str, dict[str, Any]] = {}
    for host in hostnames:
        if not host or host in out:
            continue
        out[host] = client.enrich(host)
    return out
