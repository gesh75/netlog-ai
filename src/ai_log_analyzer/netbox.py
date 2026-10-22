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


def _guarded_open(request: Request, timeout: float = 10.0):
    """Default transport: SSRF-validated, redirects refused (the ``Authorization``
    token must not follow a 3xx). NETBOX_URL is operator-configured, so private
    addresses are allowed; metadata/link-local targets never are."""
    # lazy import: avoids a cycle at package load
    from ai_log_analyzer.sources import outbound
    return outbound.safe_urlopen(request, timeout=timeout, allow_private=True, require_https=False)


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
        self._opener = opener or _guarded_open

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
        """Return a compact device record, or None if missing/disabled/unreachable."""
        try:
            return self._device_record(hostname)
        except NetBoxError as exc:
            log.warning("NetBox device lookup failed for %s: %s", hostname, exc)
            return None

    def _device_record(self, hostname: str) -> dict[str, Any] | None:
        """Like ``lookup_device`` but raises NetBoxError instead of hiding an API error."""
        if not hostname or not self.configured:
            return None
        payload = self._request("/api/dcim/devices/", {"name": hostname})
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
        """Return a compact interface record, or None if missing/disabled/unreachable."""
        try:
            return self._interface_record(hostname, ifname)
        except NetBoxError as exc:
            log.warning("NetBox interface lookup failed for %s %s: %s", hostname, ifname, exc)
            return None

    def _interface_record(self, hostname: str, ifname: str) -> dict[str, Any] | None:
        if not hostname or not ifname or not self.configured:
            return None
        payload = self._request(
            "/api/dcim/interfaces/",
            {"device": hostname, "name": ifname},
        )
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
        try:
            device = self._device_record(hostname)
        except NetBoxError as exc:
            # An API/transport failure is not "device not in NetBox".
            log.warning("NetBox device lookup failed for %s: %s", hostname, exc)
            record.update({"found": None, "error": str(exc)})
            return record
        if device:
            record.update(device)
        else:
            record["found"] = False
            return record
        record["found"] = True
        if interface:
            try:
                iface = self._interface_record(hostname, interface)
            except NetBoxError as exc:
                log.warning("NetBox interface lookup failed for %s %s: %s", hostname, interface, exc)
                record["interface_error"] = str(exc)
            else:
                if iface:
                    record["interface"] = iface
        return record

    def _iter_results(
        self, path: str, params: dict[str, str] | None = None,
    ) -> Iterable[dict[str, Any]]:
        """Yield every result page. Stops when NetBox omits ``next``."""
        query = dict(params or {})
        query.setdefault("limit", "200")
        offset = 0
        while True:
            query["offset"] = str(offset)
            payload = self._request(path, query)
            results = payload.get("results") or []
            yielded = 0
            for item in results:
                if isinstance(item, dict):
                    yielded += 1
                    yield item
            if not payload.get("next") or yielded == 0:
                return
            offset += yielded

    def build_site_manifest(self, site: str | None = None) -> dict[str, Any]:
        """Devices + cable adjacency for one site (or the whole inventory).

        Cable terminations whose ``device`` is ``None`` — FrontPort / RearPort
        on an unbound patch panel, CircuitTermination — are skipped so they
        cannot raise ``AttributeError``.
        """
        if not self.configured:
            return _empty_manifest(site, configured=False)

        device_params: dict[str, str] = {}
        if site:
            device_params["site"] = site
        devices: list[dict[str, Any]] = []
        for raw in self._iter_results("/api/dcim/devices/", device_params):
            name = str(raw.get("name") or "")
            if not name:
                continue
            devices.append({
                "hostname": name,
                "site": _nested_name(raw, "site") or (site or ""),
                "role": _nested_name(raw, "role", "device_role"),
                "status": _nested_name(raw, "status") or str(raw.get("status") or ""),
                "device_type": _nested_name(raw, "device_type"),
                "id": raw.get("id"),
            })

        cable_params: dict[str, str] = {}
        if site:
            cable_params["site"] = site
        links: list[dict[str, str]] = []
        adjacency: dict[str, list[str]] = {}
        skipped = 0
        for cable in self._iter_results("/api/dcim/cables/", cable_params):
            ends = _cable_device_ends(cable)
            skipped += ends["skipped"]
            left, right = ends["devices"]
            if not left or not right or left == right:
                continue
            a_if, b_if = ends["interfaces"]
            links.append({
                "a": left, "b": right,
                "a_iface": a_if, "b_iface": b_if,
            })
            adjacency.setdefault(left, [])
            adjacency.setdefault(right, [])
            if right not in adjacency[left]:
                adjacency[left].append(right)
            if left not in adjacency[right]:
                adjacency[right].append(left)

        return {
            "site": site or _first_device_site(devices),
            "source": "netbox",
            "configured": True,
            "devices": devices,
            "links": links,
            "adjacency": adjacency,
            "skipped_terminations": skipped,
        }


def _empty_manifest(site: str | None, *, configured: bool) -> dict[str, Any]:
    return {
        "site": site or "",
        "source": "netbox",
        "configured": configured,
        "devices": [],
        "links": [],
        "adjacency": {},
        "skipped_terminations": 0,
    }


def _first_device_site(devices: list[dict[str, Any]]) -> str:
    for device in devices:
        site = device.get("site")
        if site:
            return str(site)
    return ""


def _attr(obj: Any, key: str, default: Any = None) -> Any:
    """Dict-or-object field access. ``None`` object → default (no AttributeError)."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _termination_device_name(term: Any) -> str | None:
    """Return the device hostname on a cable termination, or None to skip.

    FrontPort / RearPort patch panels and CircuitTermination often have
    ``device is None``. Calling ``.device.name`` on those must not raise.
    """
    if term is None:
        return None
    obj = _attr(term, "object", term)
    device = _attr(obj, "device")
    if device is None:
        return None
    name = _attr(device, "name") or _attr(device, "display") or device
    if not name or not isinstance(name, str):
        return None
    return name


def _termination_iface_name(term: Any) -> str:
    if term is None:
        return ""
    obj = _attr(term, "object", term)
    return str(_attr(obj, "name") or _attr(obj, "label") or "")


def _iter_terminations(cable: Any, side: str) -> list[Any]:
    """NetBox 3.3+ uses ``a_terminations`` lists; older uses ``termination_a``."""
    plural = _attr(cable, f"{side}_terminations")
    if isinstance(plural, list):
        return [t for t in plural if t is not None]
    if plural:
        return [plural]
    single = _attr(cable, f"termination_{side}")
    return [single] if single is not None else []


def _cable_device_ends(cable: Any) -> dict[str, Any]:
    """Collect up to two device names from a cable; count skipped terms."""
    names: list[str] = []
    ifaces: list[str] = []
    skipped = 0
    for side in ("a", "b"):
        for term in _iter_terminations(cable, side):
            host = _termination_device_name(term)
            if host is None:
                skipped += 1
                continue
            names.append(host)
            ifaces.append(_termination_iface_name(term))
    # First two named devices become the link endpoints.
    devices = (names[0] if names else "", names[1] if len(names) > 1 else "")
    interfaces = (ifaces[0] if ifaces else "", ifaces[1] if len(ifaces) > 1 else "")
    return {"devices": devices, "interfaces": interfaces, "skipped": skipped}


def build_site_manifest(
    site: str | None = None,
    client: NetBoxClient | None = None,
) -> dict[str, Any]:
    """Build a site manifest (devices + adjacency) from NetBox.

    No-op empty manifest when NetBox is unset — no network.
    """
    if client is None:
        if not is_enabled():
            return _empty_manifest(site, configured=False)
        client = NetBoxClient()
    return client.build_site_manifest(site)


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
