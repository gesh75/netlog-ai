"""Optional NetBox client — mocked urllib, no network in CI."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from io import BytesIO

import pytest

from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.classifier import LogEvent
from ai_log_analyzer.netbox import (
    NetBoxClient,
    NetBoxError,
    enrich_host,
    enrich_hosts,
    is_enabled,
)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _device_payload(name: str = "leaf1") -> dict:
    return {
        "results": [{
            "id": 17,
            "name": name,
            "site": {"name": "AMS1", "slug": "ams1"},
            "role": {"name": "leaf", "slug": "leaf"},
            "status": {"value": "active", "label": "Active"},
            "device_type": {"model": "7280CR3", "slug": "7280cr3"},
            "primary_ip": {"address": "10.0.0.1/32"},
        }]
    }


def _iface_payload() -> dict:
    return {
        "results": [{
            "name": "Ethernet1",
            "enabled": True,
            "type": {"value": "10gbase-x-sfpp", "label": "10GBASE-X SFP+"},
            "description": "to spine1",
        }]
    }


@pytest.fixture
def netbox_env(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "https://netbox.example.test")
    monkeypatch.setenv("NETBOX_TOKEN", "super-secret-token")


@pytest.mark.unit
def test_disabled_when_env_unset(monkeypatch):
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("NetBox must not open a socket when unset")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert is_enabled() is False
    assert enrich_hosts(["leaf1"]) == {}
    assert enrich_host("leaf1") == {"configured": False, "hostname": "leaf1"}


@pytest.mark.unit
def test_token_never_in_repr_or_str(netbox_env):
    client = NetBoxClient()
    text = f"{client!r} {client!s}"
    assert "super-secret-token" not in text
    assert "***" in text
    assert "netbox.example.test" in text


@pytest.mark.unit
def test_lookup_device_and_interface(netbox_env):
    calls: list[str] = []

    def opener(request, timeout=None):
        calls.append(request.full_url)
        assert request.get_header("Authorization") == "Token super-secret-token"
        if "/api/dcim/devices/" in request.full_url:
            return _FakeResponse(_device_payload())
        if "/api/dcim/interfaces/" in request.full_url:
            return _FakeResponse(_iface_payload())
        raise AssertionError(request.full_url)

    client = NetBoxClient(opener=opener)
    device = client.lookup_device("leaf1")
    assert device is not None
    assert device["site"] == "AMS1"
    assert device["role"] == "leaf"
    assert device["device_type"] == "7280CR3"
    assert device["primary_ip"] == "10.0.0.1/32"

    iface = client.lookup_interface("leaf1", "Ethernet1")
    assert iface is not None
    assert iface["name"] == "Ethernet1"
    assert iface["description"] == "to spine1"

    record = client.enrich("leaf1", interface="Ethernet1")
    assert record["configured"] is True
    assert record["found"] is True
    assert record["interface"]["name"] == "Ethernet1"
    assert all(url.startswith("https://netbox.example.test/api/") for url in calls)


@pytest.mark.unit
def test_http_error_does_not_leak_token(netbox_env):
    def opener(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url, 401, "nope", hdrs={}, fp=BytesIO(b""),
        )

    client = NetBoxClient(opener=opener)
    with pytest.raises(NetBoxError) as exc:
        client._request("/api/dcim/devices/")
    assert "super-secret-token" not in str(exc.value)
    assert "401" in str(exc.value)
    assert client.lookup_device("leaf1") is None


@pytest.mark.unit
def test_enrich_hosts_uses_mock_and_skips_duplicates(netbox_env, monkeypatch):
    seen = {"n": 0}

    def opener(request, timeout=None):
        seen["n"] += 1
        return _FakeResponse(_device_payload("leaf1"))

    monkeypatch.setattr(urllib.request, "urlopen", opener)
    out = enrich_hosts(["leaf1", "leaf1", ""])
    assert set(out) == {"leaf1"}
    assert out["leaf1"]["site"] == "AMS1"
    assert seen["n"] == 1


@pytest.mark.unit
def test_analyze_stays_offline_when_netbox_unset(monkeypatch):
    monkeypatch.delenv("NETBOX_URL", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("analyze() must not call NetBox when unset")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    result = analyze([
        LogEvent("Oct 13 10:00:01", "leaf1", "rpd", "err", "bgp peer 10.0.0.1 down"),
    ], use_llm=False)
    assert result.netbox == {}
    assert result.to_dict()["netbox"] == {}


@pytest.mark.unit
def test_analyze_attaches_netbox_when_enabled(netbox_env, monkeypatch):
    def opener(request, timeout=None):
        return _FakeResponse(_device_payload("leaf1"))

    monkeypatch.setattr(urllib.request, "urlopen", opener)
    result = analyze([
        LogEvent("Oct 13 10:00:01", "leaf1", "rpd", "err", "bgp peer 10.0.0.1 down"),
    ], use_llm=False)
    assert result.netbox["leaf1"]["site"] == "AMS1"
    assert result.netbox["leaf1"]["role"] == "leaf"
