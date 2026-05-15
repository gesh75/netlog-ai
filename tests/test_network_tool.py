"""Tests for the network-tool adapter (DCN_Network_Tool bridge)."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from ai_log_analyzer.adapters import network_tool


@pytest.mark.unit
def test_run_command_rejects_empty():
    r = network_tool.run_command("h1", "   ")
    assert not r.ok
    assert "Empty" in r.error


@pytest.mark.unit
def test_run_command_handles_timeout():
    with patch.object(network_tool.requests, "post", side_effect=requests.Timeout):
        r = network_tool.run_command("h1", "show version", timeout=1)
        assert not r.ok
        assert "Timeout" in r.error


@pytest.mark.unit
def test_run_command_handles_network_error():
    with patch.object(network_tool.requests, "post",
                      side_effect=requests.ConnectionError("nope")):
        r = network_tool.run_command("h1", "show version")
        assert not r.ok
        assert "unreachable" in r.error.lower()


@pytest.mark.unit
def test_run_command_handles_http_error():
    resp = MagicMock(status_code=500, text="server boom")
    with patch.object(network_tool.requests, "post", return_value=resp):
        r = network_tool.run_command("h1", "show version")
        assert not r.ok
        assert "500" in r.error


@pytest.mark.unit
def test_run_command_parses_ok_response():
    resp = MagicMock(status_code=200, headers={"content-type": "application/json"})
    resp.json.return_value = {"ok": True, "output": "BGP summary here"}
    with patch.object(network_tool.requests, "post", return_value=resp):
        r = network_tool.run_command("h1", "show ip bgp summary")
        assert r.ok
        assert "BGP summary" in r.output
        assert r.error == ""


@pytest.mark.unit
def test_run_command_truncates_huge_output():
    resp = MagicMock(status_code=200, headers={"content-type": "application/json"})
    big = "x" * 50000
    resp.json.return_value = {"ok": True, "output": big}
    with patch.object(network_tool.requests, "post", return_value=resp):
        r = network_tool.run_command("h1", "show log")
        assert len(r.output) <= 20000


@pytest.mark.unit
def test_is_available_false_on_connection_error():
    with patch.object(network_tool.requests, "get",
                      side_effect=requests.ConnectionError):
        assert network_tool.is_available(timeout=0.5) is False


@pytest.mark.unit
def test_is_available_true_on_200():
    resp = MagicMock(status_code=200)
    with patch.object(network_tool.requests, "get", return_value=resp):
        assert network_tool.is_available() is True


@pytest.mark.unit
def test_fetch_running_config_returns_output():
    resp = MagicMock(status_code=200, headers={"content-type": "application/json"})
    resp.json.return_value = {"ok": True, "output": "router bgp 65001\n neighbor ..."}
    with patch.object(network_tool.requests, "post", return_value=resp):
        cfg = network_tool.fetch_running_config("h1", platform="frr")
        assert cfg and "router bgp" in cfg


@pytest.mark.unit
def test_fetch_running_config_returns_none_on_failure():
    resp = MagicMock(status_code=500, text="boom")
    with patch.object(network_tool.requests, "post", return_value=resp):
        cfg = network_tool.fetch_running_config("h1")
        assert cfg is None


@pytest.mark.unit
def test_list_devices_handles_list_response():
    resp = MagicMock(status_code=200)
    resp.json.return_value = [{"hostname": "h1"}, {"hostname": "h2"}]
    with patch.object(network_tool.requests, "get", return_value=resp):
        out = network_tool.list_devices()
        assert len(out) == 2


@pytest.mark.unit
def test_list_devices_handles_wrapped_response():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"devices": [{"hostname": "h1"}]}
    with patch.object(network_tool.requests, "get", return_value=resp):
        out = network_tool.list_devices()
        assert out == [{"hostname": "h1"}]
