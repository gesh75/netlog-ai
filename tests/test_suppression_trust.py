"""Suppression must not take its device facts from forgeable log text: addresses a network sender claims
(``locip=``, the far end of its BGP session, HA events) only count when the listener's own view of
that sender (``sender_ip`` bound to the host in the dependency map) agrees; operator-supplied logs
without transport information keep working."""
from __future__ import annotations

import pytest

from ai_log_analyzer.suppression import Topology, _learn_ownership, suppress_alerts
from tests._w8_events import ev

pytestmark = pytest.mark.unit

ROGUE_IP = "203.0.113.66"
VICTIM_IPS = ("198.51.100.11", "198.51.100.12")


def _from(sender: str, event):
    event.attrs = {**event.attrs, "sender_ip": sender}
    return event


def _victims(*, sender: bool = True):
    """Two devices lose their BGP sessions to 192.0.2.2 / 192.0.2.6, addresses of a silent core router."""
    out = [ev("leaf-01", 0, "bgp_session", peer="192.0.2.2", asn="65000"),
           ev("leaf-02", 1, "bgp_session", peer="192.0.2.6", asn="65000")]
    if sender:
        out = [_from(ip, e) for ip, e in zip(VICTIM_IPS, out)]
    return out


def _forged_bgp():
    """A third source names the /31 partners of the victims' peers, so each peer looks like its address."""
    return [ev("zz-rogue", 5, "bgp_session", peer="192.0.2.1", asn="65000"),
            ev("zz-rogue", 6, "bgp_session", peer="192.0.2.5", asn="65000")]


def _roots(result):
    return [(g["kind"], tuple(g["root_hosts"])) for g in result["groups"]]


def test_forged_far_end_claims_from_an_unbound_sender_do_not_re_root_other_devices():
    events = _victims() + [_from(ROGUE_IP, e) for e in _forged_bgp()]
    result = suppress_alerts(events, Topology())
    assert result["groups"] == [] and result["suppressed_events"] == 0


def test_forged_locip_claim_from_an_unbound_sender_is_ignored():
    victims = [_from(VICTIM_IPS[i], ev(f"leaf-0{i + 1}", i, "ipsec_tunnel", tun=f"T{i}", peer="192.0.2.9",
                                       vendor="fortinet")) for i in range(2)]
    forged = _from(ROGUE_IP, ev("zz-rogue", 3, "ipsec_tunnel", tun="X", peer="192.0.2.50", vendor="fortinet",
                                attrs={"locip": "192.0.2.9"}))
    result = suppress_alerts(victims + [forged], Topology())
    assert not [g for g in result["groups"] if g["kind"] == "device_unreachable"]


def test_a_sender_bound_to_its_host_in_the_dependency_map_may_still_teach_addresses():
    topo = Topology(ips={ROGUE_IP: "zz-rogue"})
    events = _victims() + [_from(ROGUE_IP, e) for e in _forged_bgp()]
    owned = _learn_ownership(events, topo)
    assert owned["192.0.2.2"][0] == "zz-rogue"                 # verified sender: the claim is believed
    assert _roots(suppress_alerts(events, topo)) == [("device_unreachable", ("zz-rogue",))]


def test_a_sender_bound_to_another_host_cannot_teach_addresses():
    topo = Topology(ips={ROGUE_IP: "somebody-else"})
    owned = _learn_ownership([_from(ROGUE_IP, e) for e in _forged_bgp()], topo)
    assert "192.0.2.2" not in owned


def test_dependency_map_addresses_always_win_over_anything_logged():
    topo = Topology(ips={"192.0.2.2": "core-01", "192.0.2.6": "core-01"})
    events = _victims() + _forged_bgp()                        # no sender info: operator-supplied logs
    owned = _learn_ownership(events, topo)
    assert owned["192.0.2.2"] == ("core-01", "dependency_map")
    assert _roots(suppress_alerts(events, topo)) == [("device_unreachable", ("core-01",))]


def test_logs_without_transport_information_still_learn_ownership():
    result = suppress_alerts(_victims(sender=False) + _forged_bgp(), Topology())
    assert _roots(result) == [("device_unreachable", ("zz-rogue",))]    # unchanged: no sender to check


def test_inferred_ha_peer_must_come_from_a_bound_sender():
    topo = Topology(ips={"198.51.100.21": "fw-v1"})
    real = _from("198.51.100.21", ev("fw-v1", 0, "ha_state", vendor="fortinet"))
    child = _from("198.51.100.21", ev("fw-v1", 10, "bgp_session", peer="192.0.2.9", vendor="fortinet"))
    rogue = _from(ROGUE_IP, ev("aa-rogue", 5, "ha_state", vendor="fortinet"))
    groups = suppress_alerts([real, child, rogue], topo)["groups"]
    assert groups and all("aa-rogue" not in g["root_hosts"] for g in groups)
    assert groups[0]["root_hosts"] == ["fw-v1"]


def test_inferred_ha_peers_between_bound_senders_still_pair():
    topo = Topology(ips={"198.51.100.21": "fw-a", "198.51.100.22": "fw-b"})
    a = _from("198.51.100.21", ev("fw-a", 0, "ha_state", vendor="fortinet"))
    b = _from("198.51.100.22", ev("fw-b", 5, "ha_state", vendor="fortinet"))
    child = _from("198.51.100.22", ev("fw-b", 10, "bgp_session", peer="192.0.2.9", vendor="fortinet"))
    groups = suppress_alerts([a, b, child], topo)["groups"]
    assert groups and groups[0]["root_hosts"] == ["fw-a", "fw-b"]


def test_a_listed_relay_may_vouch_for_the_hosts_it_forwards():
    events = _victims() + [_from(ROGUE_IP, e) for e in _forged_bgp()]
    owned = _learn_ownership(events, Topology(relays={ROGUE_IP}))
    assert owned["192.0.2.2"][0] == "zz-rogue"


def test_relays_load_from_the_dependency_map(tmp_path):
    import json

    from ai_log_analyzer.suppression import load_topology
    path = tmp_path / "deps.json"
    path.write_text(json.dumps({"relays": ["192.0.2.50", "not-an-ip", "::ffff:192.0.2.51"],
                                "devices": {"core-01": {"ips": ["10.0.0.1"]}}}))
    topo = load_topology(path=str(path))
    assert topo.relays == {"192.0.2.50", "192.0.2.51"} and topo.ips == {"10.0.0.1": "core-01"}
