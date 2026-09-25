"""Work-shift ticket, brief, edge patterns, and 7-day repeats."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ai_log_analyzer.classifier import LogEvent, classify_events
from ai_log_analyzer.handoff import incident_handoff
from ai_log_analyzer.memory import IncidentStore

pytestmark = pytest.mark.unit


def _one(message: str):
    events, _, _ = classify_events([LogEvent(
        timestamp="2026-09-25T10:00:00", hostname="clinic-sw1", appname="",
        severity_raw="err", message=message,
    )])
    return events[0]


@pytest.mark.parametrize("message,category,description", [
    ("Meraki AP lobby-1 is offline", "wireless", "Access point down"),
    ("DOT1X-5-FAIL: Authentication failed for client aabb", "security", "802.1X authentication failure"),
    ("DHCP pool VLAN20 exhausted, no free addresses left", "dhcp", "DHCP pool exhausted"),
    ("WAN uplink failover to cellular active", "redundancy", "WAN uplink failover"),
    ("Non-Meraki VPN tunnel down", "vpn", "VPN/IPsec tunnel failure"),
])
def test_work_edge_patterns(message, category, description):
    event = _one(message)
    assert event.category == category
    assert event.description == description


def test_ticket_is_local_and_sanitized():
    card = incident_handoff({
        "score": 40,
        "grade": "F",
        "blast": {"epicenter": "clinic-sw1", "estimated_impact": "site down"},
        "change_window": {"detected": True, "count": 1, "devices": ["clinic-sw1"], "samples": []},
        "action_items": [{
            "severity": "high",
            "category": "wireless",
            "description": "Access point down password 7 keep-me-out",
            "count": 2,
            "devices": ["clinic-sw1"],
        }],
        "repeat_offenders": [{
            "hostname": "clinic-sw1", "category": "wireless", "count": 4,
        }],
    })
    ticket = card["ticket"]
    assert ticket["posted"] is False
    assert ticket["urgency"] == "1 - High"
    assert ticket["configuration_item"] == "clinic-sw1"
    assert "keep-me-out" not in ticket["short_description"]
    assert "keep-me-out" not in ticket["work_notes"]
    brief = card["brief"]
    assert "Epicenter: clinic-sw1" in brief
    assert "Change window: yes" in brief
    assert "show ap summary" in brief
    assert "4 times in 7 days" in brief
    assert len(brief) <= 1200


def test_repeats_count_only_the_last_seven_days(tmp_path):
    store = IncidentStore(tmp_path / "incidents.jsonl")
    now = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    old = (now - timedelta(days=8)).isoformat()
    recent = (now - timedelta(days=1)).isoformat()
    store.record(
        [{"description": "Access point down", "category": "wireless", "devices": ["ap-1"]}],
        old,
    )
    store.record(
        [{"description": "Access point down", "category": "wireless", "devices": ["ap-1"]}],
        recent,
    )
    store.record(
        [{"description": "Access point down", "category": "wireless", "devices": ["ap-1"]}],
        now.isoformat(),
    )
    rows = store.repeats(now=now)
    assert rows == [{
        "hostname": "ap-1",
        "category": "wireless",
        "count": 2,
        "last_seen": now.isoformat(),
    }]
