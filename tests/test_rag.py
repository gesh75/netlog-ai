"""Retrieval index: chunking with line numbers, golden-config drift, BM25
search, incident precedents, and the evidence wired into analyzer/copilot."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from ai_log_analyzer import copilot, llm, rag
from ai_log_analyzer.adapters.file import parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.memory import IncidentStore, SqliteIncidentStore, incident_id
from ai_log_analyzer.state_store import StateDB

JUNOS = """\
system {
    host-name edge-01;
    services {
        ssh;
    }
}
interfaces {
    ge-0/0/1 {
        description "uplink to core-01";
        unit 0 {
            family inet {
                address 10.1.1.1/31;
            }
        }
    }
    ge-0/0/2 {
        description "to fw-01";
        unit 0 {
            family inet {
                address 10.1.1.3/31;
            }
        }
    }
}
protocols {
    bgp {
        group CORE {
            type external;
            peer-as 65010;
            neighbor 10.1.1.0 {
                hold-time 30;
            }
        }
    }
}
"""

EOS = """\
hostname leaf-01
!
snmp-server community s3cr3tCommunity ro
!
interface Ethernet1
   description to spine-01 Ethernet3
   no switchport
   ip address 10.0.1.1/31
!
interface Ethernet2
   description to spine-02 Ethernet3
   no switchport
   ip address 10.0.1.3/31
!
router bgp 65101
   neighbor 10.0.1.0 remote-as 65100
   neighbor 10.0.1.2 remote-as 65100
!
ip route 0.0.0.0/0 192.0.2.1
ip route 10.99.0.0/16 10.0.1.0
"""


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


@pytest.fixture
def index(db):
    return rag.RagIndex(db)


# ── tokenizer ───────────────────────────────────────────────────────────────

def test_tokenizer_canonicalizes_interfaces_and_keeps_entities_whole():
    toks = rag.tokenize("GigabitEthernet0/1 Gi0/1 Ethernet1 Et1 ge-0/0/1.0 10.1.1.0/31 AS65001")
    assert toks.count("gi0/1") == 2          # long and short forms meet
    assert toks.count("et1") == 2
    assert "ge-0/0/1" in toks                # Junos unit also indexes the port
    assert "10.1.1.0" in toks and "10.1.1.0/31" in toks
    assert "65001" in toks                   # AS65001 matches "remote-as 65001"


# ── chunking ────────────────────────────────────────────────────────────────

def test_junos_chunks_are_specific_stanzas_with_original_line_numbers():
    chunks = {c.heading: c for c in rag.chunk_config(JUNOS)}
    assert "interfaces > ge-0/0/1" in chunks
    ge1 = chunks["interfaces > ge-0/0/1"]
    lines = JUNOS.splitlines()
    assert lines[ge1.start - 1].strip() == "ge-0/0/1 {"
    assert "address 10.1.1.1/31" in ge1.text
    assert lines[ge1.end - 1].strip() == "}"
    assert any(h.startswith("protocols") for h in chunks)


def test_indented_cli_chunks_group_stanzas_and_loose_lines():
    chunks = rag.chunk_config(EOS)
    heads = [c.heading for c in chunks]
    assert "interface Ethernet1" in heads and "router bgp 65101" in heads
    routes = next(c for c in chunks if c.heading == "ip")
    assert routes.text.count("ip route") == 2          # consecutive one-liners merge
    eth1 = next(c for c in chunks if c.heading == "interface Ethernet1")
    assert EOS.splitlines()[eth1.start - 1] == "interface Ethernet1"


def test_set_format_chunks():
    text = "set system host-name x\nset protocols bgp group A neighbor 10.0.0.1\nset protocols bgp group A peer-as 1\n"
    chunks = rag.chunk_config(text)
    bgp = next(c for c in chunks if c.heading.startswith("protocols bgp"))
    assert (bgp.start, bgp.end) == (2, 3)


# ── drift ───────────────────────────────────────────────────────────────────

def test_config_drift_reports_hunks_with_running_line_numbers_and_stanza():
    golden = EOS.replace("   neighbor 10.0.1.0 remote-as 65100\n",
                         "   neighbor 10.0.1.0 remote-as 65100\n   neighbor 10.0.1.0 bfd\n")
    running = "! Last configuration change at 10:00\n" + EOS.replace("10.0.1.3/31", "10.0.1.5/31")
    drift = rag.config_drift(running, golden)
    assert drift["drifted"] and drift["added"] == 1 and drift["removed"] == 2
    changed = next(h for h in drift["hunks"] if h["kind"] == "changed")
    assert changed["added"] == ["   ip address 10.0.1.5/31"]
    assert changed["stanza"] == "interface Ethernet2"
    assert running.splitlines()[changed["running_lines"][0] - 1].strip() == "ip address 10.0.1.5/31"
    removed = next(h for h in drift["hunks"] if h["kind"] == "removed")
    assert removed["removed"] == ["   neighbor 10.0.1.0 bfd"]
    assert removed["stanza"] == "router bgp 65101"


def test_config_drift_ignores_volatile_banner_lines():
    a = "! Last configuration change at Mon\nhostname x\n"
    b = "! Last configuration change at Tue\nhostname x\n"
    assert rag.config_drift(a, b)["drifted"] is False


# ── index & search ──────────────────────────────────────────────────────────

def test_search_ranks_the_stanza_naming_the_peer_and_cites_line_numbers(index):
    rag.index_configs(index, [{"hostname": "edge-01", "platform": "junos", "config_text": JUNOS},
                              {"hostname": "leaf-01", "platform": "eos", "config_text": EOS}])
    hits = index.search("BGP neighbor 10.1.1.0 hold timer expired", k=3)
    top = hits[0]
    assert top["host"] == "edge-01" and top["kind"] == "config"
    assert "protocols" in top["title"]
    start, end = top["meta"]["start"], top["meta"]["end"]
    assert "neighbor 10.1.1.0" in "\n".join(JUNOS.splitlines()[start - 1:end])
    assert top["citation"] == f"edge-01 running-config L{start}-L{end} `{top['title']}`"


def test_host_only_kinds_drop_other_devices_configs(index):
    rag.index_configs(index, [{"hostname": "edge-01", "platform": "junos", "config_text": JUNOS},
                              {"hostname": "leaf-01", "platform": "eos", "config_text": EOS}])
    hits = index.search("neighbor remote-as interface", k=10, hosts=["leaf-01"], host_only_kinds=("config",))
    assert hits and {h["host"] for h in hits} == {"leaf-01"}


def test_secrets_are_scrubbed_at_rest_and_reindex_is_idempotent(index, db):
    devs = [{"hostname": "leaf-01", "platform": "eos", "config_text": EOS}]
    n1 = rag.index_configs(index, devs, source_key="configs:x")
    n2 = rag.index_configs(index, devs, source_key="configs:x")
    assert n1 == n2 == index.stats()["documents"]
    bodies = " ".join(r[0] for r in db.conn().execute("SELECT body FROM rag_docs"))
    assert "s3cr3tCommunity" not in bodies


def test_drift_documents_are_indexed_and_searchable(index):
    golden = EOS.replace("   neighbor 10.0.1.2 remote-as 65100\n", "")
    rag.index_configs(index, [{"hostname": "leaf-01", "platform": "eos", "config_text": EOS}],
                      {"leaf-01": golden})
    hits = index.search("neighbor 10.0.1.2", k=5, kinds=["drift"])
    assert hits and hits[0]["kind"] == "drift"
    assert hits[0]["citation"].startswith("leaf-01 drift vs golden L")


def test_site_bundle_indexing_includes_topology(index):
    from pathlib import Path
    site = Path(rag.__file__).parent / "data" / "sites" / "lab-alpha"
    report = rag.index_site_dir(index, site)
    assert report["devices"] >= 3 and report["config_docs"] > 10 and report["topology_docs"] >= 3
    assert index.stats()["by_kind"]["topology"] >= 3


# ── incident precedents ─────────────────────────────────────────────────────

def _incident(desc, devices, when, **extra):
    return {"description": desc, "severity": "high", "category": "routing", "devices": devices,
            "count": 3, "sample_messages": [f"{devices[0]} bgpd: neighbor 10.1.1.0 Down hold time expired"],
            "generated_at": when, **extra}


def test_sync_incidents_is_incremental_and_tracks_resolutions(index, db):
    store = SqliteIncidentStore(db)
    store.record([_incident("BGP hold timer expired", ["edge-01"], "2026-10-01T10:00:00+00:00")],
                 "2026-10-01T10:00:00+00:00")
    assert rag.sync_incidents(index, store) == 1
    assert rag.sync_incidents(index, store) == 0          # nothing changed → nothing rewritten
    inc = store.records()[0]["incident_id"]
    assert inc == "INC-000001"
    store.resolve(inc, "Replaced the optic on ge-0/0/1; hold-time raised to 90", resolved_by="alice")
    assert rag.sync_incidents(index, store) == 1          # resolution changed the doc
    hit = index.search("hold timer expired edge-01 optic", k=3, kinds=["incident"])[0]
    assert hit["ref"] == inc and hit["meta"]["resolved"] is True
    assert "resolved" in hit["citation"] and "2026-10-01" in hit["citation"]


def test_jsonl_store_resolve_and_stable_ids(tmp_path):
    store = IncidentStore(tmp_path / "inc.jsonl")
    store.record([_incident("BGP hold timer expired", ["edge-01"], "2026-10-01T10:00:00+00:00")], "x")
    inc = store.records()[0]["incident_id"]
    assert inc.startswith("INC-") and inc == incident_id(store.records()[0])
    out = store.resolve(inc, "fixed the optic", resolved_by="bob")
    assert out and out["resolution"] == "fixed the optic"
    reloaded = IncidentStore(tmp_path / "inc.jsonl")
    assert reloaded.get(inc)["resolved_by"] == "bob"
    assert store.resolve("INC-NOPE", "x") is None


# ── analyzer wiring ─────────────────────────────────────────────────────────

LOGS = [
    "Oct 20 10:00:01 edge-01 rpd[2210]: bgp_hold_timeout:4102: NOTIFICATION sent to 10.1.1.0 (External AS 65010): "
    "code 4 (Hold Timer Expired Error), Reason: holdtime expired for 10.1.1.0 (External AS 65010)",
    "Oct 20 10:00:01 edge-01 rpd[2210]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.0 (External AS 65010) "
    "changed state from Established to Idle (event HoldTime) (instance master)",
]


def _seeded_index(index, db):
    golden = JUNOS.replace("                hold-time 30;\n", "                hold-time 90;\n")
    rag.index_configs(index, [{"hostname": "edge-01", "platform": "junos", "config_text": JUNOS}],
                      {"edge-01": golden})
    rag.index_kb(index)
    store = SqliteIncidentStore(db)
    store.record([_incident("BGP hold timer expired", ["edge-01"], "2026-09-01T10:00:00+00:00")], "x")
    store.resolve("INC-000001", "Hold-time drifted to 30 from golden 90; restored golden config", "alice")
    return store


def test_every_playbook_carries_verifiable_evidence_without_llm(index, db, monkeypatch):
    _seeded_index(index, db)
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(db.path))
    result = analyze(parse_lines(LOGS), use_llm=False, rag_index=index)
    item = next(a for a in result.action_items if "hold timer" in a.description.lower())
    ev = item.deep_analysis["evidence"]
    kinds = {e["kind"] for e in ev}
    assert {"config", "drift", "incident", "runbook"} <= kinds
    drift = next(e for e in ev if e["kind"] == "drift")
    assert drift["host"] == "edge-01" and drift["lines"][0] > 0
    assert "hold-time 30" in JUNOS.splitlines()[drift["lines"][0] - 1]
    inc = next(e for e in ev if e["kind"] == "incident")
    assert inc["ref"] == "INC-000001" and "restored golden" in inc["resolution"]
    assert [e["id"] for e in ev] == [f"S{i}" for i in range(1, len(ev) + 1)]


def test_this_run_is_never_cited_as_its_own_precedent(index, db, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(db.path))
    rag.index_kb(index)
    analyze(parse_lines(LOGS), use_llm=False, rag_index=index)   # first run: nothing to cite
    first = analyze(parse_lines(LOGS), use_llm=False, rag_index=index)
    refs = [e["ref"] for a in first.action_items for e in a.deep_analysis.get("evidence", [])
            if e["kind"] == "incident"]
    # Second run may cite the first run's records (INC-000001..), never ids it creates itself.
    store = SqliteIncidentStore(db)
    own = {r["incident_id"] for r in store.records()[-len(first.action_items):]}
    assert not set(refs) & own


def test_llm_prompt_carries_evidence_and_invented_citations_are_flagged(index, db, monkeypatch):
    _seeded_index(index, db)
    captured = []

    def fake_query(system, user, max_tokens=0):
        captured.append(user)
        if "5-phase" in user:
            return json.dumps({"root_cause": "Hold-time drift [S1]; see [S9]", "phases": [], "risk": "r"})
        return "- summary"

    llm.set_enabled(True)
    with patch.object(llm, "query", side_effect=fake_query), patch.object(llm, "is_enabled", return_value=True):
        result = analyze(parse_lines(LOGS), use_llm=True, rag_index=index)
    item = next(a for a in result.action_items if a.deep_analysis.get("llm_powered"))
    prompt = next(p for p in captured if "5-phase" in p)
    assert "EVIDENCE (numbered sources)" in prompt and "[S1]" in prompt
    assert item.deep_analysis["citations"] == {"cited": ["S1"], "invalid": ["S9"]}


# ── copilot wiring ──────────────────────────────────────────────────────────

def test_copilot_numbers_lines_and_validates_line_and_source_citations(index, db):
    _seeded_index(index, db)
    seen = {}
    line = next(i for i, ln in enumerate(JUNOS.splitlines(), 1) if "hold-time 30" in ln)

    def fake_query(system, user, max_tokens=0):
        seen["user"] = user
        return f"The hold-time is set at edge-01 L{line} [S1]; also edge-01 L999 and [S7]."

    llm.set_enabled(True)
    with patch.object(llm, "query", side_effect=fake_query):
        out = copilot.ask("What is the BGP hold-time for neighbor 10.1.1.0?",
                          [{"hostname": "edge-01", "platform": "junos", "config_text": JUNOS}], rag_index=index)
    assert "L1| system {" in seen["user"]
    assert "EVIDENCE (numbered sources)" in seen["user"]
    assert out["citations"]["cited"] == ["S1"] and out["citations"]["invalid"] == ["S7"]
    assert out["citations"]["line_refs"] == {"valid": [f"edge-01 L{line}"], "invalid": ["edge-01 L999"]}
    assert f"L{line}|                 hold-time 30;" in seen["user"]
    assert out["evidence"] and out["evidence"][0]["id"] == "S1"


def test_get_index_follows_env_and_can_be_disabled(tmp_path, monkeypatch):
    assert rag.get_index() is None
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_DB", str(tmp_path / "rag.db"))
    assert rag.get_index() is not None
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG", "0")
    assert rag.get_index() is None
