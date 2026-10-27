"""Secrets must never reach the retrieval index: drift documents and stanza headings are redacted
like config bodies, so the stored rows, search output and LLM prompts carry no config secret."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_log_analyzer import analyzer, copilot, llm, rag
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit

VTY_NEW, VTY_OLD = "VtyRunningS3cr3tOnly", "VtyGoldenS3cr3tOnly"
RADIUS_NEW, RADIUS_OLD = "RadiusRunKeyOnly77", "RadiusGoldKeyOnly88"
COMM_NEW, COMM_OLD = "CommAlphaRunK9x2Zq", "CommAlphaOldP4w7Lm"
COMM_B = "CommBravoSharedQ3v8Rt"
SECRETS = (VTY_NEW, VTY_OLD, RADIUS_NEW, RADIUS_OLD, COMM_NEW, COMM_OLD, COMM_B)


def _eos(vty: str, radius: str) -> str:
    return (
        "hostname leaf-01\n!\n"
        "line vty 0 4\n"
        f"   password {vty}\n"
        "   login\n!\n"
        f"radius-server host 192.0.2.9 key 0 {radius}\n"
        "   timeout 5\n!\n"
        "interface Ethernet1\n   ip address 192.0.2.1/31\n"
    )


def _junos(community: str) -> str:
    """The ``snmp`` stanza is over 15 lines, so every child becomes its own chunk headed by its path."""
    return (
        "system {\n    host-name edge-01;\n}\n"
        "snmp {\n"
        "    contact ops;\n"
        f"    community {community} {{\n"
        "        authorization read-only;\n"
        "        clients {\n"
        "            192.0.2.0/24;\n"
        "            198.51.100.0/24;\n"
        "        }\n"
        "    }\n"
        f"    community {COMM_B} {{\n"
        "        authorization read-write;\n"
        "        clients {\n"
        "            203.0.113.0/24;\n"
        "        }\n"
        "    }\n"
        "    trap-group ops {\n"
        "        targets {\n"
        "            192.0.2.50;\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


@pytest.fixture
def index(db):
    return rag.RagIndex(db)


def _everything_stored(db) -> str:
    conn = db.conn()
    docs = [" ".join(str(c) for c in row) for row in conn.execute("SELECT * FROM rag_docs")]
    terms = [r[0] for r in conn.execute("SELECT term FROM rag_postings")]
    return "\n".join(docs + terms)


def _assert_clean(text: str) -> None:
    low = text.lower()
    leaked = [s for s in SECRETS if s.lower() in low]
    assert not leaked, leaked


def _seed(index) -> None:
    rag.index_configs(
        index,
        [{"hostname": "leaf-01", "platform": "eos", "config_text": _eos(VTY_NEW, RADIUS_NEW)},
         {"hostname": "edge-01", "platform": "junos", "config_text": _junos(COMM_NEW)}],
        {"leaf-01": _eos(VTY_OLD, RADIUS_OLD), "edge-01": _junos(COMM_OLD)})


def test_drift_documents_hold_no_line_anchored_secret(index, db):
    _seed(index)
    drift = [r for r in db.conn().execute("SELECT title, body FROM rag_docs WHERE kind='drift'")]
    assert len(drift) >= 3
    _assert_clean(_everything_stored(db))
    # the drift is still reported, with the value masked
    bodies = "\n".join(b for _, b in drift)
    assert "+    password <REDACTED>" in bodies and "-    password <REDACTED>" in bodies


def test_stanza_headings_hold_no_snmp_community(index, db):
    _seed(index)
    titles = [r[0] for r in db.conn().execute("SELECT title FROM rag_docs WHERE host='edge-01'")]
    assert any(t.startswith("snmp > community") for t in titles)       # the stanza was split by child
    _assert_clean("\n".join(titles))
    _assert_clean(_everything_stored(db))


def test_search_and_citations_stay_useful_and_clean(index):
    _seed(index)
    for kinds in (["config"], ["drift"]):
        hits = index.search("snmp community authorization read-only clients", k=10, kinds=kinds,
                            hosts=["edge-01"])
        assert hits and all(h["host"] == "edge-01" for h in hits), kinds
        _assert_clean("\n".join(f"{h['title']}\n{h['citation']}\n{h['snippet']}" for h in hits))
    cfg = index.search("snmp community", k=10, kinds=["config"], hosts=["edge-01"])
    assert any("community <REDACTED>" in h["title"] for h in cfg)
    vty = index.search("line vty password login", k=5, kinds=["drift"], hosts=["leaf-01"])
    assert vty and any("password" in h["snippet"] for h in vty)
    # non-secret retrieval is unchanged
    assert index.search("ip address 192.0.2.1/31", k=3, kinds=["config"])[0]["host"] == "leaf-01"


def test_config_drift_output_is_redacted_but_still_detects_a_changed_secret():
    drift = rag.config_drift(_eos(VTY_NEW, RADIUS_NEW), _eos(VTY_OLD, RADIUS_OLD))
    assert drift["drifted"] and drift["added"] == 2 and drift["removed"] == 2
    _assert_clean(repr(drift))
    drift = rag.config_drift(_junos(COMM_NEW), _junos(COMM_OLD))
    assert drift["drifted"]
    _assert_clean(repr(drift))
    assert any("community <REDACTED>" in h["stanza"] for h in drift["hunks"])


def test_set_format_heading_is_redacted_when_the_scrub_removes_the_value():
    text = f"set system host-name x\nset snmp-server community {COMM_NEW} ro\nset system services ssh\n"
    assert any(COMM_NEW in c.heading for c in rag.chunk_config(text))   # the set chunker heads it by value
    docs = rag.config_docs("x", "junos", text)
    _assert_clean("\n".join(f"{d.title}\n{d.body}" for d in docs))


def test_every_prompt_built_from_the_index_is_clean(index, db):
    _seed(index)
    captured: list[str] = []

    def fake_query(system, user, max_tokens=0):
        captured.append(user)
        return "ok"

    evidence = rag.retrieve_evidence(
        index, "line vty password radius key snmp community changed from golden",
        hosts=["leaf-01", "edge-01"], mix={"config": 4, "drift": 6})
    assert {e["kind"] for e in evidence} >= {"config", "drift"}
    llm.set_enabled(True)
    with patch.object(llm, "query", side_effect=fake_query), \
            patch.object(llm, "is_enabled", return_value=True):
        analyzer.deep_analyze("routing", "snmp community changed", ["edge-01"], 3, ["x"], evidence=evidence)
        out = copilot.ask("What changed in snmp community and line vty password on edge-01 and leaf-01?",
                          [{"hostname": "edge-01", "platform": "junos", "config_text": "system {\n}\n"}],
                          rag_index=index)
    assert len(captured) == 2 and all("EVIDENCE" in p for p in captured)
    _assert_clean("\n".join(captured))
    _assert_clean(repr(rag.public_evidence(evidence)) + repr(out["evidence"]))


def test_a_registered_site_is_reindexed_when_the_index_format_changes(index, tmp_path, monkeypatch):
    """Rows written by an older build may hold leaked values; the fingerprint carries a format marker."""
    import json
    site = tmp_path / "dc1"
    site.mkdir()
    (site / "manifest.json").write_text(json.dumps(
        {"site": "dc1", "devices": [{"hostname": "edge-01", "file": "edge-01.txt", "platform": "junos"}]}))
    (site / "edge-01.txt").write_text(_junos(COMM_NEW))
    rag.index_site_dir(index, site)
    assert index.refresh_stale() == []
    monkeypatch.setattr(rag, "_INDEX_FORMAT", rag._INDEX_FORMAT + 1)
    assert index.refresh_stale() == ["configs:dc1"]


def test_incident_titles_are_scrubbed_like_bodies():
    doc = rag.incident_doc({"incident_id": "INC-000009", "severity": "critical", "category": "security",
                            "description": "auth failed password=Hunter2Example from 192.0.2.7",
                            "devices": ["edge-01"], "sample_messages": []})
    assert "Hunter2Example" not in doc.title and "Hunter2Example" not in doc.body
