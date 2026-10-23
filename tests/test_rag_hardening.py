"""Retrieval index hardening: stable citation line numbers, automatic re-indexing of changed
site files, site-qualified document keys, and bounded search cost."""
from __future__ import annotations

import json
import os

import pytest

from ai_log_analyzer import rag
from ai_log_analyzer.state_store import StateDB

pytestmark = pytest.mark.unit


@pytest.fixture
def index(tmp_path):
    return rag.RagIndex(StateDB(tmp_path / "state.db"))


def _long_stanza(n: int = 120) -> str:
    """One interface stanza whose children alternate with `!` / `exit` lines the chunker skips."""
    body = []
    for i in range(n):
        body += [f" description marker-{i:03d}", " !" if i % 2 else " exit"]
    return "hostname r1\n!\ninterface Ethernet1\n" + "\n".join(body) + "\n!\nrouter bgp 65000\n neighbor 10.9.9.9 remote-as 1\n"


def test_window_line_numbers_point_at_the_original_lines_even_with_skipped_lines():
    text = _long_stanza()
    orig = text.splitlines()
    chunks = rag.chunk_config(text)
    windows = [c for c in chunks if c.heading == "interface Ethernet1"]
    assert len(windows) >= 3                                   # the stanza spans several windows
    for c in chunks:
        assert orig[c.start - 1] == c.lines[0], (c.heading, c.start)
        assert orig[c.end - 1] == c.lines[-1], (c.heading, c.end)
        assert all(orig[n - 1] == line for n, line in zip(c.nums or range(c.start, c.end + 1), c.lines))
    # every kept line is cited exactly once and no cited range overlaps the next window
    assert [c.start for c in windows] == sorted(c.start for c in windows)
    assert all(a.end < b.start for a, b in zip(windows, windows[1:]))


def test_cited_range_contains_the_text_that_matched():
    text = _long_stanza()
    marker = "marker-095"
    chunk = next(c for c in rag.chunk_config(text) if marker in c.text)
    assert marker in "\n".join(text.splitlines()[chunk.start - 1:chunk.end])


def _site(root, name: str, config: str, host: str = "leaf1") -> str:
    site = root / name
    site.mkdir()
    (site / "manifest.json").write_text(json.dumps({"site": name, "devices": [
        {"hostname": host, "file": f"{host}.txt", "platform": "eos"}]}))
    (site / f"{host}.txt").write_text(config)
    return str(site)


CFG_A = "hostname leaf1\ninterface Ethernet1\n   ip address 10.1.1.1/31\nrouter bgp 65001\n   neighbor 10.1.1.0 remote-as 65100\n"


def test_changed_site_files_are_reindexed_without_an_explicit_rag_index(index, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_REFRESH_SECONDS", "0")
    site = _site(tmp_path, "dc1", CFG_A)
    rag.index_site_dir(index, site)
    assert index.search("neighbor 10.7.7.7", k=3, kinds=["config"]) == [] or \
        "10.7.7.7" not in index.search("neighbor 10.7.7.7", k=3, kinds=["config"])[0]["snippet"]
    cfg = tmp_path / "dc1" / "leaf1.txt"
    cfg.write_text(CFG_A + "   neighbor 10.7.7.7 remote-as 65777\n")
    os.utime(cfg, ns=(1, 2_000_000_000))           # mtime change even on coarse-timestamp filesystems
    hits = index.search("neighbor 10.7.7.7 remote-as 65777", k=3, kinds=["config"])
    assert hits and "10.7.7.7" in hits[0]["snippet"]


def test_unchanged_site_is_not_reindexed_and_refresh_can_be_disabled(index, tmp_path, monkeypatch):
    site = _site(tmp_path, "dc1", CFG_A)
    rag.index_site_dir(index, site)
    assert index.refresh_stale() == []
    (tmp_path / "dc1" / "leaf1.txt").write_text(CFG_A + "   neighbor 10.7.7.7 remote-as 65777\n")
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_REFRESH_SECONDS", "-1")
    assert not any("10.7.7.7" in h["snippet"] for h in index.search("neighbor 10.7.7.7", k=5, kinds=["config"]))
    assert index.refresh_stale() == ["configs:dc1"]
    assert index.refresh_stale() == []                                   # fingerprint updated


def test_refresh_is_throttled(index, tmp_path, monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_REFRESH_SECONDS", "3600")
    rag.index_site_dir(index, _site(tmp_path, "dc1", CFG_A))
    calls = []
    monkeypatch.setattr(index, "refresh_stale", lambda: calls.append(1) or [])
    for _ in range(5):
        index.search("neighbor 10.1.1.0", k=1)
    assert len(calls) == 1


def test_same_short_hostname_in_two_sites_does_not_collide(index, tmp_path):
    rag.index_site_dir(index, _site(tmp_path, "dc1", CFG_A))
    rag.index_site_dir(index, _site(tmp_path, "dc2", CFG_A.replace("10.1.1", "10.2.2")))
    rows = index.db.conn().execute("SELECT ref FROM rag_docs WHERE kind='config'").fetchall()
    refs = [r[0] for r in rows]
    assert len(refs) == len(set(refs)) and all(r.startswith(("dc1:", "dc2:")) for r in refs)
    hit = index.search("neighbor 10.2.2.0 remote-as", k=1, kinds=["config"], hosts=["leaf1"])[0]
    assert hit["meta"]["site"] == "dc2" and "[dc2]" in hit["citation"] and "leaf1" in hit["citation"]
    other = index.search("neighbor 10.1.1.0 remote-as", k=1, kinds=["config"], hosts=["leaf1"])[0]
    assert "[dc1]" in other["citation"]
    topo = [r[0] for r in index.db.conn().execute("SELECT ref FROM rag_docs WHERE kind='topology'")]
    assert len(topo) == len(set(topo)) == 2


def test_citation_without_a_site_is_unchanged(index):
    rag.index_configs(index, [{"hostname": "leaf1", "platform": "eos", "config_text": CFG_A}])
    hit = index.search("neighbor 10.1.1.0", k=1)[0]
    assert hit["citation"].startswith("leaf1 running-config L") and "[" not in hit["citation"].split("`")[0]


def test_search_skips_ubiquitous_terms_and_caps_postings(index, monkeypatch):
    monkeypatch.setattr(rag, "_HIGH_DF_MIN_DOCS", 10)
    monkeypatch.setattr(rag, "_MAX_POSTINGS_PER_TERM", 4)
    docs = [rag.Doc("runbook", f"kb:{i}", f"t{i}", f"common filler words {'zebra' if i == 7 else ''}") for i in range(40)]
    index.replace_source("kb", docs)
    # selective term wins and the ubiquitous one is not even loaded
    top = index.search("common zebra", k=5)
    assert top and top[0]["ref"] == "kb:7" and len(top) == 1
    # only ubiquitous terms: still answers, but from at most the capped number of postings
    assert 0 < len(index.search("common filler", k=20)) <= 4


def test_empty_index_still_returns_nothing(index):
    assert index.search("anything at all", k=5) == []
    assert index.search("", k=5) == []
    assert index.refresh_stale() == []
