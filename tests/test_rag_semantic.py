"""Tests for hybrid (BM25 + vector) RAG search (v2.3.0 feature 2).

A fake ``Embedder`` stands in for Ollama: documents about BGP/OSPF/
interfaces get orthogonal vectors, and a query with no keyword overlap
("routing protocol fails") embeds near the BGP document. No network is
used. The keyword-only fallback (no Ollama) is covered by the same
tests with the embedder disabled or unavailable.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import rag
from ai_log_analyzer.embeddings import Embedder
from ai_log_analyzer.state_store import StateDB


class FakeEmbedder(Embedder):
    """Orthogonal toy vectors keyed on the words in the text."""

    def __init__(self, available: bool = True):
        super().__init__(url="http://fake:11434", model="fake-model")
        self._fake_available = available

    def is_available(self) -> bool:
        return self._fake_available

    def embed(self, texts: list[str]) -> list[list[float]] | None:
        if not self._fake_available:
            return None
        out = []
        for t in texts:
            low = t.lower()
            if "bgp" in low:
                out.append([1.0, 0.0, 0.0])
            elif "ospf" in low:
                out.append([0.0, 1.0, 0.0])
            elif "interface" in low or "link" in low:
                out.append([0.0, 0.0, 1.0])
            else:
                out.append([0.9, 0.1, 0.0])  # "routing protocol fails" lands near BGP
        return out


@pytest.fixture
def db(tmp_path):
    return StateDB(tmp_path / "state.db")


def _seed(index):
    docs = [
        rag.Doc("runbook", "kb:bgp", "BGP hold timer",
                "BGP neighbor hold timer expired after upgrade"),
        rag.Doc("runbook", "kb:ospf", "OSPF adjacency",
                "OSPF adjacency down on interface"),
        rag.Doc("runbook", "kb:link", "Interface link",
                "Interface link down, cable fault suspected"),
    ]
    index.replace_source("kb", docs)


def test_hybrid_search_finds_semantic_match_with_no_keyword_overlap(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    hits = index.search("routing protocol fails", k=3)
    assert hits, "vector signal should match despite zero shared terms"
    assert hits[0]["ref"] == "kb:bgp"
    assert index.last_search_mode == "hybrid"
    assert hits[0]["vector_score"] is not None and hits[0]["vector_score"] > 0.9
    assert hits[0]["bm25_score"] == 0.0  # no keyword overlap at all


def test_keyword_only_fallback_when_embeddings_disabled(db):
    index = rag.RagIndex(db, embedder=False)
    _seed(index)
    assert index.search("routing protocol fails", k=3) == []
    assert index.last_search_mode == "keyword"
    hits = index.search("BGP neighbor hold timer", k=3)
    assert hits and hits[0]["ref"] == "kb:bgp"
    assert hits[0]["vector_score"] is None
    assert hits[0]["bm25_score"] == hits[0]["score"]


def test_keyword_only_fallback_when_ollama_unavailable(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder(available=False))
    _seed(index)
    assert index.search("routing protocol fails", k=3) == []
    assert index.search("BGP neighbor hold timer", k=3)[0]["ref"] == "kb:bgp"
    assert index.last_search_mode == "keyword"
    assert index.stats()["embeddings"]["available"] is False


def test_hybrid_blend_keeps_bm25_winner_when_signals_agree(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    hits = index.search("BGP neighbor hold timer", k=3)
    assert hits[0]["ref"] == "kb:bgp"
    assert index.last_search_mode == "hybrid"
    assert hits[0]["bm25_score"] > 0 and hits[0]["vector_score"] == pytest.approx(1.0)
    assert 0.0 < hits[0]["score"] <= 1.0  # fused score is normalised


def test_hybrid_vector_can_outrank_keyword_match(db):
    # "interface" matches the link doc by keyword AND the OSPF doc mentions
    # "interface" too; the query vector points at the link doc instead.
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    hits = index.search("interface link down", k=3)
    assert hits[0]["ref"] == "kb:link"


def test_embed_missing_and_stats_report_coverage(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    stats = index.stats()["embeddings"]
    assert stats == {"enabled": True, "model": "fake-model", "available": True,
                     "embedded_docs": 3, "documents": 3}


def test_model_change_drops_old_vectors_and_reembeds(db):
    emb = FakeEmbedder()
    index = rag.RagIndex(db, embedder=emb)
    _seed(index)
    assert index.stats()["embeddings"]["embedded_docs"] == 3
    emb.model = "other-model"
    report = index.embed_missing()
    assert report == {"embedded": 3, "model": "other-model", "available": True}
    assert index.stats()["embeddings"]["embedded_docs"] == 3


def test_reindex_drops_embeddings_of_removed_docs(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    assert index.stats()["embeddings"]["embedded_docs"] == 3
    index.replace_source("kb", [rag.Doc("runbook", "kb:bgp", "BGP hold timer",
                                        "BGP neighbor hold timer expired")])
    assert index.stats()["embeddings"]["embedded_docs"] == 1
    assert index.search("routing protocol fails", k=3)[0]["ref"] == "kb:bgp"


def test_clear_drops_embeddings(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    index.clear()
    assert index.stats()["embeddings"]["embedded_docs"] == 0
    assert index.stats()["documents"] == 0


def test_stats_reports_embeddings_disabled(db):
    index = rag.RagIndex(db, embedder=False)
    _seed(index)
    assert index.stats()["embeddings"] == {"enabled": False, "model": None,
                                           "available": False, "embedded_docs": 0,
                                           "documents": 3}


def test_public_evidence_carries_both_scores(db):
    index = rag.RagIndex(db, embedder=FakeEmbedder())
    _seed(index)
    hits = index.search("BGP neighbor hold timer", k=1)
    pub = rag.public_evidence([{**hits[0], "id": "S1"}])
    assert pub[0]["bm25_score"] > 0
    assert pub[0]["vector_score"] == pytest.approx(1.0)


# ── API + CLI surface ────────────────────────────────────────────────────────

VIEW = "view-tok-0123456789"
ADMIN = "admin-tok-0123456789"


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    import ai_log_analyzer.web.app as web_app
    from ai_log_analyzer.state_store import open_db
    from ai_log_analyzer.web.app import create_app

    path = tmp_path / "state.db"
    monkeypatch.setenv("AI_LOG_ANALYZER_STATE_DB", str(path))
    open_db(path)
    monkeypatch.setattr(web_app, "API_TOKEN", "")
    monkeypatch.setenv("AI_LOG_ANALYZER_VIEWER_TOKENS", f"vera:{VIEW}")
    monkeypatch.setenv("AI_LOG_ANALYZER_ADMIN_TOKENS", f"ada:{ADMIN}")
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_api_search_reports_keyword_mode_without_ollama(api_client):
    r = api_client.post("/api/rag/reindex", json={}, headers=_h(ADMIN))
    assert r.status_code == 200
    body = api_client.get("/api/rag/search?q=bgp+neighbor+remote-as&k=3",
                          headers=_h(VIEW)).get_json()
    assert body["mode"] == "keyword"  # no Ollama in the test environment
    assert body["embeddings"]["enabled"] is True
    assert body["embeddings"]["available"] is False
    assert body["hits"] and body["hits"][0]["bm25_score"] > 0
    assert body["hits"][0]["vector_score"] is None


def test_api_stats_reports_embedding_coverage(api_client):
    api_client.post("/api/rag/reindex", json={}, headers=_h(ADMIN))
    body = api_client.get("/api/rag/stats", headers=_h(VIEW)).get_json()
    assert body["embeddings"]["documents"] == body["documents"]
    assert body["embeddings"]["embedded_docs"] == 0  # nothing embedded without Ollama


def test_cli_rag_embed_reports_unavailable_without_ollama(db, monkeypatch, capsys):
    import argparse

    from ai_log_analyzer.cli import cmd_rag

    args = argparse.Namespace(rag_cmd="embed", db=str(db.path))
    assert cmd_rag(args) == 0
    assert '"available": false' in capsys.readouterr().out


def test_cli_rag_search_json_reports_mode(db, monkeypatch, capsys):
    import argparse

    from ai_log_analyzer.cli import cmd_rag

    _seed(rag.RagIndex(db, embedder=False))
    args = argparse.Namespace(rag_cmd="search", db=str(db.path), query="BGP neighbor",
                              hosts=None, k=3, json=True)
    assert cmd_rag(args) == 0
    import json

    body = json.loads(capsys.readouterr().out)
    assert body["mode"] == "keyword"
    assert body["hits"] and body["hits"][0]["ref"] == "kb:bgp"
