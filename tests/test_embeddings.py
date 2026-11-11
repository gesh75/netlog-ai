"""Tests for the Ollama embedding client (semantic RAG, v2.3.0 feature 2).

The client must never raise on a missing/unreachable Ollama: every
failure mode degrades to ``None`` / ``False`` so search falls back to
keyword-only. A fake ``requests`` session stands in for Ollama here;
no network is used.
"""
from __future__ import annotations

import pytest

from ai_log_analyzer import embeddings
from ai_log_analyzer.embeddings import Embedder, cosine, hybrid_fuse, pack_vector, unpack_vector


class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Session:
    """Fake requests.Session recording calls; behaviour set per test."""

    def __init__(self, get=None, post=None):
        self._get = get
        self._post = post
        self.get_calls = 0
        self.post_calls = 0

    def get(self, url, timeout=None):
        self.get_calls += 1
        if isinstance(self._get, Exception):
            raise self._get
        return self._get

    def post(self, url, json=None, timeout=None):
        self.post_calls += 1
        if isinstance(self._post, Exception):
            raise self._post
        return self._post


def _embedder(**kw):
    return Embedder(url="http://localhost:11434", model="nomic-embed-text", **kw)


# ── cosine / pack / fuse ─────────────────────────────────────────────────────

def test_cosine_identical_is_one_and_orthogonal_is_zero():
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    assert cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)
    assert cosine([], []) == 0.0
    assert cosine([0.0, 0.0], [1.0, 2.0]) == 0.0
    assert cosine([1.0], [1.0, 2.0]) == 0.0  # length mismatch


def test_pack_unpack_vector_roundtrip():
    vec = [0.5, -1.25, 3.0, 0.0]
    assert unpack_vector(pack_vector(vec)) == pytest.approx(vec)
    assert unpack_vector(b"") == []
    assert unpack_vector(b"\x00\x00") == []  # truncated blob: no whole float


def test_hybrid_fuse_blends_both_signals():
    fused = hybrid_fuse({1: 10.0, 2: 5.0}, {1: 0.9, 3: 0.1}, alpha=0.5)
    assert set(fused) == {1, 2, 3}
    assert fused[1] == pytest.approx(1.0)  # top on both signals
    assert fused[2] == pytest.approx(0.0)  # keyword-only, lowest BM25 of the set
    assert fused[3] == pytest.approx(0.0)  # vector-only, worst on both
    assert hybrid_fuse({}, {}) == {}
    assert hybrid_fuse({1: 4.0}, {}, alpha=0.5) == {1: 1.0}  # single doc: both norms are 1


def test_hybrid_fuse_alpha_one_is_keyword_only():
    fused = hybrid_fuse({1: 2.0, 2: 1.0}, {1: -1.0, 2: 1.0}, alpha=1.0)
    assert fused[1] > fused[2]


# ── Embedder: availability probe ─────────────────────────────────────────────

def test_is_available_true_and_cached():
    sess = _Session(get=_Resp(200, {"models": []}))
    emb = _embedder(session=sess)
    assert emb.is_available() is True
    assert emb.is_available() is True
    assert sess.get_calls == 1  # second call served from the 60 s cache


def test_is_available_false_on_connection_error_and_non_200():
    sess = _Session(get=ConnectionError("refused"))
    assert _embedder(session=sess).is_available() is False
    sess = _Session(get=_Resp(500, {}, "boom"))
    assert _embedder(session=sess).is_available() is False


# ── Embedder: embed ──────────────────────────────────────────────────────────

def test_embed_returns_vectors_in_order():
    sess = _Session(post=_Resp(200, {"embeddings": [[0.1, 0.2], [0.3, 0.4]]}))
    assert _embedder(session=sess).embed(["a", "b"]) == [[0.1, 0.2], [0.3, 0.4]]
    assert sess.post_calls == 1


def test_embed_returns_none_on_every_failure_mode():
    cases = [
        _Session(post=ConnectionError("refused")),
        _Session(post=TimeoutError("slow")),
        _Session(post=_Resp(404, {}, "model not found")),
        _Session(post=_Resp(200, {"embeddings": [[0.1], [0.2]]})),  # wrong count
        _Session(post=_Resp(200, {"nope": True})),  # missing key
        _Session(post=_Resp(200, ValueError("not json"))),  # bad body
    ]
    for sess in cases:
        assert _embedder(session=sess).embed(["hello"]) is None


def test_embed_empty_input_needs_no_request():
    sess = _Session(post=_Resp(200, {"embeddings": []}))
    assert _embedder(session=sess).embed([]) == []
    assert sess.post_calls == 0


def test_embed_one_returns_single_vector_or_none():
    sess = _Session(post=_Resp(200, {"embeddings": [[1.0, 2.0]]}))
    assert _embedder(session=sess).embed_one("x") == [1.0, 2.0]
    assert _embedder(session=_Session(post=ConnectionError())).embed_one("x") is None


# ── env factory ──────────────────────────────────────────────────────────────

def test_default_embedder_disabled_by_env(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_EMBEDDINGS", "0")
    assert embeddings.default_embedder() is None


def test_default_embedder_reads_url_model_and_ollama_fallback(monkeypatch):
    monkeypatch.delenv("AI_LOG_ANALYZER_EMBEDDING_URL", raising=False)
    monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")
    monkeypatch.setenv("AI_LOG_ANALYZER_EMBEDDING_MODEL", "my-model")
    emb = embeddings.default_embedder()
    assert emb is not None
    assert emb.url == "http://ollama:11434"
    assert emb.model == "my-model"


def test_default_embedder_defaults(monkeypatch):
    for var in ("AI_LOG_ANALYZER_EMBEDDINGS", "AI_LOG_ANALYZER_EMBEDDING_URL",
                "AI_LOG_ANALYZER_EMBEDDING_MODEL", "OLLAMA_URL"):
        monkeypatch.delenv(var, raising=False)
    emb = embeddings.default_embedder()
    assert emb is not None
    assert emb.url == "http://localhost:11434"
    assert emb.model == "nomic-embed-text"


def test_embeddings_enabled_parsing(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_EMBEDDINGS", "auto")
    assert embeddings.embeddings_enabled() is True
    monkeypatch.setenv("AI_LOG_ANALYZER_EMBEDDINGS", "off")
    assert embeddings.embeddings_enabled() is False
    monkeypatch.delenv("AI_LOG_ANALYZER_EMBEDDINGS")
    assert embeddings.embeddings_enabled() is True


def test_hybrid_alpha_clamped(monkeypatch):
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_HYBRID_ALPHA", "2")
    assert embeddings.hybrid_alpha() == 1.0
    monkeypatch.setenv("AI_LOG_ANALYZER_RAG_HYBRID_ALPHA", "bogus")
    assert embeddings.hybrid_alpha() == 0.5
