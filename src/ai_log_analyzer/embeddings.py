"""Local embeddings for semantic RAG, via Ollama (``nomic-embed-text``).

The RAG index stays keyword-first: BM25 over SQLite postings is the
default and the only ranking when no embedding model is reachable.
When Ollama answers, document vectors are stored next to the index
(``rag_embeddings``) and a search blends the two signals — see
``hybrid_fuse`` in this module and ``RagIndex.search`` in ``rag.py``.

Nothing here is required at runtime: an absent, unreachable or
model-less Ollama only ever degrades a search to keyword-only, never
fails it. No new dependency — the calls go through ``requests`` (already
a project dependency) to Ollama's local HTTP API, and no document text
ever leaves the host.
"""
from __future__ import annotations

import logging
import math
import os
import struct
import time
from dataclasses import dataclass, field

import requests

log = logging.getLogger(__name__)

DEFAULT_MODEL = "nomic-embed-text"
DEFAULT_URL = "http://localhost:11434"
# nomic-embed-text context is 8192 tokens; ~8k chars is a safe truncation
# for the title+body text of one index document.
MAX_TEXT_CHARS = 8000
DEFAULT_BATCH_SIZE = 32
_PROBE_TIMEOUT_SECONDS = 2.0
_PROBE_TTL_SECONDS = 60.0


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def embeddings_enabled() -> bool:
    """``AI_LOG_ANALYZER_EMBEDDINGS``: ``0`` disables vectors entirely.

    Default (unset / ``auto``) is enabled-but-optional: Ollama is probed
    and a missing server just means keyword-only search.
    """
    raw = os.environ.get("AI_LOG_ANALYZER_EMBEDDINGS", "").strip().lower()
    if raw in ("0", "false", "no", "off", "disabled"):
        return False
    if raw in ("1", "true", "yes", "on", "auto", ""):
        return True
    log.warning("AI_LOG_ANALYZER_EMBEDDINGS=%r is not a known value; treating as enabled", raw)
    return True


def hybrid_alpha() -> float:
    """Weight of the BM25 signal in the hybrid score (0..1, default 0.5)."""
    return min(1.0, max(0.0, _env_float("AI_LOG_ANALYZER_RAG_HYBRID_ALPHA", 0.5)))


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity in [-1, 1]; 0.0 when either vector is empty/zero."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return max(-1.0, min(1.0, dot / (na * nb)))


def pack_vector(vec: list[float]) -> bytes:
    """float32 little-endian blob for the ``rag_embeddings`` table."""
    return struct.pack(f"<{len(vec)}f", *vec)


def unpack_vector(blob: bytes) -> list[float]:
    n = len(blob) // 4
    return list(struct.unpack(f"<{n}f", blob[: n * 4])) if n else []


def hybrid_fuse(bm25: dict[int, float], vectors: dict[int, float],
                alpha: float = 0.5) -> dict[int, float]:
    """Blend BM25 scores with cosine similarities into one ranking.

    Each signal is min-max normalised over the union of candidates, so a
    lone keyword hit and a lone vector hit are comparable; a document
    present in only one signal scores 0 on the other. ``alpha`` is the
    BM25 weight (1.0 = keyword-only). An empty input scores nothing.
    """
    ids = set(bm25) | set(vectors)
    if not ids:
        return {}
    b_max = max(bm25.values(), default=0.0)
    b_min = min(bm25.values(), default=0.0)
    v_max = max(vectors.values(), default=0.0)
    v_min = min(vectors.values(), default=0.0)

    def norm(value: float, lo: float, hi: float) -> float:
        return 1.0 if hi <= lo else (value - lo) / (hi - lo)

    return {doc_id: alpha * norm(bm25.get(doc_id, b_min), b_min, b_max)
            + (1.0 - alpha) * norm(vectors.get(doc_id, v_min), v_min, v_max)
            for doc_id in ids}


@dataclass
class Embedder:
    """Thin client for Ollama's ``/api/embed`` endpoint.

    ``session`` is injectable for tests; otherwise a private
    ``requests.Session`` is used. Every failure mode returns ``None`` /
    ``False`` instead of raising — callers treat that as "keyword-only".
    """

    url: str = DEFAULT_URL
    model: str = DEFAULT_MODEL
    timeout: float = 30.0
    batch_size: int = DEFAULT_BATCH_SIZE
    session: requests.Session | None = None
    _available: bool | None = field(default=None, init=False, repr=False)
    _probed_at: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.url = self.url.rstrip("/")
        if self.session is None:
            self.session = requests.Session()

    def is_available(self) -> bool:
        """True when Ollama answers ``/api/tags`` (result cached 60 s)."""
        now = time.monotonic()
        if self._available is not None and now - self._probed_at < _PROBE_TTL_SECONDS:
            return self._available
        self._probed_at = now
        try:
            resp = self.session.get(f"{self.url}/api/tags", timeout=_PROBE_TIMEOUT_SECONDS)  # type: ignore[union-attr]
            self._available = resp.status_code == 200
        except Exception as exc:  # connection refused / timeout / DNS — Ollama is absent
            log.debug("Ollama probe failed (%s): %s", self.url, type(exc).__name__)
            self._available = False
        return self._available

    def embed(self, texts: list[str]) -> list[list[float]] | None:
        """Embed ``texts`` (in order); ``None`` when Ollama cannot do it."""
        assert self.session is not None
        inputs = [(t or "")[:MAX_TEXT_CHARS] for t in texts]
        if not inputs:
            return []
        try:
            resp = self.session.post(f"{self.url}/api/embed",
                                     json={"model": self.model, "input": inputs},
                                     timeout=self.timeout)
        except Exception as exc:
            log.warning("Ollama embed failed (%s): %s", self.url, type(exc).__name__)
            return None
        if resp.status_code != 200:
            log.warning("Ollama embed HTTP %s: %s", resp.status_code, resp.text[:200])
            return None
        try:
            vectors = resp.json()["embeddings"]
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("Ollama embed returned an unusable body: %s", type(exc).__name__)
            return None
        if len(vectors) != len(inputs) or any(not isinstance(v, list) for v in vectors):
            log.warning("Ollama embed returned %d vectors for %d inputs", len(vectors), len(inputs))
            return None
        return [list(map(float, v)) for v in vectors]

    def embed_one(self, text: str) -> list[float] | None:
        vectors = self.embed([text])
        return vectors[0] if vectors else None


def default_embedder() -> Embedder | None:
    """Embedder from the environment, or ``None`` when vectors are disabled."""
    if not embeddings_enabled():
        return None
    url = (os.environ.get("AI_LOG_ANALYZER_EMBEDDING_URL", "").strip()
           or os.environ.get("OLLAMA_URL", "").strip() or DEFAULT_URL)
    model = os.environ.get("AI_LOG_ANALYZER_EMBEDDING_MODEL", "").strip() or DEFAULT_MODEL
    return Embedder(url=url, model=model,
                    timeout=_env_float("AI_LOG_ANALYZER_EMBEDDING_TIMEOUT", 30.0),
                    batch_size=max(1, _env_int("AI_LOG_ANALYZER_RAG_EMBED_BATCH", DEFAULT_BATCH_SIZE)))
