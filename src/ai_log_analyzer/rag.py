"""Local retrieval index over configs, drift, topology, runbooks and past incidents.

Every RCA and playbook should point at evidence an engineer can open and
check: a config stanza with line numbers, a drift hunk against the golden
config, a NetBox device record, a KB runbook, or a past incident ID. This
module builds that evidence base without any external service or package:

* **Store:** SQLite tables (``rag_docs``, ``rag_postings``) in the shared
  state DB or in ``AI_LOG_ANALYZER_RAG_DB``.
* **Ranking:** Okapi BM25 (k1=1.2, b=0.75) computed in Python over the
  postings, with a boost for documents about the affected devices.
* **Tokenizer:** network-aware. Interface names are canonicalized
  (``GigabitEthernet0/1`` and ``Gi0/1`` both index as ``gi0/1``); IP
  addresses, ASNs and Junos interface names stay whole tokens, so a BGP
  neighbor in a log line retrieves the stanza that configures it.

Document kinds and their citation format:

=========  ===========================================================
config     ``leaf1 running-config L120-L134 `router bgp 65001```
drift      ``leaf1 drift vs golden L120-L122 `router bgp 65001```
topology   ``NetBox device leaf1 (role leaf, site DC1)``
runbook    ``KB runbook routing/bgp_down``
incident   ``INC-000042 (2026-10-01, resolved)``
=========  ===========================================================

Config bodies are secret-scrubbed with ``sanitize()`` before they are stored,
so the index never holds passwords or keys at rest; line numbers refer to
the original file.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import logging
import math
import os
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai_log_analyzer.sanitize import sanitize

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rag_docs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ref         TEXT NOT NULL,
    host        TEXT,
    title       TEXT,
    body        TEXT NOT NULL,
    meta        TEXT,
    length      INTEGER NOT NULL,
    digest      TEXT,
    indexed_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS rag_docs_source ON rag_docs (source_key);
CREATE INDEX IF NOT EXISTS rag_docs_ref ON rag_docs (ref);
CREATE TABLE IF NOT EXISTS rag_postings (
    term    TEXT NOT NULL,
    doc_id  INTEGER NOT NULL,
    tf      INTEGER NOT NULL,
    PRIMARY KEY (term, doc_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rag_postings_doc ON rag_postings (doc_id);
"""

_K1 = 1.2
_B = 0.75
_MAX_CHUNK_LINES = 60
_WINDOW_LINES = 40
_SNIPPET_CHARS = 420

# ─────────────────────────────────────────────────────────────────────────────
# Tokenizer
# ─────────────────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:/-]*[a-z0-9]|[a-z0-9]")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_SPLIT_RE = re.compile(r"[._:/-]+")
_IFACE_RE = re.compile(
    r"^(gigabitethernet|tengigabitethernet|twentyfivegige|fortygigabitethernet|fortygige|"
    r"hundredgigabitethernet|hundredgige|ethernet|eth|et|gig|gi|te|port-channel|po|"
    r"loopback|lo|management|mgmt|ma|tunnel|tu|vlan)(\d[\d/.:]*)$")
_IFACE_SHORT = {
    "gigabitethernet": "gi", "gig": "gi", "gi": "gi", "tengigabitethernet": "te", "te": "te",
    "twentyfivegige": "twe", "fortygigabitethernet": "fo", "fortygige": "fo",
    "hundredgigabitethernet": "hu", "hundredgige": "hu", "ethernet": "et", "eth": "et", "et": "et",
    "port-channel": "po", "po": "po", "loopback": "lo", "lo": "lo", "management": "ma",
    "mgmt": "ma", "ma": "ma", "tunnel": "tu", "tu": "tu", "vlan": "vlan",
}
_STOPWORDS = frozenset({
    "the", "and", "for", "on", "to", "of", "a", "an", "in", "is", "from", "with", "by", "at",
    "or", "be", "as", "it", "this", "that", "no", "not", "are", "was", "has", "have",
})


def tokenize(text: str) -> list[str]:
    """Lowercased terms with network-entity awareness (see module docstring)."""
    out: list[str] = []
    for tok in _TOKEN_RE.findall((text or "").lower()):
        if tok in _STOPWORDS:
            continue
        m = _IFACE_RE.match(tok)
        if m:
            short = _IFACE_SHORT[m.group(1)] + m.group(2)
            out.append(short)
            if short != tok:
                out.append(tok)
            continue
        out.append(tok)
        if tok.startswith("as") and tok[2:].isdigit():
            out.append(tok[2:])   # AS65001 also matches "remote-as 65001"
            continue
        if _IPV4_RE.match(tok):
            if "/" in tok:
                out.append(tok.split("/", 1)[0])
            continue
        if _SPLIT_RE.search(tok):
            # Junos units (ge-0/0/1.0) also index as the physical port.
            if re.match(r"^[a-z]{2}-\d+/\d+/\d+\.\d+$", tok):
                out.append(tok.rsplit(".", 1)[0])
            out.extend(p for p in _SPLIT_RE.split(tok) if len(p) >= 3 and p not in _STOPWORDS)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Config chunking and drift
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Chunk:
    start: int        # 1-based, inclusive
    end: int
    heading: str
    lines: list[str]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


_VOLATILE_RE = re.compile(
    r"^\s*(?:##?\s*last (?:commit|changed)|!\s*last configuration change|!\s*nvram config last|"
    r"building configuration|current configuration\s*:|ntp clock-period|!\s*time:|"
    r"#\s*(?:generated|exported) (?:at|on))", re.IGNORECASE)


def _style(lines: list[str]) -> str:
    code = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith(("#", "!"))]
    if not code:
        return "indent"
    if sum(1 for ln in code if ln.lstrip().startswith("set ")) > len(code) * 0.5:
        return "set"
    if sum(1 for ln in code if ln.rstrip().endswith("{")) >= 3:
        return "curly"
    return "indent"


def _windows(chunk: Chunk) -> list[Chunk]:
    if len(chunk.lines) <= _MAX_CHUNK_LINES:
        return [chunk]
    out = []
    for off in range(0, len(chunk.lines), _WINDOW_LINES):
        part = chunk.lines[off:off + _WINDOW_LINES]
        out.append(Chunk(chunk.start + off, chunk.start + off + len(part) - 1, chunk.heading, part))
    return out


_SPLIT_STANZA_LINES = 15


def _curly_chunks(lines: list[str]) -> list[Chunk]:
    """Junos-style braces: parse a stanza tree, emit the most specific stanzas.

    Small top-level stanzas stay whole; larger ones are emitted as their
    children (``interfaces > ge-0/0/0``), recursing while a child is still
    oversized. Leaf statements directly under a split stanza become runs
    headed by that stanza's path, so no line is dropped.
    """
    root: dict[str, Any] = {"head": "", "start": 0, "end": len(lines), "kids": [], "direct": []}
    stack = [root]
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith(("#", "/*")):
            continue
        if s.endswith("{"):
            node = {"head": s.rstrip("{ ").strip(), "start": i, "end": i, "kids": [], "direct": []}
            stack[-1]["kids"].append(node)
            stack.append(node)
        elif s.startswith("}") and len(stack) > 1:
            stack.pop()["end"] = i
        else:
            stack[-1]["direct"].append(i)
    while len(stack) > 1:      # unbalanced input: close what is open
        stack.pop()["end"] = len(lines)

    out: list[Chunk] = []

    def piece(start: int, end: int, heading: str) -> None:
        out.extend(_windows(Chunk(start, end, heading, lines[start - 1:end])))

    def emit(node: dict, path: str) -> None:
        size = node["end"] - node["start"] + 1
        if not node["kids"] or size <= (_SPLIT_STANZA_LINES if path == node["head"] else _MAX_CHUNK_LINES):
            piece(node["start"], node["end"], path)
            return
        run: list[int] = []
        for ln in node["direct"] + [None]:
            if ln is not None and (not run or ln == run[-1] + 1):
                run.append(ln)
                continue
            if run:
                piece(run[0], run[-1], path)
            run = [ln] if ln is not None else []
        for kid in node["kids"]:
            emit(kid, f"{path} > {kid['head']}")

    for top in root["kids"]:
        emit(top, top["head"])
    out.sort(key=lambda c: c.start)
    return out


def _set_chunks(lines: list[str]) -> list[Chunk]:
    out: list[Chunk] = []
    cur: Chunk | None = None
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s.startswith(("set ", "deactivate ", "delete ")):
            continue
        words = s.split()
        key = " ".join(words[1:4]) if words[0] == "set" else " ".join(words[:4])
        if cur is not None and cur.heading == key and i == cur.end + 1:
            cur.lines.append(raw)
            cur.end = i
            continue
        if cur is not None:
            out.extend(_windows(cur))
        cur = Chunk(i, i, key, [raw])
    if cur is not None:
        out.extend(_windows(cur))
    return out


def _indent_chunks(lines: list[str]) -> list[Chunk]:
    out: list[Chunk] = []
    cur: Chunk | None = None
    loose: Chunk | None = None   # run of single top-level lines sharing a first word

    def flush_loose() -> None:
        nonlocal loose
        if loose is not None:
            out.extend(_windows(loose))
            loose = None

    for i, raw in enumerate(lines, 1):
        if not raw.strip() or raw.strip() in ("!", "end", "exit"):
            continue
        if raw[:1] in (" ", "\t"):
            if cur is not None:
                cur.lines.append(raw)
                cur.end = i
            continue
        s = raw.strip()
        if s.startswith(("!", "#")) and not s.startswith("#config"):
            continue
        if cur is not None:
            if len(cur.lines) > 1:
                flush_loose()
                out.extend(_windows(cur))
            else:
                first = cur.heading.split()[0]
                if loose is not None and loose.heading == first:
                    loose.lines.append(cur.lines[0])
                    loose.end = cur.end
                else:
                    flush_loose()
                    loose = Chunk(cur.start, cur.end, first, list(cur.lines))
        cur = Chunk(i, i, s, [raw])
    if cur is not None:
        if len(cur.lines) > 1:
            flush_loose()
            out.extend(_windows(cur))
        else:
            first = cur.heading.split()[0]
            if loose is not None and loose.heading == first:
                loose.lines.append(cur.lines[0])
                loose.end = cur.end
            else:
                flush_loose()
                loose = Chunk(cur.start, cur.end, first, list(cur.lines))
    flush_loose()
    return out


def chunk_config(text: str) -> list[Chunk]:
    """Split a config into stanzas with original 1-based line numbers.

    Handles Junos curly-brace and ``set`` formats and indentation-based CLIs
    (IOS/IOS-XE/NX-OS/EOS/FRR/FortiOS). Oversized stanzas are split into
    second-level children (Junos) or 40-line windows.
    """
    lines = (text or "").splitlines()
    style = _style(lines)
    if style == "curly":
        return _curly_chunks(lines)
    if style == "set":
        return _set_chunks(lines)
    return _indent_chunks(lines)


def _heading_at(chunks: list[Chunk], line_no: int) -> str:
    for c in chunks:
        if c.start <= line_no <= c.end:
            return c.heading
    return ""


def config_drift(running: str, golden: str) -> dict[str, Any]:
    """Line-level drift of the running config against its golden config.

    Returns ``{"drifted": bool, "added": n, "removed": n, "hunks": [...]}``.
    Each hunk carries running/golden line ranges (1-based), the enclosing
    running-config stanza, and the added/removed lines. Volatile banner
    lines (last-commit stamps, "Building configuration") are ignored.
    """
    run_lines = (running or "").splitlines()
    gold_lines = (golden or "").splitlines()

    def keep(lines: list[str]) -> list[tuple[int, str]]:
        return [(i, ln.rstrip()) for i, ln in enumerate(lines, 1)
                if ln.strip() and not _VOLATILE_RE.match(ln)]

    run_kept = keep(run_lines)
    gold_kept = keep(gold_lines)
    run_chunks = chunk_config(running)
    gold_chunks = chunk_config(golden)
    sm = difflib.SequenceMatcher(a=[t for _, t in gold_kept], b=[t for _, t in run_kept],
                                 autojunk=False)
    hunks: list[dict[str, Any]] = []
    added = removed = 0
    for tag, g1, g2, r1, r2 in sm.get_opcodes():
        if tag == "equal":
            continue
        plus = [run_kept[j][1] for j in range(r1, r2)]
        minus = [gold_kept[j][1] for j in range(g1, g2)]
        added += len(plus)
        removed += len(minus)
        if r2 > r1:
            rs, re_ = run_kept[r1][0], run_kept[r2 - 1][0]
        else:  # pure deletion: anchor at the running line before the gap
            rs = re_ = run_kept[r1 - 1][0] if r1 > 0 else 1
        gs = gold_kept[g1][0] if g2 > g1 else (gold_kept[g1 - 1][0] if g1 > 0 else 1)
        ge = gold_kept[g2 - 1][0] if g2 > g1 else gs
        heading = _heading_at(run_chunks, rs) or _heading_at(gold_chunks, gs)
        hunks.append({"kind": {"replace": "changed", "insert": "added", "delete": "removed"}[tag],
                      "running_lines": [rs, re_], "golden_lines": [gs, ge], "stanza": heading,
                      "added": plus[:40], "removed": minus[:40]})
    return {"drifted": bool(hunks), "added": added, "removed": removed, "hunks": hunks}


# ─────────────────────────────────────────────────────────────────────────────
# Index
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Doc:
    kind: str
    ref: str
    title: str
    body: str
    host: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def _short(host: str) -> str:
    return (host or "").strip().lower().split(".", 1)[0]


def citation_for(kind: str, ref: str, title: str, host: str, meta: Mapping[str, Any]) -> str:
    if kind == "config":
        return f"{host} running-config L{meta.get('start')}-L{meta.get('end')} `{title}`"
    if kind == "drift":
        return f"{host} drift vs golden L{meta.get('start')}-L{meta.get('end')} `{title}`"
    if kind == "incident":
        status = "resolved" if meta.get("resolved") else "open"
        day = str(meta.get("generated_at") or "")[:10]
        return f"{ref} ({day}, {status})" if day else f"{ref} ({status})"
    if kind == "runbook":
        return f"KB runbook {title}"
    if kind == "topology":
        return f"{meta.get('source', 'topology').replace('netbox', 'NetBox')} {title}"
    return f"{kind} {ref}"


class RagIndex:
    """BM25 index persisted in SQLite (see module docstring)."""

    def __init__(self, db: Any) -> None:   # db: state_store.StateDB
        self.db = db
        db.conn().executescript(_SCHEMA)

    # ── write ───────────────────────────────────────────────────────────────
    @staticmethod
    def _rows(docs: Iterable[Doc]) -> list[tuple[Doc, Counter, int, str]]:
        rows = []
        for d in docs:
            terms = tokenize(f"{d.title}\n{d.body}\n{d.host}")
            if not terms:
                continue
            digest = d.meta.get("digest") or hashlib.sha1(
                f"{d.kind}|{d.ref}|{d.title}|{d.body}".encode()).hexdigest()
            rows.append((d, Counter(terms), len(terms), digest))
        return rows

    @staticmethod
    def _insert(c: Any, source_key: str, rows: list[tuple[Doc, Counter, int, str]], now: float) -> None:
        for d, tf, length, digest in rows:
            cur = c.execute(
                "INSERT INTO rag_docs(source_key, kind, ref, host, title, body, meta, length, digest, "
                "indexed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (source_key, d.kind, d.ref, _short(d.host), d.title[:300], d.body,
                 json.dumps(d.meta, default=str), length, digest, now))
            c.executemany("INSERT INTO rag_postings(term, doc_id, tf) VALUES (?, ?, ?)",
                          [(t, cur.lastrowid, n) for t, n in tf.items()])

    @staticmethod
    def _delete_ids(c: Any, ids: list[int]) -> None:
        if ids:
            c.executemany("DELETE FROM rag_postings WHERE doc_id=?", [(i,) for i in ids])
            c.executemany("DELETE FROM rag_docs WHERE id=?", [(i,) for i in ids])

    def replace_source(self, source_key: str, docs: Iterable[Doc]) -> int:
        """Atomically replace every document of ``source_key`` (idempotent reindex)."""
        rows = self._rows(docs)
        with self.db.write() as c:
            self._delete_ids(c, [r[0] for r in c.execute(
                "SELECT id FROM rag_docs WHERE source_key=?", (source_key,))])
            self._insert(c, source_key, rows, time.time())
        return len(rows)

    def upsert(self, source_key: str, docs: Iterable[Doc], *, drop_refs: Iterable[str] = ()) -> int:
        """Replace the given refs inside ``source_key`` and delete ``drop_refs``."""
        rows = self._rows(docs)
        refs = [r[0].ref for r in rows] + list(drop_refs)
        with self.db.write() as c:
            ids: list[int] = []
            for off in range(0, len(refs), 500):
                part = refs[off:off + 500]
                ids.extend(r[0] for r in c.execute(
                    f"SELECT id FROM rag_docs WHERE source_key=? AND ref IN ({','.join('?' * len(part))})",
                    [source_key, *part]))
            self._delete_ids(c, ids)
            self._insert(c, source_key, rows, time.time())
        return len(rows)

    def source_digests(self, source_key: str) -> dict[str, str]:
        return dict(self.db.conn().execute(
            "SELECT ref, digest FROM rag_docs WHERE source_key=?", (source_key,)).fetchall())

    def clear(self) -> None:
        with self.db.write() as c:
            c.execute("DELETE FROM rag_postings")
            c.execute("DELETE FROM rag_docs")

    # ── read ────────────────────────────────────────────────────────────────
    def stats(self) -> dict[str, Any]:
        conn = self.db.conn()
        by_kind = dict(conn.execute("SELECT kind, COUNT(*) FROM rag_docs GROUP BY kind").fetchall())
        sources = [r[0] for r in conn.execute("SELECT DISTINCT source_key FROM rag_docs ORDER BY 1")]
        return {"documents": sum(by_kind.values()), "by_kind": by_kind, "sources": sources}

    def search(self, query: str, k: int = 5, *, kinds: Iterable[str] | None = None,
               hosts: Iterable[str] | None = None, host_only_kinds: Iterable[str] = (),
               host_boost: float = 1.0) -> list[dict[str, Any]]:
        """Top-``k`` BM25 hits for ``query``.

        ``hosts`` boosts documents about those devices; for kinds listed in
        ``host_only_kinds`` (e.g. config, drift) documents about other
        devices are dropped, since citing an unrelated device's config is
        noise, not evidence.
        """
        q_terms = list(dict.fromkeys(tokenize(query)))[:64]
        if not q_terms:
            return []
        conn = self.db.conn()
        n_docs, avgdl = conn.execute("SELECT COUNT(*), AVG(length) FROM rag_docs").fetchone()
        if not n_docs:
            return []
        avgdl = float(avgdl or 1.0)
        marks = ",".join("?" * len(q_terms))
        postings = conn.execute(
            f"SELECT term, doc_id, tf FROM rag_postings WHERE term IN ({marks})", q_terms).fetchall()
        if not postings:
            return []
        df = Counter(term for term, _, _ in postings)
        doc_ids = {doc_id for _, doc_id, _ in postings}
        kind_set = set(kinds) if kinds else None
        host_set = {_short(h) for h in hosts or () if h}
        host_only = set(host_only_kinds)
        meta_rows: dict[int, tuple] = {}
        ids = list(doc_ids)
        for off in range(0, len(ids), 900):
            part = ids[off:off + 900]
            for row in conn.execute(
                    f"SELECT id, kind, host, length FROM rag_docs WHERE id IN ({','.join('?' * len(part))})",
                    part):
                meta_rows[row[0]] = row
        scores: Counter = Counter()
        for term, doc_id, tf in postings:
            row = meta_rows.get(doc_id)
            if row is None:
                continue
            _, kind, host, length = row
            if kind_set is not None and kind not in kind_set:
                continue
            if kind in host_only and host_set and host not in host_set:
                continue
            idf = math.log(1 + (n_docs - df[term] + 0.5) / (df[term] + 0.5))
            scores[doc_id] += idf * tf * (_K1 + 1) / (tf + _K1 * (1 - _B + _B * length / avgdl))
        if host_set:
            for doc_id in scores:
                if meta_rows[doc_id][2] in host_set:
                    scores[doc_id] *= 1 + host_boost
        top = scores.most_common(k)
        if not top:
            return []
        rows = {r[0]: r for r in conn.execute(
            f"SELECT id, kind, ref, host, title, body, meta FROM rag_docs WHERE id IN "
            f"({','.join('?' * len(top))})", [d for d, _ in top])}
        hits = []
        for doc_id, score in top:
            _, kind, ref, host, title, body, meta = rows[doc_id]
            meta_d = json.loads(meta or "{}")
            hits.append({"kind": kind, "ref": ref, "host": host, "title": title,
                         "score": round(score, 3), "meta": meta_d,
                         "snippet": _snippet(body, q_terms),
                         "citation": citation_for(kind, ref, title, host, meta_d)})
        return hits


def _snippet(body: str, q_terms: list[str]) -> str:
    """The densest few lines of ``body`` for the query, trimmed to the budget."""
    lines = body.splitlines()
    if len(body) <= _SNIPPET_CHARS:
        return body
    qs = set(q_terms)
    best, best_score = 0, -1
    for i in range(len(lines)):
        window = " ".join(lines[i:i + 6])
        score = sum(1 for t in tokenize(window) if t in qs)
        if score > best_score:
            best, best_score = i, score
    return "\n".join(lines[best:best + 8])[:_SNIPPET_CHARS]


# ─────────────────────────────────────────────────────────────────────────────
# Builders
# ─────────────────────────────────────────────────────────────────────────────

def _scrub(text: str) -> str:
    return sanitize(text, mask_pii=False)[0]


def config_docs(hostname: str, platform: str, config_text: str,
                golden_text: str | None = None) -> list[Doc]:
    """Stanza documents for one device, plus drift hunks when a golden config is given."""
    docs: list[Doc] = []
    for c in chunk_config(config_text):
        docs.append(Doc("config", f"{hostname}:L{c.start}-L{c.end}", c.heading, _scrub(c.text),
                        host=hostname, meta={"start": c.start, "end": c.end, "platform": platform}))
    if golden_text is not None:
        drift = config_drift(config_text, golden_text)
        for h in drift["hunks"]:
            rs, re_ = h["running_lines"]
            body = "\n".join([f"stanza: {h['stanza']}"] + [f"+ {ln}" for ln in h["added"]]
                             + [f"- {ln}" for ln in h["removed"]])
            docs.append(Doc("drift", f"{hostname}:drift:L{rs}-L{re_}", h["stanza"] or "(top level)",
                            _scrub(body), host=hostname,
                            meta={"start": rs, "end": re_, "golden_lines": h["golden_lines"],
                                  "change": h["kind"], "platform": platform}))
    return docs


def index_configs(index: RagIndex, devices: Iterable[Mapping[str, Any]],
                  golden: Mapping[str, str] | None = None, *, source_key: str = "configs") -> int:
    """Index ``[{hostname, platform, config_text}]``; ``golden`` maps hostname → golden text."""
    golden = {_short(k): v for k, v in (golden or {}).items()}
    docs: list[Doc] = []
    for dev in devices:
        host = str(dev.get("hostname") or "")
        text = str(dev.get("config_text") or "")
        if not host or not text:
            continue
        docs.extend(config_docs(host, str(dev.get("platform") or ""), text, golden.get(_short(host))))
    return index.replace_source(source_key, docs)


def _read_golden(golden_dir: Path | None, hostname: str, file_name: str) -> str | None:
    if golden_dir is None:
        return None
    for cand in (golden_dir / file_name, golden_dir / f"{hostname}.txt", golden_dir / f"{hostname}.cfg",
                 golden_dir / f"{hostname}.conf"):
        if cand.is_file():
            return cand.read_text(encoding="utf-8", errors="replace")
    return None


def index_site_dir(index: RagIndex, site_dir: str | Path, golden_dir: str | Path | None = None) -> dict:
    """Index one bundled site (``manifest.json`` + per-device configs)."""
    site_dir = Path(site_dir)
    manifest = json.loads((site_dir / "manifest.json").read_text(encoding="utf-8"))
    gdir = Path(golden_dir) if golden_dir else (site_dir / "golden" if (site_dir / "golden").is_dir() else None)
    devices, golden = [], {}
    for dev in manifest.get("devices") or []:
        path = site_dir / str(dev.get("file") or "")
        if not path.is_file():
            continue
        host = str(dev.get("hostname") or path.stem)
        devices.append({"hostname": host, "platform": dev.get("platform", ""),
                        "config_text": path.read_text(encoding="utf-8", errors="replace")})
        gold = _read_golden(gdir, host, path.name)
        if gold is not None:
            golden[host] = gold
    site = str(manifest.get("site") or site_dir.name)
    n_cfg = index_configs(index, devices, golden, source_key=f"configs:{site}")
    n_topo = index_topology(index, {**manifest, "source": manifest.get("source", "site manifest")},
                            source_key=f"topology:{site}")
    return {"site": site, "devices": len(devices), "golden": len(golden), "config_docs": n_cfg,
            "topology_docs": n_topo}


def index_topology(index: RagIndex, manifest: Mapping[str, Any], *, source_key: str = "topology") -> int:
    """Device and link records from a NetBox-built or bundled site manifest."""
    source = str(manifest.get("source") or "topology")
    site = str(manifest.get("site") or "")
    links_by_host: dict[str, list[str]] = {}
    for ln in manifest.get("links") or []:
        a, b = str(ln.get("a") or ""), str(ln.get("b") or "")
        if a and b:
            links_by_host.setdefault(a, []).append(f"{ln.get('a_iface', '')} -> {b} {ln.get('b_iface', '')}")
            links_by_host.setdefault(b, []).append(f"{ln.get('b_iface', '')} -> {a} {ln.get('a_iface', '')}")
    docs = []
    for dev in manifest.get("devices") or []:
        host = str(dev.get("hostname") or dev.get("name") or "")
        if not host:
            continue
        fields = {k: v for k, v in dev.items() if k in (
            "role", "function", "platform", "site", "status", "device_type", "primary_ip", "tenant", "rack")
            and v}
        fields.setdefault("site", site)
        head = ", ".join(f"{k} {v}" for k, v in fields.items() if v)
        body = "\n".join([f"device {host}", *(f"{k}: {v}" for k, v in fields.items() if v),
                          *(f"link {x}" for x in links_by_host.get(host, [])[:40])])
        docs.append(Doc("topology", f"{source}:device:{host}", f"device {host} ({head})", body,
                        host=host, meta={"source": source, "site": site}))
    return index.replace_source(source_key, docs)


def index_kb(index: RagIndex) -> int:
    """Every curated KB playbook as a runbook document."""
    from ai_log_analyzer import kb

    docs, seen = [], set()
    for category, subs in kb.KB.items():
        for sub_key, entry in subs.items():
            if not isinstance(entry, dict) or id(entry) in seen:
                continue  # "_default" and shared entries alias an already indexed playbook
            seen.add(id(entry))
            parts = [str(entry.get("root_cause", "")), str(entry.get("risk", ""))]
            for phase in entry.get("phases") or []:
                parts.append(f"{phase.get('name', '')}: {phase.get('goal', '')}")
                for a in phase.get("actions") or []:
                    parts.extend(str(c) for c in (a.get("cli") or {}).values())
                    parts.append(str(a.get("expected", "")))
            parts.extend(str(x) for x in entry.get("preventive_config") or [])
            parts.extend(str(x) for x in entry.get("monitoring") or [])
            docs.append(Doc("runbook", f"kb:{category}/{sub_key}", f"{category}/{sub_key}",
                            "\n".join(p for p in parts if p),
                            meta={"category": category, "entry": sub_key, "match": entry.get("match", "")}))
    return index.replace_source("kb", docs)


def _incident_digest(inc: str, rec: Mapping[str, Any]) -> str:
    keys = ("description", "category", "severity", "devices", "sample_messages", "generated_at", "resolution")
    return hashlib.sha1(json.dumps([inc, *(rec.get(k) for k in keys)], default=str).encode()).hexdigest()


def incident_doc(rec: Mapping[str, Any]) -> Doc:
    from ai_log_analyzer.memory import incident_id

    inc = str(rec.get("incident_id") or incident_id(dict(rec)))
    devices = list(rec.get("devices") or [])
    body = "\n".join([str(rec.get("description", "")), f"category {rec.get('category', '')}",
                      f"severity {rec.get('severity', '')}", f"devices {' '.join(devices)}",
                      *[str(m) for m in rec.get("sample_messages") or []],
                      *([f"resolution: {rec['resolution']}"] if rec.get("resolution") else [])])
    meta = {"generated_at": rec.get("generated_at", ""), "resolved": bool(rec.get("resolution")),
            "resolution": rec.get("resolution", ""), "devices": devices,
            "category": rec.get("category", ""), "severity": rec.get("severity", ""),
            "digest": _incident_digest(inc, rec)}
    return Doc("incident", inc, str(rec.get("description", ""))[:200], _scrub(body),
               host=devices[0] if len(devices) == 1 else "", meta=meta)


def sync_incidents(index: RagIndex, store: Any) -> int:
    """Bring the index in line with the incident store; returns docs written.

    Incremental: only records that are new or changed (e.g. newly resolved)
    are scrubbed and re-indexed, and records the store dropped are removed.
    """
    if store is None:
        return 0
    have = index.source_digests("incidents")
    changed, want = [], set()
    for rec in store.records():
        inc = rec["incident_id"]
        want.add(inc)
        if have.get(inc) != _incident_digest(inc, rec):
            changed.append(rec)
    gone = [ref for ref in have if ref not in want]
    if not changed and not gone:
        return 0
    return index.upsert("incidents", (incident_doc(r) for r in changed), drop_refs=gone)


def build_default_index(index: RagIndex, *, sites_dir: str | Path | None = None,
                        golden_dir: str | Path | None = None, netbox: bool = False,
                        store: Any = None) -> dict[str, Any]:
    """(Re)build every source: KB runbooks, site configs (+ golden drift),
    NetBox topology and the incident store."""
    report: dict[str, Any] = {"kb": index_kb(index), "sites": []}
    if sites_dir and Path(sites_dir).is_dir():
        for site in sorted(p for p in Path(sites_dir).iterdir() if (p / "manifest.json").is_file()):
            gdir = Path(golden_dir) / site.name if golden_dir and (Path(golden_dir) / site.name).is_dir() \
                else golden_dir
            try:
                report["sites"].append(index_site_dir(index, site, gdir))
            except (OSError, ValueError) as exc:
                log.warning("skipping site %s: %s", site, exc)
    if netbox:
        from ai_log_analyzer import netbox as nb
        if nb.is_enabled():
            try:
                report["netbox"] = index_topology(index, nb.build_site_manifest(), source_key="topology:netbox")
            except Exception as exc:  # NetBoxError / network
                report["netbox_error"] = str(exc)[:200]
    if store is None:
        from ai_log_analyzer.memory import get_store
        store = get_store()
    report["incidents"] = sync_incidents(index, store)
    report["stats"] = index.stats()
    return report


_INDEXES: dict[str, RagIndex] = {}


def get_index() -> RagIndex | None:
    """The configured index (``AI_LOG_ANALYZER_RAG_DB`` or the shared state
    DB), or None when neither is set or ``AI_LOG_ANALYZER_RAG=0``."""
    if os.environ.get("AI_LOG_ANALYZER_RAG", "").strip().lower() in ("0", "false", "off", "no"):
        return None
    from ai_log_analyzer.state_store import get_state_db, open_db

    path = os.environ.get("AI_LOG_ANALYZER_RAG_DB", "").strip()
    db = open_db(path) if path else get_state_db()
    if db is None:
        return None
    key = str(db.path)
    if key not in _INDEXES:
        _INDEXES[key] = RagIndex(db)
    return _INDEXES[key]


# ─────────────────────────────────────────────────────────────────────────────
# Evidence for analyzer / copilot
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MIX: dict[str, int] = {"drift": 2, "config": 2, "incident": 2, "runbook": 1, "topology": 1}
_CITE_RE = re.compile(r"\[(S\d{1,2})\]")


def retrieve_evidence(index: RagIndex | None, query: str, *, hosts: Iterable[str] = (),
                      mix: Mapping[str, int] | None = None, limit: int = 6) -> list[dict[str, Any]]:
    """Labelled evidence (``S1``..``Sn``) mixed across kinds by ``mix`` caps."""
    if index is None or not query.strip():
        return []
    mix = dict(mix or DEFAULT_MIX)
    hosts = [h for h in hosts if h]
    try:
        hits = index.search(query, k=max(limit * 5, 20), hosts=hosts,
                            host_only_kinds=("config", "drift", "topology") if hosts else ())
    except Exception as exc:  # sqlite3.Error — retrieval must never break an analysis
        log.warning("RAG retrieval failed: %s", exc)
        return []
    if hosts:
        # Without a host match, config/drift/topology hits are about other devices.
        hs = {_short(h) for h in hosts}
        hits = [h for h in hits if h["kind"] not in ("config", "drift", "topology") or h["host"] in hs]
    else:
        hits = [h for h in hits if h["kind"] not in ("config", "drift")]
    taken: Counter = Counter()
    out = []
    for h in hits:
        if taken[h["kind"]] >= mix.get(h["kind"], 0):
            continue
        taken[h["kind"]] += 1
        out.append(h)
        if len(out) >= limit:
            break
    for i, h in enumerate(out, 1):
        h["id"] = f"S{i}"
    return out


def evidence_block(evidence: list[dict[str, Any]]) -> str:
    """Prompt section listing the evidence; callers fence it with wrap_untrusted."""
    parts = []
    for e in evidence:
        parts.append(f"[{e['id']}] {e['citation']}\n{e['snippet']}")
    return "\n\n".join(parts)


CITATION_RULES = (
    "EVIDENCE RULES: Ground the root cause and each phase in the numbered EVIDENCE when it is relevant, "
    "citing it inline as [S1], [S2]. Cite only labels that appear in EVIDENCE. If no evidence supports "
    "a claim, say it is an inference. Never invent config line numbers or incident IDs."
)


def check_citations(text: str, evidence: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Split the ``[S#]`` labels in model output into valid and invented ones."""
    known = {e["id"] for e in evidence}
    used = list(dict.fromkeys(_CITE_RE.findall(text or "")))
    return {"cited": [u for u in used if u in known], "invalid": [u for u in used if u not in known]}


def public_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evidence as attached to playbooks and API responses."""
    keep = ("id", "kind", "ref", "host", "title", "citation", "snippet", "score")
    out = []
    for e in evidence:
        rec = {k: e.get(k) for k in keep}
        m = e.get("meta") or {}
        if e["kind"] in ("config", "drift"):
            rec["lines"] = [m.get("start"), m.get("end")]
        if e["kind"] == "drift":
            rec["golden_lines"] = m.get("golden_lines")
        if e["kind"] == "incident":
            rec["resolution"] = m.get("resolution", "")
        out.append(rec)
    return out
