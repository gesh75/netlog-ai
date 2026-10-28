"""Strip credentials from URLs and from exception text.

``requests`` and ``urllib3`` put the request URL into their exception messages: userinfo
(``https://user:pass@host``) and query strings in full, and for connection errors the path and query
(``Max retries exceeded with url: /services/T0/B0/<secret>``). Anything that leaves the process as an API
response, MCP result, log line or audit row passes its error text through here first.

* ``redact_url(url)``: userinfo and fragment dropped; the values of secret-looking query parameters
  (token, key, secret, password, auth, sig, ...) masked as ``***``; the path is kept.
* ``redact_url(url, keep_path=False)``: for URLs whose path IS the secret (Slack, Discord and Teams
  incoming webhooks): only ``scheme://host[:port]/…`` remains, no path, no query.
* ``redact_text(text, keep_path=...)``: the same, for every URL found in free text, including the
  scheme-less ``url: /path?query`` form urllib3 prints.

A hand-written scanner (no backtracking regexes): the cost is linear in the text, whatever its shape.
"""
from __future__ import annotations

import re

_SECRET_NAME_HINTS = ("token", "secret", "pass", "pwd", "key", "auth", "sig", "cred", "cookie", "session")
_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
_MAX_SCHEME = 32
_AUTHORITY_END = re.compile(r"[/?#]")
_TOKEN_END = re.compile(r"[\s'\"<>]")          # a URL inside text ends at whitespace, a quote or an angle bracket
_TRAILING = ".,;:!?)"                          # sentence punctuation that is not part of the URL
# scheme-less references that urllib3 and requests print: (marker, offset of the leading "/")
_REF_MARKERS = (("url: /", 5), ("URL '/", 5))


def _mask_query(query: str) -> str:
    parts = []
    for piece in query.split("&"):
        name, eq, _value = piece.partition("=")
        low = name.lower()
        parts.append(f"{name}=***" if eq and any(h in low for h in _SECRET_NAME_HINTS) else piece)
    return "&".join(parts)


def _redact_path_query(rest: str, keep_path: bool) -> str:
    """``rest`` starts at the path (or is empty): ``/p/a/t/h?query#fragment``."""
    rest = rest.partition("#")[0]
    path, _q, query = rest.partition("?")
    if keep_path:
        return path + ("?" + _mask_query(query) if query else "")
    return path if path in ("", "/") else "/…"


def redact_url(url: str, *, keep_path: bool = True) -> str:
    """``url`` without userinfo or fragment and with secret query values masked; see the module doc."""
    url = "" if url is None else str(url)
    scheme, sep, rest = url.partition("://")
    if not sep or not scheme:
        return _redact_path_query(url, keep_path) if url.startswith("/") else url
    end = _AUTHORITY_END.search(rest)
    cut = end.start() if end else len(rest)
    authority = rest[:cut].rpartition("@")[2]
    return f"{scheme}://{authority}{_redact_path_query(rest[cut:], keep_path)}"


def _token_end(text: str, start: int) -> int:
    match = _TOKEN_END.search(text, start)
    end = match.start() if match else len(text)
    while end > start and text[end - 1] in _TRAILING:
        end -= 1
    return end


def redact_text(text: object, *, keep_path: bool = True) -> str:
    """``text`` (an exception, usually) with every URL passed through ``redact_url``."""
    s = "" if text is None else str(text)
    out: list[str] = []
    i = 0
    nxt: dict[str, int] = {}                   # next occurrence per marker, recomputed only once passed

    def find(marker: str) -> int:
        pos = nxt.get(marker, -2)
        if pos != -1 and pos < i:
            pos = nxt[marker] = s.find(marker, i)
        return pos

    while True:
        candidates = [(p, "://", 0) for p in [find("://")] if p != -1]
        candidates += [(p + off, m, off) for m, off in _REF_MARKERS for p in [find(m)] if p != -1]
        if not candidates:
            break
        pos, marker, _off = min(candidates)
        if marker == "://":
            start = pos
            while start > i and pos - start < _MAX_SCHEME and s[start - 1] in _SCHEME_CHARS:
                start -= 1
            while start < pos and not s[start].isalpha():       # a scheme starts with a letter
                start += 1
            if start == pos:                                    # no scheme in front: plain text
                out.append(s[i:pos + 3])
                i = pos + 3
                continue
            end = _token_end(s, pos + 3)
            out.append(s[i:start])
            out.append(redact_url(s[start:end], keep_path=keep_path))
        else:
            end = _token_end(s, pos)
            out.append(s[i:pos])
            out.append(_redact_path_query(s[pos:end], keep_path))
        i = max(end, pos + 1)
    out.append(s[i:])
    return "".join(out)
