"""HTML/PDF report escaping and CSV formula neutralising (kDHa73ce, d3Xtyvgg). Synthetic data only."""

from __future__ import annotations

import csv
import io
import sys
from html.parser import HTMLParser
from typing import Any

import pytest

from ai_log_analyzer import reports

pytestmark = pytest.mark.unit


# ── reports.to_html_site / to_pdf (kDHa73ce) ───────────────────────────────────────────────────────

class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


_ALLOWED_TAGS = {"html", "head", "meta", "title", "style", "body", "h1", "h2", "h3", "h4", "p", "div", "span",
                 "strong", "b", "code", "pre", "ul", "li"}
HOSTILE_SEVERITIES = [
    '"><script>alert(1)</script>',
    '"><link rel=attachment href=file:///etc/hosts>',
    "high\" onmouseover=\"alert(1)",
    "<img src=http://192.0.2.1/x>",
    "x'><iframe src=file:///etc/hosts>",
]


@pytest.mark.parametrize("severity", HOSTILE_SEVERITIES)
@pytest.mark.parametrize("score", [72, "<script>alert(2)</script>", '"><link rel=attachment href=x>', None])
def test_html_report_escapes_severity_and_score(severity: str, score: Any) -> None:
    result = {"site_id": "LAB-X", "site_score": score, "llm_powered": True,
              "cross_device_findings": [{"severity": severity, "category": "c", "title": "t",
                                         "affected_devices": ["fw-01"], "evidence": "e", "rationale": "r"}]}
    page = reports.to_html_site(result)
    parser = _Tags()
    parser.feed(page)
    assert {t for t, _ in parser.tags} <= _ALLOWED_TAGS, [t for t, _ in parser.tags]
    for tag, attrs in parser.tags:
        assert not any(k.startswith("on") for k in attrs), (tag, attrs)
    classes = {c for _, a in parser.tags for c in (a.get("class") or "").split()}
    assert classes <= {"finding", "finding-head", "cat", "meta", "score", "sev-pill", "sev-unknown",
                       "sev-critical", "sev-high", "sev-medium", "sev-low"}, classes


def test_html_report_keeps_known_severities_and_numeric_scores() -> None:
    result = {"site_id": "S", "site_score": 72.0,
              "cross_device_findings": [{"severity": "CRITICAL", "title": "t"},
                                        {"severity": "low", "title": "u"}, {"title": "no severity"}]}
    page = reports.to_html_site(result)
    assert 'class="finding sev-critical"' in page and 'class="sev-pill sev-critical">CRITICAL<' in page
    assert 'class="finding sev-low"' in page and ">72/100<" in page


def test_html_report_escapes_non_string_values_instead_of_crashing() -> None:
    page = reports.to_html_site({"site_id": ["a"], "site_summary": {"x": "<blink>"}, "site_score": [1],
                                 "cross_device_findings": [{"title": ["<i>"], "category": 3, "evidence": 4.5,
                                                            "affected_devices": [1, "<u>"],
                                                            "fix_per_device": {"d": ["<s>", 1]},
                                                            "verify_cli": ["<v>"]}]})
    assert "<i>" not in page and "<u>" not in page and "<s>" not in page and "<v>" not in page
    assert "<blink>" not in page


class _FakeWeasy:
    """Stand-in for the weasyprint module: records how HTML() is built and what its fetcher refuses."""

    calls: list[dict[str, Any]] = []

    class HTML:
        def __init__(self, **kw: Any) -> None:
            _FakeWeasy.calls.append(kw)

        def write_pdf(self) -> bytes:
            return b"%PDF-fake"

    @staticmethod
    def default_url_fetcher(url: str, *a: Any, **kw: Any) -> dict[str, Any]:
        return {"string": b"data", "mime_type": "image/png"}


def test_pdf_renderer_cannot_fetch_local_files_or_network_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = type(sys)("weasyprint")
    fake.HTML = _FakeWeasy.HTML  # type: ignore[attr-defined]
    fake.default_url_fetcher = _FakeWeasy.default_url_fetcher  # type: ignore[attr-defined]
    _FakeWeasy.calls.clear()
    monkeypatch.setitem(sys.modules, "weasyprint", fake)
    assert reports.to_pdf("<html><body>x</body></html>") == b"%PDF-fake"
    fetcher = _FakeWeasy.calls[0].get("url_fetcher")
    assert callable(fetcher), "weasyprint must be given a url_fetcher"
    for url in ("file:///etc/hosts", "http://192.0.2.1/", "https://example.com/x.css", "ftp://192.0.2.1/x",
                "FILE:///proc/self/environ"):
        with pytest.raises(ValueError):
            fetcher(url)
    assert fetcher("data:image/png;base64,AAAA") == {"string": b"data", "mime_type": "image/png"}


def _no_weasyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "weasyprint", None)  # `from weasyprint import HTML` -> ImportError


def test_wkhtmltopdf_runs_without_local_file_access_or_scripts(monkeypatch: pytest.MonkeyPatch,
                                                               tmp_path: Any) -> None:
    _no_weasyprint(monkeypatch)
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any):
        seen["argv"], seen["input"] = argv, kw.get("input")
        with open(argv[-1], "wb") as fh:
            fh.write(b"%PDF-wk")
        return type("P", (), {"returncode": 0})()

    monkeypatch.setattr(reports.shutil, "which",
                        lambda name: "/fake/wkhtmltopdf" if name == "wkhtmltopdf" else None)
    monkeypatch.setattr(reports.subprocess, "run", fake_run)
    assert reports.to_pdf("<html><head></head><body>x</body></html>") == b"%PDF-wk"
    assert "--disable-local-file-access" in seen["argv"] and "--disable-javascript" in seen["argv"]
    assert "Content-Security-Policy" in seen["input"] and "default-src 'none'" in seen["input"]


def test_chrome_page_carries_a_content_security_policy(monkeypatch: pytest.MonkeyPatch,
                                                      tmp_path: Any) -> None:
    _no_weasyprint(monkeypatch)
    fake_chrome = tmp_path / "chromium"
    fake_chrome.write_text("")
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any):
        page = next(a for a in argv if a.startswith("file://"))[len("file://"):]
        with open(page, encoding="utf-8") as fh:
            seen["page"] = fh.read()
        out = next(a for a in argv if a.startswith("--print-to-pdf="))[len("--print-to-pdf="):]
        with open(out, "wb") as fh:
            fh.write(b"%PDF-chrome")
        return type("P", (), {"returncode": 0})()

    monkeypatch.setattr(reports.shutil, "which",
                        lambda name: str(fake_chrome) if name == "chromium" else None)
    monkeypatch.setattr(reports.subprocess, "run", fake_run)
    doc = "<!DOCTYPE html><html><head><title>t</title></head><body>x</body></html>"
    assert reports.to_pdf(doc) == b"%PDF-chrome"
    page = seen["page"]
    assert page.index("Content-Security-Policy") < page.index("<title>"), "policy must come first"
    assert "default-src 'none'" in page and "frame-src" not in page.replace("default-src 'none'", "")


# ── reports.to_csv_findings: spreadsheet formula prefixes (d3Xtyvgg) ───────────────────────────────

FORMULAS = ['=HYPERLINK("http://192.0.2.1/","y")', "@SUM(1)", "+1+1", "-2+3", "\t=1+1", "\r=1+1",
            "=cmd|' /C calc'!A0"]


def _csv_rows(result: dict[str, Any]) -> list[list[str]]:
    return list(csv.reader(io.StringIO(reports.to_csv_findings(result))))


@pytest.mark.parametrize("payload", FORMULAS)
def test_csv_neutralises_formula_prefixes_in_every_text_cell(payload: str) -> None:
    result = {"hostname": payload, "findings": [{"severity": payload, "category": payload, "title": payload,
                                                 "evidence": payload, "rationale": payload}]}
    row = _csv_rows(result)[1]
    assert len(row) == 6
    for cell in row:
        assert cell.startswith("'") and cell[1:] == payload.replace("\n", " "), repr(cell)


def test_csv_neutralises_site_results_and_affected_devices() -> None:
    result = {"cross_device_findings": [{"severity": "high", "category": "c", "title": "=1+1",
                                         "affected_devices": ["=fw", "fw2"], "evidence": "@x\nline",
                                         "rationale": "-r"}]}
    row = _csv_rows(result)[1]
    assert row == ["high", "c", "'=1+1", "'=fw, fw2", "'@x line", "'-r"]


def test_csv_leaves_ordinary_text_and_numbers_alone() -> None:
    result = {"findings": [{"severity": 3, "category": "cat egory", "title": "No SNMPv3 (a=b)",
                            "affected_devices": ["rt-01"], "evidence": "x - y", "rationale": ""}]}
    assert _csv_rows(result)[1] == ["3", "cat egory", "No SNMPv3 (a=b)", "rt-01", "x - y", ""]
