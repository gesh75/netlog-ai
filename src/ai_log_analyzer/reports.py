"""Report generators — turn a site/device analysis result into shareable artifacts.

Supports:
  - Markdown (for git, wiki, Slack)
  - HTML standalone (self-contained, no external CSS/JS — email/attachment ready)
  - CSV (executive spreadsheet)
  - PDF (HTML rendered via wkhtmltopdf / chrome headless / weasyprint — caller picks)

The HTML / Markdown variants are pure-Python with no external deps. PDF
generation requires either `weasyprint` or `wkhtmltopdf` installed.
"""
from __future__ import annotations

import csv
import io
import html
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable


# ─────────────────────────────────────────────────────────────────────────────
# Markdown
# ─────────────────────────────────────────────────────────────────────────────

def to_markdown_site(result: dict) -> str:
    """Markdown report for a site-level analysis."""
    out: list[str] = []
    site = result.get("site_id", "(site)")
    out.append(f"# Site Analysis: {site}")
    out.append("")
    out.append(f"_Generated {datetime.utcnow().isoformat(timespec='seconds')}Z_  ")
    out.append(f"_LLM: {'on' if result.get('llm_powered') else 'rule-based'}_")
    out.append("")
    out.append(f"**Maturity score:** {result.get('site_score', 0)}/100")
    out.append("")
    out.append(f"**Summary:** {result.get('site_summary', '')}")
    out.append("")

    topo = result.get("topology") or {}
    if topo.get("devices_seen"):
        out.append("## Topology")
        out.append("")
        out.append(f"- **Devices analyzed:** {len(topo['devices_seen'])} — "
                   f"{', '.join(topo['devices_seen'])}")
        for role, devs in (topo.get("roles") or {}).items():
            if isinstance(devs, list):
                out.append(f"- **{role}:** {', '.join(devs)}")
        if topo.get("isp_uplinks"):
            out.append(f"- **ISP uplinks:** {', '.join(topo['isp_uplinks'])}")
        out.append("")

    findings = result.get("cross_device_findings") or []
    out.append(f"## Cross-Device Findings ({len(findings)})")
    out.append("")
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "?").upper()
        out.append(f"### {i}. [{sev}] {f.get('title', '(untitled)')}")
        out.append(f"_Category:_ `{f.get('category', '')}`  |  "
                   f"_Affected:_ {', '.join(f.get('affected_devices') or [])}")
        out.append("")
        if f.get("evidence"):
            out.append(f"**Evidence:** {f['evidence']}")
            out.append("")
        if f.get("rationale"):
            out.append(f"**Why it matters:** {f['rationale']}")
            out.append("")
        fpd = f.get("fix_per_device") or {}
        for dev, cmds in fpd.items():
            if isinstance(cmds, list) and cmds:
                out.append(f"**Fix on `{dev}`:**")
                out.append("```")
                out.extend(cmds)
                out.append("```")
                out.append("")
        if f.get("verify_cli"):
            out.append("**Verify:**")
            out.append("```")
            out.extend(f["verify_cli"])
            out.append("```")
            out.append("")

    mons = result.get("monitoring_gaps") or []
    if mons:
        out.append(f"## Monitoring Gaps ({len(mons)})")
        out.append("")
        for m in mons:
            out.append(f"- {m}")
        out.append("")

    return "\n".join(out)


def to_markdown_optimize(result: dict) -> str:
    """Markdown report for a single-device optimize result."""
    out: list[str] = []
    out.append(f"# Device Optimization Report: {result.get('hostname', '(device)')}")
    out.append("")
    out.append(f"_Generated {datetime.utcnow().isoformat(timespec='seconds')}Z_  ")
    out.append(f"_Platform: {result.get('platform', '?')}  |  "
               f"LLM: {'on' if result.get('llm_powered') else 'rule-based'}_")
    out.append("")
    out.append(f"**Maturity score:** {result.get('score', 0)}/100")
    out.append("")
    out.append(f"**Summary:** {result.get('summary', '')}")
    out.append("")
    findings = result.get("findings") or []
    out.append(f"## Findings ({len(findings)})")
    out.append("")
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "?").upper()
        out.append(f"### {i}. [{sev}] {f.get('title', '(untitled)')}")
        out.append(f"_Category:_ `{f.get('category', '')}`")
        out.append("")
        if f.get("evidence"):
            out.append(f"**Evidence:** {f['evidence']}")
            out.append("")
        if f.get("rationale"):
            out.append(f"**Why it matters:** {f['rationale']}")
            out.append("")
        if f.get("patch"):
            out.append("**Patch:**")
            out.append("```")
            out.extend(f["patch"])
            out.append("```")
            out.append("")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────

def to_csv_findings(result: dict) -> str:
    """Flat CSV of every finding (single-device or site-level)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "category", "title", "affected", "evidence", "rationale"])
    findings = result.get("cross_device_findings") or result.get("findings") or []
    for f in findings:
        affected = ", ".join(f.get("affected_devices") or
                             [result.get("hostname", "")])
        w.writerow([
            f.get("severity", ""), f.get("category", ""),
            f.get("title", ""), affected,
            (f.get("evidence") or "").replace("\n", " "),
            (f.get("rationale") or "").replace("\n", " "),
        ])
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# HTML standalone
# ─────────────────────────────────────────────────────────────────────────────

def to_html_site(result: dict, mermaid_diagram: str | None = None) -> str:
    """Self-contained HTML report — single file, no external deps.

    If `mermaid_diagram` is supplied, it's embedded and rendered with mermaid.js
    pulled from a CDN (the only external dep — caller can strip it).
    """
    site = result.get("site_id", "(site)")
    findings = result.get("cross_device_findings") or []
    topo = result.get("topology") or {}
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    findings_html = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "low").lower()
        affected = f.get("affected_devices") or []
        patches_html = ""
        for dev, cmds in (f.get("fix_per_device") or {}).items():
            if isinstance(cmds, list) and cmds:
                patches_html += f'<h4>Fix on <code>{html.escape(dev)}</code></h4><pre>{html.escape(chr(10).join(cmds))}</pre>'
        verify_html = ""
        if f.get("verify_cli"):
            verify_html = f'<h4>Verify</h4><pre>{html.escape(chr(10).join(f["verify_cli"]))}</pre>'
        findings_html.append(f"""
<div class="finding sev-{sev}">
  <div class="finding-head">
    <span class="sev-pill sev-{sev}">{sev.upper()}</span>
    <strong>{html.escape(f.get('title', ''))}</strong>
    <span class="cat">{html.escape(f.get('category', ''))}</span>
  </div>
  <p><b>Affected:</b> {html.escape(', '.join(affected))}</p>
  <p><b>Evidence:</b> {html.escape(f.get('evidence') or '—')}</p>
  <p><b>Why it matters:</b> {html.escape(f.get('rationale') or '—')}</p>
  {patches_html}
  {verify_html}
</div>""")

    mons_html = ""
    if result.get("monitoring_gaps"):
        items = "".join(f"<li>{html.escape(m)}</li>" for m in result["monitoring_gaps"])
        mons_html = f"<h2>Monitoring Gaps</h2><ul>{items}</ul>"

    topo_html = ""
    if topo.get("devices_seen"):
        topo_html = (f"<h2>Topology</h2>"
                     f"<p><b>Devices ({len(topo['devices_seen'])}):</b> "
                     f"{html.escape(', '.join(topo['devices_seen']))}</p>")

    diagram_html = ""
    if mermaid_diagram:
        # Embed mermaid.js from a CDN — only external dep
        diagram_html = f"""
<h2>Topology Diagram</h2>
<div class="mermaid">{html.escape(mermaid_diagram)}</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true,theme:'dark'}});</script>
"""

    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>{html.escape(site)} — AI Network Analysis</title>
<style>
  body {{ font: 14px/1.5 -apple-system, system-ui, sans-serif;
          background:#0d1117; color:#e6edf3; margin:0; padding:20px; max-width:1100px; margin:auto; }}
  h1 {{ border-bottom:2px solid #30363d; padding-bottom:8px; }}
  h2 {{ margin-top:28px; color:#79c0ff; font-size:18px; border-bottom:1px solid #30363d; padding-bottom:4px; }}
  h3, h4 {{ margin-top:14px; color:#c9d1d9; }}
  code, pre {{ font-family: ui-monospace, "SF Mono", monospace; }}
  code {{ background:#161b22; padding:1px 6px; border-radius:3px; color:#79c0ff; }}
  pre {{ background:#161b22; padding:10px; border-radius:4px; overflow:auto; border:1px solid #30363d; white-space:pre-wrap; }}
  .score {{ font-size:48px; font-weight:700; color:#58a6ff; }}
  .meta {{ color:#8b949e; font-size:12px; }}
  .finding {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
              padding:14px; margin:12px 0; border-left:4px solid #666; }}
  .finding.sev-critical {{ border-left-color:#f85149; }}
  .finding.sev-high     {{ border-left-color:#ff7b72; }}
  .finding.sev-medium   {{ border-left-color:#d29922; }}
  .finding.sev-low      {{ border-left-color:#79c0ff; }}
  .sev-pill {{ display:inline-block; padding:2px 8px; border-radius:12px;
               font-size:11px; font-weight:600; text-transform:uppercase; margin-right:8px; }}
  .sev-pill.sev-critical {{ background:rgba(248,81,73,0.2); color:#f85149; }}
  .sev-pill.sev-high     {{ background:rgba(255,123,114,0.2); color:#ff7b72; }}
  .sev-pill.sev-medium   {{ background:rgba(210,153,34,0.2); color:#d29922; }}
  .sev-pill.sev-low      {{ background:rgba(121,192,255,0.2); color:#79c0ff; }}
  .cat {{ float:right; color:#8b949e; font-size:12px; }}
  .finding-head {{ margin-bottom:6px; }}
  ul {{ line-height:1.7; }}
  @media print {{ body {{ background:white; color:black; }} h2 {{ color:#0366d6; }}
                  .finding {{ background:#f6f8fa; }} pre, code {{ background:#f6f8fa; color:#24292e; }} }}
</style></head><body>
<h1>🧠 AI Network Analysis — {html.escape(site)}</h1>
<p class="meta">Generated {timestamp} · LLM: {'on' if result.get('llm_powered') else 'rule-based'} · {len(findings)} findings</p>
<div class="score">{result.get('site_score', result.get('score', 0))}/100</div>
<p><b>Summary:</b> {html.escape(result.get('site_summary', result.get('summary', '')))}</p>
{topo_html}
{diagram_html}
<h2>Findings ({len(findings)})</h2>
{''.join(findings_html) if findings_html else '<p>No findings.</p>'}
{mons_html}
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# PDF (best-effort: try weasyprint, fall back to wkhtmltopdf, fall back to None)
# ─────────────────────────────────────────────────────────────────────────────

def to_pdf(html_text: str) -> bytes | None:
    """Render HTML to PDF if a backend is available. Returns bytes or None.

    Tries (in order):
      1. weasyprint (pure Python — preferred)
      2. wkhtmltopdf binary
      3. Chrome / Chromium headless (--print-to-pdf)
    """
    # Try weasyprint
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html_text).write_pdf()
    except ImportError:
        pass
    except Exception:
        pass

    # Try wkhtmltopdf
    wk = shutil.which("wkhtmltopdf")
    if wk:
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as out:
                outpath = out.name
            proc = subprocess.run(
                [wk, "--quiet", "-", outpath],
                input=html_text, text=True, capture_output=True, timeout=60,
            )
            if proc.returncode == 0:
                data = Path(outpath).read_bytes()
                Path(outpath).unlink(missing_ok=True)
                return data
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Try Chrome / Chromium headless
    chrome = (shutil.which("chromium-browser") or shutil.which("chromium")
              or shutil.which("google-chrome") or shutil.which("chrome")
              or "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if chrome and Path(chrome).exists():
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as inp:
                inp.write(html_text)
                inpath = inp.name
            outpath = inpath.replace(".html", ".pdf")
            proc = subprocess.run(
                [chrome, "--headless", "--disable-gpu", "--no-sandbox",
                 f"--print-to-pdf={outpath}", f"file://{inpath}"],
                capture_output=True, timeout=60,
            )
            if proc.returncode == 0 and Path(outpath).is_file():
                data = Path(outpath).read_bytes()
                Path(inpath).unlink(missing_ok=True)
                Path(outpath).unlink(missing_ok=True)
                return data
        except (subprocess.TimeoutExpired, OSError):
            pass

    return None
