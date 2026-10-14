# LinkedIn Post — netlog-ai v1.1.0 Release

## Recommended post copy (final — body has NO outbound link; URL goes in comment #1)

> Most "AI for networking" tools are a generic LLM wrapper that hallucinates when a CLOS fabric flaps. When an optical link takes bit errors, they blame EVPN overlay routes or draft unstructured advice without rollback protection.
>
> I wanted something built for real production operations, so I built **netlog-ai** v1.1.0 and open-sourced it under MIT.
>
> ⚡ **What it does:** Runs 100% locally on your laptop or bastion. Ingests raw syslog or CLI output across Arista EOS, Juniper Junos, Cisco NX-OS/IOS-XE, Nokia SR Linux, SONiC, and FRR. Classifies events across 80+ regex patterns, compresses syslog storms by 90%+ via Drain clustering, and synthesizes 5-phase root-cause playbooks.
>
> 🌐 **What’s new in v1.1.0:**
>
> 🧠 **5-Layer EVPN-VXLAN Causal Engine** — models physical (L1), LAG/MLAG (L2), underlay IGP/BGP (L3), VTEP NVE (L4), and EVPN overlay (L5) CLOS dependencies. When a spine link or underlay neighbor flaps, it suppresses thousands of downstream Type-2/Type-5 route withdrawals to pinpoint the true root cause.
> 🔬 **Optical DOM vs. QoS Discard Fusion** — separates dirty transceivers (low Rx dBm + rising FCS/CRC errors) from clean dark-fiber cuts (hard Rx LOS, 0 CRC) and control-plane microburst buffer drops (healthy optics, 0 CRC, high queue discards).
> 🗺️ **NetBox v4.x Auto-Discovery** — pulls device roles, sites, and multi-hop patch panel cabling into an instant topology manifest.
> 🛡️ **Vendor-Safe Remediation with Auto-Rollback** — generates transactional change plans guarded by auto-reverting commit timers (`commit confirmed` on Junos, `commit timer` on EOS, `checkpoint` on NX-OS, `revert timer` on IOS-XE) and a destructive command blocklist.
> 🎫 **Two-Way Jira & ServiceNow Enrichment** — deterministic `NETLOG-<SHA256>` incident fingerprinting eliminates duplicate alert storms across CLOS fabrics.
> 🤖 **15 MCP Tools** — stdio / streamable-HTTP server exposing fabric triage, EVPN causality, remediation, and telemetry directly to Claude Code and AI agents.
>
> Design invariants:
> 🔒 **Sanitize before LLM** — stateful token vault masks IPv4/IPv6, MAC, and ASNs before any external model sees it.
> 🚀 **No telemetry, no SaaS** — runs air-gapped on your Mac or Linux host.
> 🧪 **579+ tests passing** — hermetic unit, integration, and MCP test suites.
>
> Built solo over nights and weekends for senior network architects and NetOps engineers who need deterministic verification, not AI hallucination.
>
> 🎬 Demo video and docs in the first comment.
>
> #NetworkEngineering #NetOps #EVPN #BGP #Junos #Arista #Cisco #OpenSource #MCP #Python

---

## First comment (paste IMMEDIATELY after publishing the post)

> Repo & Live Documentation:
> 👉 https://github.com/gesh75/netlog-ai
> 📖 https://gesh75.github.io/netlog-ai/
>
> MIT licensed. Star ⭐ if useful — and let me know what vendor logs or ITSM workflows you'd like to see next!

---

## Why this version (vs previous drafts)

- **Contrarian operator opener** ("Most AI for networking tools are a generic LLM wrapper that hallucinates when a CLOS fabric flaps…") establishes immediate credibility with principal/architect peers.
- **No outbound link in the post body** → keeps LinkedIn algorithmic distribution high. The repo and docs URLs live exclusively in comment #1.
- **Concrete technical depth** — calls out 5-layer EVPN-VXLAN hierarchy, 90%+ syslog storm compression, optical DOM vs QoS discard correlation, NetBox v4.x manifest resolution, and vendor-safe commit rollback timers.
- **15 MCP Tools + 579+ tests passing** — concrete empirical proof of software rigor.
- **Visual rhythm** with professional emojis (⚡🌐🧠🔬🗺️🛡️🎫🤖🔒🚀🧪🎬) without fluff.

---

## Posting checklist

1. **Upload [`demo.mp4`](https://github.com/gesh75/netlog-ai/releases/download/media-2026-06/demo.mp4)** as native LinkedIn video (NOT a YouTube/Vimeo link — native ranks higher)
2. **Paste the post body** from above
3. **Click Post**
4. **Immediately drop the comment text** from the section above — this is the click-target for the URL
5. **Engage in the first hour** — reply to every comment, that locks in the algorithm boost
6. **Best times to post (B2B/tech audience):** Tue–Thu 8–10am or 5–6pm in your timezone

---

## Storyboard (what's actually on screen in `demo.mp4`)

| Time | Scene | What viewers see | Caption |
|------|-------|------------------|---------|
| 0:00–0:07 | Intro | Brand header, sidebar with 3 tabs, welcome panel | "netlog-ai — AI-powered network log analyzer" → "Multi-vendor · Local LLM · No telemetry" |
| 0:07–0:25 | LOGS tab | Source switches to Paste Raw Logs, log lines type into textarea, hostname filled, LLM toggled off, Run Analysis → dashboard populates with KPIs, score 94 grade A, action items | "Paste any vendor syslog — classifier ranks the top issues" → "50+ regex patterns · deduped action items · health score 0–100" |
| 0:25–0:50 | DEVICE tab | Switch to DEVICE, pick `junos-fw-01` sample, click Optimize → LLM auditing → findings populate with severity badges, code blocks (Proposed Patch, Rollback, Verify CLI), Copy All Patches button, toast "Optimization complete" | "Audit a device config — LLM produces patches + rollback + verify CLI" → "Findings with severity, evidence, proposed patch, rollback, verify CLI" |
| 0:50–1:25 | SITE tab | Switch to SITE, pick `lab-bravo`, Analyze Whole Site → cross-device findings populate, then Topology → D3 force-directed map with 6 nodes, legend visible | "Or analyze a full site bundle" → "Cross-device gap analysis — BGP, OSPF, MTU, missing BFD…" → "D3 force-directed topology inferred from configs alone" |
| 1:25–1:42 | Copilot | AI Copilot section opens, "Which devices are missing BFD on BGP?" types, Ask Copilot fires → LLM streams a markdown answer listing all affected devices | "Ask the LLM questions about the loaded site" → "Context-grounded answer — LLM never sees raw secrets (pre-sanitized)" |
| 1:42–1:47 | Outro | Scroll to top, clean dashboard, outro caption | "github.com/gesh75/netlog-ai · MIT · 237 tests passing" |

**Total runtime: 1:47 (107 seconds)** — comfortably under the 2-minute target.

---

## Asset files

| File | Size | Use |
|------|------|-----|
| [`demo.mp4`](https://github.com/gesh75/netlog-ai/releases/download/media-2026-06/demo.mp4) | 9.0 MB | **LinkedIn upload** (H.264, 1920×1080, faststart, no audio) |
| [`demo.webm`](https://github.com/gesh75/netlog-ai/releases/download/media-2026-06/demo.webm) | 9.5 MB | GitHub README inline + Mastodon |
| [`demo-720p.webm`](https://github.com/gesh75/netlog-ai/releases/download/media-2026-06/demo-720p.webm) | 3.8 MB | Lightweight embed (1280×720 VP9) |
| `demo-poster.png` | 348 KB | LinkedIn thumbnail + README hero |

---

## Optional voice-over

If you record a voiceover for the silent video, the captions ARE the script — read them at the timestamps in the storyboard above and use Descript or QuickTime + iMovie to layer the audio.

Sample VO script (≈ 175 words, fits 110s at 95 wpm):

> "This is netlog-ai. A local, AI-powered network log analyzer.
>
> On the LOGS tab, paste any vendor syslog — Junos, Arista, FRR — and in under a second, fifty-plus regex patterns classify every event, dedupe them by severity, and produce a weighted health score from zero to one hundred.
>
> Switch to DEVICE, pick a config sample, and the LLM writes a full audit — patches you can paste into the CLI, rollback steps if it goes wrong, and verification commands. Severity badges, evidence, and monitoring blind spots.
>
> Or analyze a whole multi-device site. The cross-device gap analysis catches BGP, OSPF, MTU, and BFD mismatches. The topology map is force-directed and inferred from the configs alone — no CDP, no SNMP walk.
>
> Ask the copilot any question — context-grounded answers, and the LLM never sees raw secrets. Everything's sanitized first.
>
> One hundred thirty-nine tests, MIT licensed, runs entirely on your laptop. Github dot com slash gesh seventy-five slash netlog dash AI."

---

## A11y verification receipts

Run `node /tmp/netlog-ai-demo/audit-a11y.cjs` against `http://localhost:6060/`. The audit walks 5 UI states and runs axe-core with WCAG 2.0 A + AA + WCAG 2.1 A + AA rule sets. Current result:

```
state-1-idle:               critical=0  serious=0  moderate=0  minor=0
state-2-logs-populated:     critical=0  serious=0  moderate=0  minor=0
state-3-device-populated:   critical=0  serious=0  moderate=0  minor=0
state-4-site-populated:     critical=0  serious=0  moderate=0  minor=0
state-5-topology:           critical=0  serious=0  moderate=0  minor=0

Total AA blockers: 0
✅ PASS
```

The fixes that got us there (commit history): bumped `.kbd-row` + `kbd` colors above 4.5:1, fixed missing `<select>` accessible names (added `aria-label` + `<label for=...>` pairs), restored proper contrast on `.group-label` / `.health-stat.zero` / `.code-copy-btn` / `.code-block-lang` (replaced parent-opacity dimming with explicit AA-compliant child colors).
