# LinkedIn Post — netlog-ai launch

## Recommended post copy (≈ 1300 chars, headline-driven)

> Just open-sourced **netlog-ai** — an AI-powered network log analyzer that runs entirely on your laptop. 🛠️
>
> Paste any vendor's syslog (Junos, Arista EOS, FRR) and in under a second you get:
> ✅ classified events across 50+ regex patterns
> ✅ deduplicated, severity-ranked action items
> ✅ a weighted health score 0–100 with A/B/C/D/F grade
>
> Point it at a single device config — the LLM (local Docker Model Runner OR Anthropic Claude) writes a config audit with **copy-pastable patches, rollback steps, and verify CLI**.
>
> Load a multi-device site bundle — it infers topology from configs alone, finds cross-device gaps (BGP, OSPF, MTU, missing BFD, LLDP), and lets you ask the LLM grounded questions about the fabric.
>
> What I'm proud of:
> 🔒 **Sanitize-before-LLM** — passwords, public IPs, SSH keys all redacted before any outbound call
> 🚀 **No telemetry, no SaaS** — your configs never leave the host
> 🎯 **Multi-vendor by design** — not Cisco-only with a chatbot retrofit
> ♿ **WCAG-AA accessible** — full keyboard nav, ARIA, prefers-reduced-motion, dark color-scheme
> 🧪 **139 tests passing** across 8 review rounds (focus rings, content-visibility culling, PWA-ready)
>
> 2-minute demo below ⬇️
> Repo: github.com/gesh75/netlog-ai (MIT)
>
> Built solo over a few weeks of nights and weekends. Networking + AI is finally a productive marriage when the AI part actually outputs something you can paste into a CLI.
>
> #networkengineering #networkautomation #devops #opensource #ai #llm #python #flask #junos #arista #bgp #ospf #infrastructure

---

## Shorter variant (≈ 600 chars, hook-driven)

> I built **netlog-ai** — a local AI dashboard that turns network syslog into ranked, copy-pastable fixes.
>
> • Multi-vendor (Junos / EOS / FRR)
> • Local LLM or Claude — your choice
> • Sanitize-before-LLM (configs never leave your laptop in cleartext)
> • Site-wide topology inferred from configs alone
> • 139 tests, MIT, no telemetry
>
> 2 minutes of demo below.
>
> 👉 github.com/gesh75/netlog-ai
>
> #networkautomation #ai #opensource #infrastructure

---

## Posting checklist

1. **Upload the video first** — LinkedIn ranks native video higher than link previews
2. **Use `docs/demo.mp4`** (LinkedIn prefers H.264 MP4 over WebM)
3. **Aspect ratio:** 16:9 (1920×1080) — works on desktop AND mobile (LinkedIn auto-crops for mobile feed)
4. **Cover image:** use `docs/demo-poster.png` as the thumbnail
5. **Pin one comment** with the repo link to maximize click-through
6. **Best times to post (B2B/tech audience):** Tue–Thu 8–10am or 5–6pm in your timezone
7. **Engage in the first hour** — reply to every comment, that locks in the algorithm boost
8. **Don't include external links in the post body** — LinkedIn de-prioritizes posts with links. Put the repo URL in a comment instead.

## Storyboard (what's actually on screen)

| Time | Scene | What viewers see | Caption |
|------|-------|------------------|---------|
| 0:00–0:07 | Intro | Brand header, sidebar with 3 tabs, welcome panel | "netlog-ai — AI-powered network log analyzer" → "Multi-vendor · Local LLM · No telemetry" |
| 0:07–0:25 | LOGS tab | Source switches to Paste Raw Logs, log lines type into textarea, hostname filled, LLM toggled off, Run Analysis → dashboard populates with KPIs, score 94 grade A, action items | "Paste any vendor syslog — classifier ranks the top issues" → "50+ regex patterns · deduped action items · health score 0–100" |
| 0:25–0:50 | DEVICE tab | Switch to DEVICE, pick `junos-fw-01` sample, click Optimize → LLM auditing → findings populate with severity badges, code blocks (Proposed Patch, Rollback, Verify CLI), Copy All Patches button, toast "Optimization complete" | "Audit a device config — LLM produces patches + rollback + verify CLI" → "Findings with severity, evidence, proposed patch, rollback, verify CLI" |
| 0:50–1:25 | SITE tab | Switch to SITE, pick `lab-bravo`, Analyze Whole Site → cross-device findings populate, then Topology → D3 force-directed map with 6 nodes, legend visible | "Or analyze a full site bundle" → "Cross-device gap analysis — BGP, OSPF, MTU, missing BFD…" → "D3 force-directed topology inferred from configs alone" |
| 1:25–1:42 | Copilot | AI Copilot section opens, "Which devices are missing BFD on BGP?" types, Ask Copilot fires → LLM streams a markdown answer listing all affected devices | "Ask the LLM questions about the loaded site" → "Context-grounded answer — LLM never sees raw secrets (pre-sanitized)" |
| 1:42–1:47 | Outro | Scroll to top, clean dashboard, outro caption | "github.com/gesh75/netlog-ai · MIT · 139 tests passing" |

**Total runtime: 1:47 (107 seconds)** — comfortably under the 2-minute target.

## Asset files in this directory

| File | Size | Use |
|------|------|-----|
| `demo.mp4` | 9.0 MB | **LinkedIn upload** (H.264, 1920×1080, faststart, no audio) |
| `demo.webm` | 9.5 MB | GitHub README inline + Mastodon |
| `demo-720p.webm` | 3.8 MB | Lightweight embed (1280×720 VP9) |
| `demo-poster.png` | 348 KB | LinkedIn thumbnail + README hero |

## Optional voice-over

If you want to record your own voiceover for the silent video, the captions ARE the script — read them at the timestamps in the storyboard above and use a tool like Descript or QuickTime + iMovie to layer the audio.

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
