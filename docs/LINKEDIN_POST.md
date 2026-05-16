# LinkedIn Post — netlog-ai launch

## Recommended post copy (final — body has NO outbound link; URL goes in comment #1)

> Most "AI for networking" tools are a chatbot bolted onto a Cisco-only dashboard. I wanted something different, so I built **netlog-ai** and open-sourced it under MIT.
>
> ⚡ It runs entirely on your laptop. Paste syslog from Junos, Arista EOS, or FRR and in under a second you get classified events across 50+ regex patterns, deduplicated severity-ranked action items, and a weighted 0–100 health score with a letter grade.
>
> 🛠️ Point it at a single device config and the LLM (your choice: local Docker Model Runner or Anthropic Claude) returns a real audit — copy-pastable patches, rollback steps, verify CLI. Load a multi-device bundle and it infers topology from configs alone, surfaces cross-device gaps in BGP, OSPF, MTU, BFD, and LLDP, and lets you ask grounded questions about the fabric.
>
> Design choices that mattered to me:
>
> 🔒 **Sanitize before LLM** — passwords, public IPs, SSH keys all redacted before any outbound call.
> 🚀 **No telemetry, no SaaS** — configs never leave the host.
> 🎯 **Multi-vendor from day one** — Junos, Arista, and FRR are all first-class. Not a chatbot retrofit.
> ♿ **WCAG-AA accessible** — axe-core verified across every UI state. Full keyboard nav, ARIA, reduced-motion, dark color-scheme.
> 🧪 **139 tests passing** across 8 review rounds — classifier, sanitizer, topology inference, LLM providers, site analysis.
>
> 📦 Bundled with two synthetic demo sites (11 devices total, mixed Junos + Arista EOS) so every feature runs end-to-end the moment you clone.
>
> Built solo over a few weeks of nights and weekends. AI starts earning its keep in networking when it outputs something you can paste straight into a CLI — not when it explains what your config probably does.
>
> 🎬 2-minute silent demo below.
>
> #NetworkEngineering #NetworkAutomation #OpenSource #LLM #Python #Junos #Arista #BGP #SASE

---

## First comment (paste IMMEDIATELY after publishing the post)

> Repo (clean public release, no internal references):
> 👉 https://github.com/gesh75/netlog-ai
>
> MIT licensed. Star ⭐ if useful — and let me know what's missing for your environment.

---

## Why this version (vs the first draft)

- **Contrarian opener** ("Most AI for networking tools are a chatbot bolted onto a Cisco-only dashboard…") replaces "Just open-sourced…". Gives readers a reason to keep reading.
- **No `Repo:` line in the body** → matches your previous post's 7.3k-impression pattern. The URL lives only in comment #1.
- **WCAG-AA claim is now empirically verified** with `@axe-core/playwright` against every UI state (idle, LOGS populated, DEVICE populated, SITE populated, topology) — **0 critical, 0 serious violations** under wcag2a/wcag2aa/wcag21a/wcag21aa rule sets. Receipts in commit history.
- **5 carefully chosen accent emojis** (⚡🛠️🔒🚀🎯♿🧪📦🎬) — visual rhythm without becoming cartoonish.
- **Closing jab at hallucination** ("…not when it explains what your config probably does") — credible to senior engineers.
- **Hashtags trimmed** to the ones that actually surface tech/infra discovery on LinkedIn.

---

## Posting checklist

1. **Upload `docs/demo.mp4`** as native LinkedIn video (NOT a YouTube/Vimeo link — native ranks higher)
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
| 1:42–1:47 | Outro | Scroll to top, clean dashboard, outro caption | "github.com/gesh75/netlog-ai · MIT · 139 tests passing" |

**Total runtime: 1:47 (107 seconds)** — comfortably under the 2-minute target.

---

## Asset files

| File | Size | Use |
|------|------|-----|
| `demo.mp4` | 9.0 MB | **LinkedIn upload** (H.264, 1920×1080, faststart, no audio) |
| `demo.webm` | 9.5 MB | GitHub README inline + Mastodon |
| `demo-720p.webm` | 3.8 MB | Lightweight embed (1280×720 VP9) |
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
