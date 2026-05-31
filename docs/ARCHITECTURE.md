<p align="center">
  <img src="assets/hero.svg" alt="netlog-ai — architecture" width="100%">
</p>

# 🏛️ netlog-ai — Architecture

**netlog-ai** is a local-first, multi-vendor network log analyzer. It ingests syslog and CLI output from
Junos, Arista EOS, Nokia SR Linux and FRR (via pluggable connectors or local adapters), classifies events with a
~60-pattern regex knowledge base, deduplicates them into a severity-ranked action list, and lets an LLM
(local Ollama / Docker Model Runner, or Anthropic Claude) write a 5-phase root-cause playbook with
copy-pastable per-vendor CLI fixes. Its defining invariant is **sanitize-before-LLM** — every config and log
is scrubbed of secrets and public IPs before any outbound call — and it degrades gracefully to a deterministic
rule-based KB when no model is available. The same analyzer core is exposed three ways: a no-build Flask +
vanilla-JS dashboard (port 6060), a CLI, and an MCP server for agent clients like Claude Code.

---

## Table of Contents

1. [System Context](#1-system-context)
2. [Container & Component Map](#2-container--component-map)
3. [Primary Flow — `POST /api/analyze` (sequence)](#3-primary-flow--post-apianalyze-sequence)
4. [Data Flow — the analysis pipeline](#4-data-flow--the-analysis-pipeline)
5. [LLM Provider Fallback (state machine)](#5-llm-provider-fallback-state-machine)
6. [Core Data Model (ER)](#6-core-data-model-er)
7. [Module Map](#7-module-map)
8. [Tech Stack](#8-tech-stack)

---

## 1. System Context

The analyzer core sits between four classes of external actor: the human operators who drive it (browser,
CLI, or AI agents over MCP), the log platforms it pulls from, the LLM runtimes it can call, and the network
devices that are the ultimate source of logs and configs. Every outbound LLM call is gated by the sanitizer.

```mermaid
flowchart TB
    OP["👩‍💻 NOC Operator<br/>browser · CLI"]
    AGENT["🤖 AI Agents<br/>Claude Code · Cursor"]
    NET([netlog-ai<br/>analyzer core])
    LOGS["📊 Log Platforms<br/>Kibana · Splunk · Loki · LibreNMS · syslog"]
    LLM["🧠 LLM Runtimes<br/>Ollama · Docker Model Runner · Claude"]
    DEV["🌐 Network Devices<br/>Junos · EOS · SR Linux · FRR"]

    OP -->|HTTP / JSON| NET
    AGENT -->|MCP stdio| NET
    LOGS -->|fetch logs| NET
    DEV -.->|syslog / configs| LOGS
    DEV -.->|docker logs · running-config| NET
    NET -->|sanitized prompt| LLM
    LLM -->|5-phase playbook JSON| NET
    NET -->|ranked actions · CLI fixes| OP
    NET -->|tool results| AGENT

    classDef sys     fill:#7c3aed,stroke:#c4b5fd,color:#fff,stroke-width:2px
    classDef person  fill:#0ea5e9,stroke:#7dd3fc,color:#fff
    classDef ext     fill:#475569,stroke:#94a3b8,color:#fff
    classDef ai      fill:#a16207,stroke:#fbbf24,color:#fff

    class NET sys
    class OP,AGENT person
    class LOGS,DEV ext
    class LLM ai
```

---

## 2. Container & Component Map

Three entrypoints (Flask UI, CLI, MCP server) all wrap a single shared analyzer core. The core is layered:
an ingest layer (connectors + adapters), the always-on sanitize gate, the deterministic classifier, the
pipeline orchestrator, and the pluggable intelligence backends (LLM client and rule-based KB).

```mermaid
flowchart TB
    subgraph ENTRY["🚪 Entrypoints"]
        WEB["web/ — Flask + vanilla-JS SPA<br/>:6060 · ~28 /api/* routes"]
        CLI["cli.py — serve · analyze · mcp"]
        MCP["mcp_server/ — FastMCP stdio"]
    end

    subgraph INGEST["📥 Ingest"]
        SRC["sources/ — connectors<br/>kibana · splunk · loki · syslog · librenms"]
        ADP["adapters/ — local<br/>frr · file · network_tool · tfsm"]
    end

    subgraph CORE["⚙️ Analyzer Core"]
        SAN["sanitize.py — redact gate"]
        CLS["classifier.py — ~60 regexes"]
        ANA["analyzer.py — orchestrator"]
        SITE["site intelligence<br/>topology · optimize · copilot"]
    end

    subgraph BRAIN["🧠 Intelligence"]
        LLMC["llm.py — provider chain"]
        KB["kb.py — rule-based fallback"]
    end

    WEB & CLI & MCP --> ANA
    SRC & ADP --> ANA
    ANA --> SAN --> CLS
    ANA --> SITE
    ANA --> LLMC
    LLMC -.fallback.-> KB

    classDef entry fill:#0ea5e9,stroke:#7dd3fc,color:#fff
    classDef in    fill:#0891b2,stroke:#67e8f9,color:#fff
    classDef gate  fill:#e11d48,stroke:#fb7185,color:#fff
    classDef core  fill:#7c3aed,stroke:#c4b5fd,color:#fff
    classDef brain fill:#a16207,stroke:#fbbf24,color:#fff

    class WEB,CLI,MCP entry
    class SRC,ADP in
    class SAN gate
    class CLS,ANA,SITE core
    class LLMC,KB brain
```

---

## 3. Primary Flow — `POST /api/analyze` (sequence)

The end-to-end runtime path: the Flask route builds `LogEvent` records, the analyzer classifies and ranks
them, sanitizes context, and asks the LLM for a structured playbook — falling back to the rule-based KB if the
model is off or fails — then scores health and returns the assembled JSON to the SPA.

```mermaid
sequenceDiagram
    autonumber
    actor OP as Operator (SPA)
    participant API as Flask /api/analyze
    participant AN as analyzer.analyze()
    participant CL as classifier
    participant SA as sanitize
    participant LK as llm · kb

    OP->>API: POST logs / site bundle
    API->>AN: analyze(events, use_llm)
    AN->>CL: strip_ansi + classify (~60 regex)
    CL-->>AN: ClassifiedEvents + counts
    AN->>AN: dedup → ranked ActionItems (sev × count)
    loop top-N action items
        AN->>SA: scrub context (secrets, public IPs)
        SA-->>AN: sanitized incident context
        AN->>LK: query() — ollama → local → claude
        alt LLM available
            LK-->>AN: 5-phase JSON playbook
        else off / failed
            LK-->>AN: kb.lookup() deterministic playbook
        end
    end
    AN->>AN: health_score (0–100 + grade) + exec summary
    AN-->>API: AnalysisResult (JSON)
    API-->>OP: score · actions · CLI · topology
```

---

## 4. Data Flow — the analysis pipeline

Data moves strictly left-to-right and transforms at each stage: raw lines become normalized events, events
become classified findings, findings dedup into ranked actions, and the top items receive deep analysis —
always passing through the sanitize gate before any LLM call.

```mermaid
flowchart LR
    RAW["📝 Raw lines<br/>syslog · CLI · paste"]
    EV["LogEvent<br/>frozen records"]
    CE["ClassifiedEvent<br/>sev · category"]
    AI["ActionItem stack<br/>ranked sev × count"]
    GATE{{"🛡️ sanitize gate"}}
    DEEP["Deep analysis<br/>5-phase playbook"]
    SCORE["Health score<br/>0–100 + A–F"]
    OUT["📤 Outputs<br/>SPA · CLI · MCP · reports"]

    RAW -->|adapters / connectors| EV
    EV -->|strip_ansi + regex KB| CE
    CE -->|dedup · drop recovery| AI
    AI -->|top-N context| GATE
    GATE -->|LLM or rule KB| DEEP
    AI --> SCORE
    DEEP --> OUT
    SCORE --> OUT

    classDef raw   fill:#0891b2,stroke:#67e8f9,color:#fff
    classDef stage fill:#7c3aed,stroke:#c4b5fd,color:#fff
    classDef gate  fill:#e11d48,stroke:#fb7185,color:#fff
    classDef score fill:#059669,stroke:#34d399,color:#fff
    classDef out   fill:#a16207,stroke:#fbbf24,color:#fff

    class RAW,EV raw
    class CE,AI,DEEP stage
    class GATE gate
    class SCORE score
    class OUT out
```

---

## 5. LLM Provider Fallback (state machine)

`llm.query()` walks a provider fallback chain so the dashboard always returns *something*. If every model path
is exhausted or disabled, control returns `None` and the caller drops to the deterministic rule-based KB —
the tool never hard-fails on a missing model.

```mermaid
stateDiagram-v2
    [*] --> Ollama: provider = local
    Ollama --> DMR: no response
    DMR --> Claude: no response / no socket
    Claude --> RuleKB: API error / disabled

    Ollama --> Done: text returned
    DMR --> Done: text returned
    Claude --> Done: text returned
    RuleKB --> Done: deterministic playbook

    Done --> [*]

    note right of Ollama
        :11434 native /api/chat
    end note
    note right of DMR
        Docker Model Runner
        :12434 + unix socket
    end note
    note right of RuleKB
        kb.lookup() — always
        emits actionable output
    end note
```

---

## 6. Core Data Model (ER)

The pipeline is built on a small set of immutable dataclasses. A `LogEvent` is classified into a
`ClassifiedEvent`; classified events deduplicate into `ActionItem`s; each top item carries a `Playbook`; and the
whole run is assembled into one `AnalysisResult`.

```mermaid
erDiagram
    LOG_SOURCE  ||--o{ LOG_EVENT       : emits
    LOG_EVENT   ||--|| CLASSIFIED_EVENT : "classify()"
    CLASSIFIED_EVENT }o--|| ACTION_ITEM : "dedup (sev, desc)"
    ACTION_ITEM ||--o| PLAYBOOK         : "deep_analyze top-N"
    ANALYSIS_RESULT ||--o{ ACTION_ITEM  : ranks

    LOG_EVENT {
        string hostname
        string appname
        string severity_raw
        string message
    }
    CLASSIFIED_EVENT {
        string severity
        string category
        string description
    }
    ACTION_ITEM {
        string severity
        int    count
        set    affected_devices
    }
    PLAYBOOK {
        string root_cause
        string risk
        json   phases_cli
    }
    ANALYSIS_RESULT {
        int    score
        string grade
        bool   llm_powered
    }
```

---

## 7. Module Map

`src/ai_log_analyzer/` is organized by responsibility: ingest packages feed the core, the core orchestrates
classify → sanitize → analyze → score, intelligence backends supply the deep analysis, and a layer of
site-aware features operates over whole-fabric config bundles.

```mermaid
flowchart TB
    subgraph IN["📥 ingest"]
        SOURCES["sources/ — LogSource Protocol<br/>+ SourceManager singleton"]
        ADAPTERS["adapters/ — frr · file<br/>network_tool · tfsm_auto"]
    end

    subgraph PIPE["⚙️ pipeline"]
        SANITIZE["sanitize.py"]
        CLASSIFIER["classifier.py"]
        ANALYZER["analyzer.py"]
    end

    subgraph INTEL["🧠 intelligence"]
        LLM["llm.py"]
        KB["kb.py"]
    end

    subgraph SITE["🗺️ site features"]
        TOPO["topology · topology_infer"]
        OPT["site_optimize · compliance"]
        EXTRA["copilot · diff · reports · runbook"]
    end

    SOURCES & ADAPTERS --> ANALYZER
    ANALYZER --> SANITIZE --> CLASSIFIER
    ANALYZER --> LLM
    LLM -.fallback.-> KB
    ANALYZER --> SITE

    classDef in   fill:#0891b2,stroke:#67e8f9,color:#fff
    classDef pipe fill:#7c3aed,stroke:#c4b5fd,color:#fff
    classDef ai   fill:#a16207,stroke:#fbbf24,color:#fff
    classDef site fill:#059669,stroke:#34d399,color:#fff

    class SOURCES,ADAPTERS in
    class SANITIZE,CLASSIFIER,ANALYZER pipe
    class LLM,KB ai
    class TOPO,OPT,EXTRA site
```

---

## 8. Tech Stack

| Layer | Technologies |
|---|---|
| **Language** | Python 3.10+ (frozen dataclasses, `typing.Protocol`, `re`) |
| **Web / API** | Flask 3 · flask-cors · gunicorn · vanilla JS · Cytoscape.js + ELK |
| **Ingest** | `requests` · raw AF_UNIX socket HTTP · `subprocess` (docker CLI) · optional tfsm-fire / TextFSM |
| **Intelligence** | Ollama · Docker Model Runner (OpenAI-compat) · Anthropic Claude (`claude-haiku-4-5`) · rule-based KB |
| **Security** | `hashlib` (sha256 stable tokens) · `ipaddress` · sanitize-before-LLM gate · X-API-Token · CORS allow-list |
| **Agent surface** | MCP SDK (FastMCP, optional) over stdio / streamable-http |
| **Packaging** | `pyproject.toml` console scripts (`ai-log-analyzer` / `netlog-ai`) · Docker · docker-compose |

---

<p align="center"><sub>Generated architecture documentation · diagrams render natively on GitHub via Mermaid.</sub></p>
