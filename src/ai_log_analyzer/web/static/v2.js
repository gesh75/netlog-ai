// netlog-ai V2 dashboard: API-token auth, status bar (spool / triage / LLM
// egress / vault), multi-vendor badges, root-cause incident cards with
// collapsible suppressed alerts, RAG evidence + citations, remediation
// CLI / Ansible / Nornir export with SafetyGuardrail highlighting, and the
// audit log. Zero-build vanilla JS; every dynamic string goes through
// textContent (via app.js's el()) so nothing from the API is parsed as HTML.
//
// Loaded BEFORE app.js: the fetch wrapper below must be in place
// before app.js makes its first /api call. Helpers from app.js ($, el, clear,
// codeBlock, sevBadge, toast) are only used inside functions that run later.

const NV2 = (() => {
  // ── API token (RBAC) ──────────────────────────────────────────────────────
  const TOKEN_KEY = "netlog-ai:api-token";
  const token = () => {
    try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
  };
  const setToken = (t) => {
    try {
      if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY);
    } catch { /* storage disabled: token lives for this call only */ }
  };
  const isApi = (url) => {
    const u = String(url || "");
    return u.startsWith("/api/") || u.startsWith(`${location.origin}/api/`);
  };

  let authNotified = false;
  const origFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    const tok = token();
    // Every state-changing call carries a custom header: a cross-site "simple" request cannot (the
    // server refuses those when auth is off), and the dashboard's own calls can.
    const method = String(init.method || (typeof input !== "string" && input.method) || "GET").toUpperCase();
    const marked = isApi(url) && !["GET", "HEAD", "OPTIONS"].includes(method);
    if (isApi(url) && (tok || marked)) {
      const headers = new Headers(init.headers || (typeof input !== "string" && input.headers) || {});
      if (tok && !headers.has("Authorization") && !headers.has("X-API-Token")) {
        headers.set("Authorization", `Bearer ${tok}`);
      }
      if (marked && !headers.has("X-Requested-With")) headers.set("X-Requested-With", "netlog-ai");
      init = { ...init, headers };
    }
    const resp = await origFetch(input, init);
    // Background status polls are reflected by the 🔒 chip; only user actions toast.
    const quiet = /\/api\/(status\/overview|llm\/status|health)\b/.test(url);
    if (isApi(url) && !quiet && (resp.status === 401 || resp.status === 403) && !authNotified) {
      authNotified = true;
      setTimeout(() => { authNotified = false; }, 15000);
      if (typeof toast === "function") {
        toast(resp.status === 401
          ? "This server requires an API token. Click the 👤 chip in the header to sign in."
          : "Your role is not allowed to do that (viewer < operator < admin).", "error", 7000);
      }
    }
    return resp;
  };

  // ── small helpers ─────────────────────────────────────────────────────────
  const chipText = (id, text) => {
    const badge = document.getElementById(id);
    if (!badge) return;
    const spans = badge.querySelectorAll("span");
    (spans.length >= 2 ? spans[1] : spans[0] || badge).textContent = text;
  };
  const chipState = (id, state, title) => {
    const badge = document.getElementById(id);
    if (!badge) return;
    ["ok", "warn", "crit", "muted"].forEach((c) => badge.classList.toggle(c, c === state));
    if (title != null) badge.title = title;
  };
  const human = (n) => (n >= 10000 ? `${(n / 1000).toFixed(n >= 100000 ? 0 : 1)}k` : String(n));
  const ago = (s) => {
    if (s == null) return "never";
    if (s < 60) return `${Math.round(s)}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    return `${Math.round(s / 3600)}h ago`;
  };
  const download = (filename, text, mime = "text/plain") => {
    const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const safeName = (s) => String(s || "plan").replace(/[^\w.-]+/g, "_").slice(0, 80);

  // ── vendor / event-type badges ────────────────────────────────────────────
  const VENDOR_LABEL = {
    fortinet: "FortiOS", paloalto: "PAN-OS", cisco_sdwan: "SD-WAN", juniper: "Junos", arista: "EOS",
    cisco_ios: "IOS-XE", cisco_nxos: "NX-OS", frr: "FRR", sonic: "SONiC", cumulus: "Cumulus",
    nokia_srl: "SR Linux",
  };
  const ETYPE_LABEL = {
    sdwan_sla: "SLA", ipsec_tunnel: "IPsec", ike_phase1: "IKE P1", ike_phase2: "IKE P2", bgp_session: "BGP",
    bgp_max_prefix: "MAX-PFX", bfd_session: "BFD", omp_peer: "OMP", control_connection: "CTRL",
    ha_state: "HA", conserve_mode: "CONSERVE", session_table: "SESSIONS", interface_link: "LINK",
    lag_member: "LAG", ospf_adjacency: "OSPF", traffic: "TRAFFIC", threat: "THREAT", auth: "AUTH",
    vpn_auth: "GP AUTH", evpn_route: "EVPN", vxlan_tunnel: "VXLAN",
  };
  // Vendors the remediation generator supports, keyed by parser vendor id.
  const VENDOR_OS = {
    frr: "frr", paloalto: "paloalto_panos", cisco_sdwan: "cisco_sdwan", fortinet: "fortinet_fortios",
    juniper: "juniper_junos", arista: "arista_eos", cisco_ios: "cisco_ios", cisco_nxos: "cisco_nxos",
  };

  function vendorBadge(vendor) {
    if (!vendor) return null;
    return el("span", { className: `vbadge v-${vendor}`, text: VENDOR_LABEL[vendor] || vendor,
      attrs: { title: `vendor: ${vendor}` } });
  }
  function etypeBadge(etype) {
    if (!etype) return null;
    return el("span", { className: "etype", text: ETYPE_LABEL[etype] || etype.toUpperCase(),
      attrs: { title: `event type: ${etype}` } });
  }
  /** Badges for an event row: vendor + event type (from the canonical schema). */
  function eventBadges(ev) {
    const ent = (ev && ev.entities) || {};
    return [vendorBadge(ent.vendor || ev.vendor), etypeBadge(ent.event_type || ev.event_type)].filter(Boolean);
  }
  function stateChip(state) {
    if (!state || state === "active") return null;
    const text = { flapping: "↯ flapping", recovered: "✓ recovered", up: "✓ up" }[state] || state;
    return el("span", { className: `state-chip s-${state}`, text });
  }

  // ── status bar ────────────────────────────────────────────────────────────
  let identity = { name: "", role: "", auth: "dev" };
  let auditEnabled = false;

  async function refreshStatus() {
    let s;
    try {
      const r = await fetch("/api/status/overview");
      if (r.status === 401) { paintLocked(); return; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      s = await r.json();
    } catch (e) {
      ["spool-badge", "triage-badge", "egress-badge", "vault-badge"].forEach((id) => chipState(id, "muted", String(e)));
      return;
    }
    paintSpool(s.spool || {});
    paintTriage(s.triage || {});
    paintEgress(s.llm || {});
    paintVault((s.llm || {}).last_call || {});
    identity = s.identity || identity;
    auditEnabled = !!s.audit;
    paintIdentity();
  }

  function paintSpool(sp) {
    if (!sp.enabled) {
      chipText("spool-badge", "Spool: off");
      chipState("spool-badge", "muted", "No shared state DB (AI_LOG_ANALYZER_STATE_DB): syslog is kept in memory only.");
      return;
    }
    const sources = sp.sources || [];
    const newest = sources.reduce((m, x) => (x.age_s != null && (m == null || x.age_s < m) ? x.age_s : m), null);
    chipText("spool-badge", `Spool ${human(sp.rows || 0)} lines · ${ago(newest)}`);
    const listeners = (sp.listeners || []).map((l) =>
      `${l.id} [${l.role || "?"}/${l.proto || "?"}:${l.port || "?"}] received ${l.received || 0}, ` +
      `rejected ${(l.rejected_sender || 0) + (l.rejected_conn_limit || 0)}, oversize ${l.dropped_oversize || 0}, ` +
      `udp drops ${l.udp_drops || 0}, lost ${l.spool_lines_lost || 0}`);
    const lossy = (sp.listeners || []).some((l) => (l.udp_drops || 0) > 0 || (l.spool_lines_lost || 0) > 0);
    const title = ["SQLite WAL syslog spool",
      ...sources.map((x) => `${x.source}: ${x.rows} rows, newest ${ago(x.age_s)}`),
      ...listeners, sp.error ? `error: ${sp.error}` : ""].filter(Boolean).join("\n");
    chipState("spool-badge", sp.error ? "crit" : newest != null && newest < 300 && !lossy ? "ok" : "warn", title);
  }

  function paintTriage(t) {
    if (!t.configured) {
      chipText("triage-badge", "Triage: n/a");
      chipState("triage-badge", "muted", "Streaming triage needs AI_LOG_ANALYZER_STATE_DB.");
      return;
    }
    const tickets = t.tickets != null ? ` · ${t.tickets} tickets` : "";
    if (!t.running) {
      chipText("triage-badge", `Triage: off${tickets}`);
      chipState("triage-badge", "muted", "Streaming triage worker is not running in this process (admin: POST /api/triage/stream/start).");
      return;
    }
    chipText("triage-badge", `Triage ${t.role}${tickets}`);
    const tot = t.totals || {};
    const gap = Object.values(t.spool_gap_rows || {}).reduce((a, n) => a + n, 0);
    const pending = t.pending_deliveries || 0;
    const openSinks = Object.entries(t.sink_state || {}).filter(([, st]) => st.open).map(([name]) => name);
    const problems = [gap ? `${gap} spool rows lost before triage read them` : "",
      pending ? `${pending} ticket deliveries pending` : "",
      openSinks.length ? `sink circuit open: ${openSinks.join(", ")}` : ""].filter(Boolean);
    chipState("triage-badge", t.role === "active" && !problems.length ? "ok" : "warn",
      [...problems, `role ${t.role} · sinks ${(t.sinks || []).join(", ")}`, `window ${t.window_events || 0} events`,
        `opened ${tot.opened || 0} · updated ${tot.updated || 0} · held ${tot.held || 0} · deferred ${tot.deferred || 0}`,
        `last tick ${t.last_tick_at ? new Date(t.last_tick_at * 1000).toLocaleTimeString() : "—"}`].join("\n"));
  }

  function paintEgress(l) {
    const order = (l.order || []).join(" → ");
    if (!l.enabled) {
      chipText("egress-badge", "LLM off · no egress");
      chipState("egress-badge", "muted", `Provider ${l.provider}; the LLM is disabled, nothing leaves the host.`);
      return;
    }
    if (l.mode === "local-only") {
      chipText("egress-badge", "🔒 Local only · no cloud fallback");
      chipState("egress-badge", "ok", `Provider ${l.provider}. Order: ${order}. ALLOW_CLOUD_FALLBACK is off.`);
    } else if (l.mode === "remote-host") {
      chipText("egress-badge", "⚠ Remote LLM host");
      chipState("egress-badge", "warn", `Provider ${l.provider} points at an off-host address (${(l.remote_hosts || []).join(", ")}); prompts leave this host. Order: ${order}.`);
    } else if (l.mode === "cloud-fallback") {
      chipText("egress-badge", "☁ Cloud fallback enabled");
      chipState("egress-badge", "warn", `Provider ${l.provider}; a cloud API is used when it fails. Order: ${order}.`);
    } else {
      chipText("egress-badge", `☁ Cloud: ${l.provider}`);
      chipState("egress-badge", "warn", `Prompts go to a cloud provider (sanitized + tokenized). Order: ${order}.`);
    }
  }

  function paintVault(c) {
    if (!c || !c.provider) {
      chipText("vault-badge", "Vault: idle");
      chipState("vault-badge", "muted", "No LLM call yet in this worker.");
      return;
    }
    chipText("vault-badge", `Vault: ${c.entities_tokenized || 0} tokenized · ${c.redactions || 0} redacted`);
    chipState("vault-badge", c.ok ? "ok" : "warn",
      [`last call → ${c.provider} (${c.ok ? "ok" : "failed"})`, `${c.prompt_chars || 0} prompt chars`,
        `${c.entities_tokenized || 0} entities tokenized (<IP_n>, <HOST_n>…), ${c.redactions || 0} secrets redacted`,
        `hostnames tokenized: ${c.hostnames_tokenized ? "yes" : "no"}${c.truncated ? " · prompt truncated to budget" : ""}`].join("\n"));
  }

  function paintLocked() {
    identity = { name: "", role: "", auth: "rbac" };
    chipText("role-badge", "🔒 Sign in");
    document.getElementById("role-badge")?.classList.add("locked");
    ["spool-badge", "triage-badge", "egress-badge", "vault-badge"].forEach((id) => {
      chipText(id, `${id.split("-")[0][0].toUpperCase()}${id.split("-")[0].slice(1)}: 🔒`);
      chipState(id, "muted", "Sign in with an API token to see live status.");
    });
    paintIdentity();
  }

  function paintIdentity() {
    const badge = document.getElementById("role-badge");
    const who = document.getElementById("auth-who");
    const auditBtn = document.getElementById("auth-audit");
    const canAudit = identity.role === "admin" || (identity.auth === "dev" && auditEnabled);
    if (badge) {
      badge.classList.toggle("locked", identity.auth === "rbac" && !identity.role);
      if (identity.auth === "dev") chipText("role-badge", "👤 dev mode");
      else if (identity.role) chipText("role-badge", `👤 ${identity.name} · ${identity.role}`);
      badge.title = identity.auth === "dev"
        ? "No API tokens configured: every route is open (bind to 127.0.0.1)."
        : "viewer < operator < admin. Click to change token.";
    }
    if (who) {
      who.textContent = identity.auth === "dev" ? "Dev mode (auth off)"
        : identity.role ? `Signed in as ${identity.name} (${identity.role})` : "Not signed in";
    }
    if (auditBtn) auditBtn.hidden = !canAudit;
    if (!canAudit) {
      const p = document.getElementById("audit-panel");
      if (p) p.style.display = "none";
    }
  }

  function wireAuth() {
    const badge = document.getElementById("role-badge");
    const pop = document.getElementById("auth-popover");
    const input = document.getElementById("auth-token-input");
    if (!badge || !pop) return;
    const toggle = (open) => {
      pop.hidden = !open;
      badge.setAttribute("aria-expanded", String(open));
      if (open && input) input.focus();
    };
    badge.addEventListener("click", () => toggle(pop.hidden));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !pop.hidden) toggle(false); });
    document.getElementById("auth-save")?.addEventListener("click", async () => {
      setToken((input.value || "").trim());
      input.value = "";
      toggle(false);
      await refreshStatus();
      if (typeof refreshLLMStatus === "function") refreshLLMStatus();
      toast(identity.role ? `Signed in as ${identity.name} (${identity.role}).` : "Token not accepted.",
        identity.role ? "success" : "error");
    });
    document.getElementById("auth-clear")?.addEventListener("click", async () => {
      setToken("");
      toggle(false);
      await refreshStatus();
    });
    document.getElementById("auth-audit")?.addEventListener("click", () => { toggle(false); showAudit(); });
  }

  // ── SafetyGuardrail highlighting ──────────────────────────────────────────
  const BLOCKED_RE = /^\s*#\s*BLOCKED\b/;
  const isBlocked = (line) => BLOCKED_RE.test(String(line || ""));
  const countBlocked = (text) => String(text || "").split("\n").filter(isBlocked).length;
  /** Rendered in place of a comment span by app.js's highlightCli. */
  function blockedLine(line) {
    const span = el("span", { className: "cli-blocked" });
    span.appendChild(el("span", { className: "guard-badge", text: "⛔ GUARDRAIL", style: { marginLeft: "0", marginRight: "6px" } }));
    span.appendChild(document.createTextNode(line));
    return span;
  }
  function guardBanner(blocked) {
    if (!blocked || !blocked.length) return null;
    const rules = [...new Set(blocked.map((b) => b.rule).filter(Boolean))].join(", ");
    const box = el("div", { className: "guard-banner" },
      el("span", { className: "guard-badge", text: `⛔ ${blocked.length} withheld`, style: { marginLeft: "0" } }),
      ` SafetyGuardrail withheld ${blocked.length} model-generated command(s)${rules ? ` (${rules})` : ""}. ` +
      "They are shown as # BLOCKED lines and cannot be run from here.");
    const ul = el("ul", { style: { margin: "4px 0 0 16px" } });
    blocked.slice(0, 8).forEach((b) => ul.appendChild(el("li", { className: "row-msg", text: `${b.rule || "rule"}: ${b.command || ""}` })));
    box.appendChild(ul);
    return box;
  }

  // ── RAG evidence + citations ──────────────────────────────────────────────
  const KIND_LABEL = { config: "CONFIG", drift: "DRIFT", topology: "NETBOX", runbook: "RUNBOOK", incident: "INCIDENT" };

  function renderEvidence(evidence, citations, scope) {
    const wrap = el("div", { className: "evidence" });
    if (!evidence || !evidence.length) return wrap;
    const cited = new Set((citations && citations.cited) || []);
    const invalid = (citations && citations.invalid) || [];
    if (invalid.length) {
      wrap.appendChild(el("div", { className: "guard-banner" },
        el("span", { className: "guard-badge", text: "⚠ unverified", style: { marginLeft: "0" } }),
        ` The model cited ${invalid.join(", ")}, which ${invalid.length > 1 ? "are" : "is"} not in the evidence. Treat those claims as unverified.`));
    }
    const ul = el("ul", { className: "evidence-list" });
    evidence.forEach((e) => {
      const det = el("details", { attrs: { id: `${scope}-${e.id}` } });
      const sum = el("summary", {},
        el("span", { className: "ev-id", text: `[${e.id}]` }),
        el("span", { className: `ev-kind ev-${e.kind}`, text: KIND_LABEL[e.kind] || e.kind, style: { marginLeft: "0", marginRight: "6px" } }),
        e.citation || e.ref || "",
        cited.has(e.id) ? el("span", { className: "ev-cited", text: "  ✓ cited" }) : null,
      );
      det.appendChild(sum);
      const meta = [];
      if (e.host) meta.push(`device ${e.host}`);
      if (e.lines && e.lines[0]) meta.push(`running-config lines ${e.lines[0]}–${e.lines[1]}`);
      if (e.golden_lines && e.golden_lines[0]) meta.push(`golden lines ${e.golden_lines[0]}–${e.golden_lines[1]}`);
      if (e.score != null) meta.push(`score ${e.score}`);
      if (meta.length) det.appendChild(el("div", { className: "row-msg", text: meta.join(" · ") }));
      if (e.kind === "incident" && e.resolution) {
        det.appendChild(el("div", { className: "row-msg" }, el("strong", { text: "Resolution: " }), e.resolution));
      }
      const pre = el("pre");
      String(e.snippet || "").split("\n").forEach((line, i) => {
        if (i) pre.appendChild(document.createTextNode("\n"));
        const cls = e.kind === "drift" && /^\+ /.test(line) ? "drift-add" : e.kind === "drift" && /^- /.test(line) ? "drift-del" : "";
        pre.appendChild(cls ? el("span", { className: cls, text: line }) : document.createTextNode(line));
      });
      det.appendChild(pre);
      ul.appendChild(el("li", {}, det));
    });
    wrap.appendChild(ul);
    return wrap;
  }

  /** Text with [S#] turned into buttons that open the matching evidence item. */
  function citedText(text, evidence, scope, tag = "div") {
    const node = el(tag);
    const known = new Set((evidence || []).map((e) => e.id));
    const parts = String(text || "—").split(/(\[S\d{1,2}\])/);
    parts.forEach((p) => {
      const m = /^\[(S\d{1,2})\]$/.exec(p);
      if (!m) { node.appendChild(document.createTextNode(p)); return; }
      const id = m[1];
      if (!known.has(id)) {
        node.appendChild(el("span", { className: "cite-link invalid", text: p, attrs: { title: "Not in the evidence: unverified" } }));
        return;
      }
      node.appendChild(el("button", {
        className: "cite-link", text: p, attrs: { type: "button", title: "Show evidence" },
        on: { click: (ev) => {
          ev.stopPropagation();
          const target = document.getElementById(`${scope}-${id}`);
          if (target) { target.open = true; target.scrollIntoView({ behavior: "smooth", block: "nearest" }); }
        } },
      }));
    });
    return node;
  }

  let evidenceScopeSeq = 0;
  const newScope = (prefix) => `${prefix}-${++evidenceScopeSeq}`;

  /** Playbook header block for app.js's togglePhasedPlan. */
  function playbookEvidence(d) {
    const scope = newScope("ev");
    const out = [];
    const banner = guardBanner(d.guardrail_blocked);
    if (banner) out.push(banner);
    out.push(citedText(d.root_cause, d.evidence, scope));
    if (d.evidence && d.evidence.length) {
      out.push(el("h3", { text: `Evidence (${d.evidence.length})` }));
      out.push(renderEvidence(d.evidence, d.citations, scope));
    }
    return out;
  }

  /** Copilot answer with clickable [S#], evidence list and line-reference checks. */
  function renderCopilot(r) {
    const scope = newScope("cp");
    const answer = document.getElementById("copilot-answer");
    const box = document.getElementById("copilot-evidence");
    if (answer) {
      clear(answer);
      answer.appendChild(citedText(r.answer || "(no answer)", r.evidence, scope, "span"));
    }
    if (!box) return;
    clear(box);
    const refs = (r.citations && r.citations.line_refs) || {};
    if ((refs.valid || []).length || (refs.invalid || []).length) {
      const row = el("div", { className: "ent-row" });
      (refs.valid || []).forEach((x) => row.appendChild(el("span", { className: "ent-chip lineref", text: `✓ ${x}` })));
      (refs.invalid || []).forEach((x) => row.appendChild(el("span", {
        className: "ent-chip lineref outcome-bad", text: `⚠ ${x}`, attrs: { title: "Line number outside the config that was sent" } })));
      box.appendChild(row);
    }
    if ((r.evidence || []).length) {
      box.appendChild(el("h3", { text: `Evidence (${r.evidence.length})`, style: { fontSize: "13px" } }));
      box.appendChild(renderEvidence(r.evidence, r.citations, scope));
    }
  }

  // ── root-cause incidents (suppression + correlation) ─────────────────────
  const CORR_KEY_LABEL = {
    shared_ip: "Peer IP", p2p_subnet: "P2P", same_tunnel: "Tunnel", same_interface: "Intf",
    shared_asn: "ASN", same_vrf: "VRF", same_device_temporal: null,
  };

  function entityChip(k, v) {
    return el("span", { className: "ent-chip" }, el("span", { className: "ent-k", text: k }), v);
  }

  /** Shared entities for a set of hosts: correlation evidence + event fields. */
  function entitiesFor(hosts, r) {
    const hs = new Set(hosts.map((h) => String(h).toLowerCase()));
    const seen = new Set();
    const chips = [];
    const add = (k, v) => {
      const key = `${k}|${String(v || "").toLowerCase()}`;
      if (!v || seen.has(key) || chips.length >= 14) return;
      seen.add(key);
      chips.push(entityChip(k, String(v)));
    };
    ((r.entity_correlation || {}).incidents || []).forEach((inc) => {
      if (!(inc.devices || []).some((d) => hs.has(String(d).toLowerCase()))) return;
      (inc.evidence || []).forEach((e) => {
        const label = CORR_KEY_LABEL[e.type];
        if (label) add(label, String(e.key).replace(/^[^:]+:/, ""));
      });
    });
    (r.classified_events || []).forEach((e) => {
      if (!hs.has(String(e.hostname || "").toLowerCase())) return;
      const ent = e.entities || {};
      add("Peer IP", ent.peer_ip);
      add("ASN", ent.asn);
      add("Tunnel", ent.tunnel_id);
      if (ent.vrf && ent.vrf !== "default" && ent.vrf !== "0") add("VRF", ent.vrf);
    });
    return chips;
  }

  function childTable(rows) {
    const tbody = el("tbody");
    rows.forEach((c) => tbody.appendChild(el("tr", {},
      el("td", {}, sevBadge(c.severity || "info")),
      el("td", {}, document.createTextNode(c.hostname || ""), vendorBadge(c.vendor)),
      el("td", {}, etypeBadge(c.event_type) || ""),
      el("td", { text: c.description || "" }),
      el("td", {}, el("code", { text: c.entity || "" })),
      el("td", {}, el("span", { className: "row-msg", text: c.timestamp || "" })),
    )));
    return el("table", {},
      el("thead", {}, el("tr", {}, ...["Sev", "Device", "Type", "Alert", "Entity", "Time"].map((h) => el("th", { text: h })))),
      tbody);
  }

  function remediateButton(host, vendor, entity) {
    const vos = VENDOR_OS[vendor || ""];
    if (!vos || !entity || /^\d+\.\d+\.\d+\.\d+/.test(entity)) return null;
    return el("button", {
      className: "tiny secondary", text: "🛡 Guarded plan for this link",
      attrs: { type: "button", title: `Prefill the remediation panel: ${host} ${entity}` },
      on: { click: () => prefillRemediation({ device: host, vendor: vos, iface: entity }) },
    });
  }

  function renderIncidents(r) {
    const panel = document.getElementById("incidents-panel");
    const list = document.getElementById("incidents-list");
    if (!panel || !list) return;
    clear(list);
    const groups = (r.suppression || {}).groups || [];
    const corr = (r.entity_correlation || {}).incidents || [];
    const covered = new Set();
    groups.forEach((g) => {
      const root = g.root || {};
      const hosts = [...(g.root_hosts || []), ...(g.child_devices || [])];
      hosts.forEach((h) => covered.add(String(h).toLowerCase()));
      const card = el("div", { className: "incident-card", attrs: { id: `inc-${g.id}` } });
      card.appendChild(el("div", { className: "incident-head" },
        el("span", { className: `kind-badge k-${g.kind}`, text: String(g.kind || "").replace("_", " ").toUpperCase(), style: { marginLeft: "0" } }),
        sevBadge(root.severity || "high"),
        vendorBadge(root.vendor), etypeBadge(root.event_type),
        el("strong", { text: root.description || g.label || "" }),
        el("span", { className: "row-msg", text: `on ${(g.root_hosts || []).join(", ")}` }),
        g.inferred ? el("span", { className: "state-chip", text: "inferred", attrs: { title: "The failed device logged nothing; inferred from what its peers lost." } }) : null,
        el("span", { className: "row-msg", text: g.id, style: { marginLeft: "auto" } }),
      ));
      card.appendChild(el("div", { className: "incident-summary", text: g.summary || "" }));
      const chips = entitiesFor(hosts, r);
      if (chips.length) card.appendChild(el("div", { className: "ent-row" }, ...chips));
      const btn = remediateButton((g.root_hosts || [])[0], root.vendor, root.entity);
      if (btn) card.appendChild(el("div", { className: "incident-actions" }, btn));
      const children = g.children || [];
      if (children.length) {
        const det = el("details");
        det.appendChild(el("summary", {
          text: `${g.suppressed_count || children.length} suppressed downstream alert(s)` +
            ((g.child_devices || []).length ? ` across ${(g.child_devices || []).length} other device(s)` : ""),
        }));
        det.appendChild(childTable(children));
        card.appendChild(det);
      }
      list.appendChild(card);
    });
    // Cross-vendor clusters that no suppression root already explains.
    corr.forEach((inc, i) => {
      const devs = (inc.devices || []).map((d) => String(d).toLowerCase());
      if (devs.length && devs.every((d) => covered.has(d))) return;
      const root = inc.root_cause || {};
      const card = el("div", { className: "incident-card", attrs: { id: `corr-${i}` } });
      card.appendChild(el("div", { className: "incident-head" },
        el("span", { className: "kind-badge k-correlated", text: "CORRELATED", style: { marginLeft: "0" } }),
        sevBadge(root.severity || "medium"), vendorBadge(root.vendor), etypeBadge(root.event_type),
        el("strong", { text: root.description || "" }),
        el("span", { className: "row-msg", text: `on ${root.hostname || ""}` }),
        el("span", { className: "row-msg", text: `confidence ${inc.confidence || "?"}`, style: { marginLeft: "auto" } }),
      ));
      card.appendChild(el("div", { className: "incident-summary", text: inc.summary || "" }));
      const chips = entitiesFor(inc.devices || [], r);
      if (chips.length) card.appendChild(el("div", { className: "ent-row" }, ...chips));
      const symptoms = inc.symptoms || [];
      if (symptoms.length) {
        const det = el("details");
        det.appendChild(el("summary", { text: `${symptoms.length} correlated downstream event(s)` }));
        det.appendChild(childTable(symptoms));
        card.appendChild(det);
      }
      list.appendChild(card);
    });
    const n = list.children.length;
    panel.style.display = n ? "block" : "none";
    const count = document.getElementById("incidents-count");
    if (count) {
      const supp = (r.suppression || {}).suppressed_events || 0;
      count.textContent = `(${n} incident${n === 1 ? "" : "s"}${supp ? ` · ${supp} suppressed alerts` : ""})`;
    }
  }

  function focusIncident(rootId) {
    const card = document.getElementById(`inc-${rootId}`);
    if (!card) return;
    const det = card.querySelector("details");
    if (det) det.open = true;
    card.scrollIntoView({ behavior: "smooth", block: "center" });
    card.classList.add("flash");
    setTimeout(() => card.classList.remove("flash"), 1600);
  }

  /** Action-item row extras: state chip + "suppressed by ROOT-…" link. */
  function actionRowExtras(item) {
    const out = [];
    const sc = stateChip(item.state);
    if (sc) out.push(sc);
    if (item.suppressed_by) {
      out.push(el("span", {
        className: "supp-chip", text: `↳ suppressed by ${item.suppressed_by}`,
        attrs: { title: "Dependent alert: open its root-cause incident", role: "link", tabindex: "0" },
        on: { click: (ev) => { ev.stopPropagation(); focusIncident(item.suppressed_by); } },
      }));
    }
    return out;
  }

  function applySuppressedFilter() {
    const box = document.getElementById("hide-suppressed");
    const hide = box ? box.checked : false;
    document.querySelectorAll("#actions-table tbody tr.suppressed-row").forEach((tr) => {
      tr.style.display = hide ? "none" : "";
      const next = tr.nextElementSibling;
      if (hide && next && next.dataset.deep) next.remove();
    });
  }

  function syncSuppressedToggle(items) {
    const n = items.filter((a) => a.suppressed_by).length;
    const wrap = document.getElementById("hide-suppressed-wrap");
    const count = document.getElementById("suppressed-count");
    if (wrap) wrap.hidden = n === 0;
    if (count) count.textContent = String(n);
    applySuppressedFilter();
  }

  // ── remediation: vendor CLI / Ansible / Nornir ────────────────────────────
  function planCli(plan) {
    const sec = (title, cmds) => (cmds && cmds.length ? [`! ── ${title}`, ...cmds, ""] : []);
    return [
      `! ${plan.plan_id} — ${plan.device} (${plan.vendor}) — ${plan.action_type}`,
      `! Rollback timer: ${plan.rollback_minutes} min. ${plan.rationale || ""}`,
      "",
      ...sec("Pre-checks (read-only)", plan.pre_checks),
      ...sec("Apply with rollback timer", [...(plan.config_commands || []), ...(plan.commit_with_timer_commands || [])]),
      ...sec("Post-checks", plan.post_checks),
      ...sec("Confirm (cancels the automatic rollback)", plan.confirm_commit_commands),
      ...sec("Manual rollback", plan.manual_rollback_commands),
    ].join("\n").trim();
  }

  async function requestRemediation(body) {
    const res = await fetch("/api/remediation", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch { data = { ok: false, error: `HTTP ${res.status}` }; }
    return { status: res.status, data };
  }

  function renderRemediationCard(plan, views, req) {
    const box = document.getElementById("remediation-v2");
    if (!box) return;
    clear(box);
    const card = el("div", { className: "rem-card" });
    const blockedBadge = el("span", { className: "guard-badge", style: { display: "none" } });
    const dryBadge = el("span", { className: "dryrun-badge", text: "DRY-RUN FIRST", style: { display: "none" },
      attrs: { title: "The playbook runs a check-mode diff task before the guarded apply." } });
    card.appendChild(el("div", { className: "rem-head" },
      el("strong", { text: plan.plan_id }),
      el("span", { text: `${plan.device} · ${plan.vendor} · ${plan.action_type}` }),
      el("span", { className: "state-chip", text: `⏱ rollback ${plan.rollback_minutes}m` }),
      dryBadge, blockedBadge));
    const tabs = el("div", { className: "rem-tabs", attrs: { role: "tablist" } });
    const body = el("div", { className: "rem-body", attrs: { role: "tabpanel" } });
    card.appendChild(tabs);
    card.appendChild(body);
    box.appendChild(card);

    const KINDS = [
      { id: "cli", label: "Vendor CLI", ext: "txt" },
      { id: "ansible", label: "Ansible playbook (YAML)", ext: "yml" },
      { id: "nornir", label: "Nornir script", ext: "py" },
    ];
    const buttons = {};
    const show = async (kind) => {
      Object.entries(buttons).forEach(([k, b]) => b.setAttribute("aria-selected", String(k === kind.id)));
      clear(body);
      if (views[kind.id] === undefined) {
        body.appendChild(el("div", { className: "rem-note", text: `Generating ${kind.label}…` }));
        const { data } = await requestRemediation({ ...req, export: kind.id });
        views[kind.id] = data.export ? data.export.content : { error: data.error || "export failed" };
        clear(body);
      }
      const v = views[kind.id];
      if (v && typeof v === "object" && v.error) {
        const blocked = /guardrail|blocked|safety/i.test(v.error);
        body.appendChild(el("div", { className: blocked ? "guard-banner" : "rem-note" },
          blocked ? el("span", { className: "guard-badge", text: "⛔ GUARDRAIL", style: { marginLeft: "0" } }) : null,
          ` ${kind.label} not available: ${v.error}`));
        return;
      }
      const text = String(v || "");
      const nBlocked = countBlocked(text);
      blockedBadge.style.display = nBlocked ? "" : "none";
      blockedBadge.textContent = `⛔ ${nBlocked} blocked by SafetyGuardrail`;
      dryBadge.style.display = kind.id === "ansible" && /check_mode:\s*true/.test(text) ? "" : "none";
      if (kind.id === "ansible") {
        body.appendChild(el("div", { className: "rem-note",
          text: "Run with --check --diff first (tag dry_run). The rescue block rolls back only if the apply changed the device." }));
      } else if (kind.id === "nornir") {
        body.appendChild(el("div", { className: "rem-note", text: "napalm_configure(dry_run=True) by default; pass --apply to commit." }));
      }
      body.appendChild(codeBlock(text, { lang: kind.id === "cli" ? plan.vendor : kind.id }));
      const fname = `${safeName(plan.plan_id)}-${kind.id}.${kind.ext}`;
      body.appendChild(el("div", { className: "rem-tools" },
        el("button", { className: "tiny secondary", text: `⬇ Download ${fname}`, attrs: { type: "button" },
          on: { click: () => download(fname, text, kind.id === "ansible" ? "application/yaml" : "text/plain") } })));
    };
    KINDS.forEach((k) => {
      const b = el("button", { className: "tiny secondary", text: k.label,
        attrs: { type: "button", role: "tab", "aria-selected": "false" }, on: { click: () => show(k) } });
      buttons[k.id] = b;
      tabs.appendChild(b);
    });
    show(KINDS[0]);
  }

  async function generateRemediation() {
    const dev = document.getElementById("remediation-device-select")?.value;
    const vendor = document.getElementById("remediation-vendor-select")?.value || "arista_eos";
    const action = document.getElementById("remediation-action-select")?.value || "drain";
    const iface = (document.getElementById("remediation-interface-input")?.value || "").trim();
    const box = document.getElementById("remediation-v2");
    const legacy = document.getElementById("remediation-card-out");
    if (legacy) legacy.style.display = "none";
    if (!dev || !box) { toast("Pick a target device first.", "error"); return; }
    clear(box);
    box.appendChild(el("div", { className: "rem-note", text: "Generating vendor-safe remediation plan with rollback timer…" }));
    const req = { device: dev, vendor, action, interface: iface || undefined };
    try {
      const { data } = await requestRemediation({ ...req, export: "ansible" });
      if (!data.plan) {
        clear(box);
        const blocked = /guardrail|blocked|safety|forbidden/i.test(data.error || "");
        box.appendChild(el("div", { className: blocked ? "guard-banner" : "rem-note" },
          blocked ? el("span", { className: "guard-badge", text: "⛔ GUARDRAIL", style: { marginLeft: "0" } }) : null,
          ` ${data.error || "Plan generation failed"}`));
        return;
      }
      const views = { cli: planCli(data.plan) };
      views.ansible = data.export ? data.export.content : { error: data.error || "export unavailable" };
      renderRemediationCard(data.plan, views, req);
    } catch (e) {
      clear(box);
      box.appendChild(el("div", { className: "rem-note", text: `Error: ${e.message}` }));
    }
  }

  function prefillRemediation({ device, vendor, iface }) {
    const panel = document.getElementById("remediation-panel");
    const dev = document.getElementById("remediation-device-select");
    if (dev && device) {
      if (![...dev.options].some((o) => o.value === device)) dev.appendChild(el("option", { text: device, attrs: { value: device } }));
      dev.value = device;
    }
    const v = document.getElementById("remediation-vendor-select");
    if (v && vendor) v.value = vendor;
    const i = document.getElementById("remediation-interface-input");
    if (i && iface) i.value = iface;
    if (panel) {
      panel.style.display = "block";
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    generateRemediation();
  }

  // ── audit log ─────────────────────────────────────────────────────────────
  async function loadAudit() {
    const tbody = document.querySelector("#audit-table tbody");
    if (!tbody) return;
    const q = new URLSearchParams({ limit: "200" });
    const actor = (document.getElementById("audit-actor")?.value || "").trim();
    const action = (document.getElementById("audit-action")?.value || "").trim();
    if (actor) q.set("actor", actor);
    if (action) q.set("action", action);
    clear(tbody);
    try {
      const data = await fetchJSON(`/api/audit?${q}`);
      const rows = data.entries || [];
      const count = document.getElementById("audit-count");
      if (count) count.textContent = data.enabled === false ? "(audit store not configured)" : `(${rows.length})`;
      rows.forEach((a) => {
        const detail = JSON.stringify(a.detail || {});
        const bad = a.outcome && a.outcome !== "ok";
        tbody.appendChild(el("tr", { className: bad ? "sev-row-high" : "" },
          el("td", {}, el("span", { className: "row-msg", text: new Date(a.ts * 1000).toISOString().replace("T", " ").slice(0, 19) })),
          el("td", { text: a.actor || "" }),
          el("td", { text: a.role || "" }),
          el("td", {}, el("code", { text: a.action || "" })),
          el("td", { text: a.target || "" }),
          el("td", {}, el("span", { className: bad ? "outcome-bad" : "outcome-ok", text: a.outcome || "" })),
          el("td", { className: "audit-detail", text: detail, attrs: { title: detail } }),
        ));
      });
      if (!rows.length) tbody.appendChild(el("tr", {}, el("td", { text: "No entries.", attrs: { colspan: "7" } })));
    } catch (e) {
      tbody.appendChild(el("tr", {}, el("td", { text: `Error: ${e.message}`, attrs: { colspan: "7" } })));
    }
  }

  async function verifyAudit() {
    try {
      const v = await fetchJSON("/api/audit/verify");
      chipText("audit-chain", v.ok ? `chain ✓ ${v.checked} rows` : `chain ✗ broken at #${v.broken_at}`);
      chipState("audit-chain", v.ok ? "ok" : "crit",
        v.ok ? "Every row's SHA-256 matches its predecessor." : "A row was edited outside SQLite: investigate.");
    } catch (e) {
      chipText("audit-chain", "chain: error");
      chipState("audit-chain", "crit", e.message);
    }
  }

  function showAudit() {
    const panel = document.getElementById("audit-panel");
    if (!panel) return;
    panel.style.display = "block";
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    loadAudit();
    verifyAudit();
  }

  // ── analysis hook (called at the end of app.js render) ───────────────────
  function onAnalysis(r) {
    try { renderIncidents(r); } catch (e) { console.error("incidents render failed", e); }
    syncSuppressedToggle(r.action_items || []);
    refreshStatus();
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireAuth();
    document.getElementById("remediation-generate-btn")?.addEventListener("click", generateRemediation);
    document.getElementById("hide-suppressed")?.addEventListener("change", applySuppressedFilter);
    document.getElementById("audit-refresh")?.addEventListener("click", loadAudit);
    document.getElementById("audit-verify")?.addEventListener("click", verifyAudit);
    refreshStatus();
    setInterval(refreshStatus, 10000);
  });

  return {
    token, setToken, refreshStatus, eventBadges, vendorBadge, etypeBadge, actionRowExtras,
    isBlocked, blockedLine, guardBanner, playbookEvidence, renderEvidence, citedText, renderCopilot,
    renderIncidents, focusIncident, prefillRemediation, generateRemediation, planCli, showAudit, onAnalysis,
  };
})();
