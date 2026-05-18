// AI Log Analyzer — vanilla JS frontend with phased incident playbook + live execution.
// All dynamic content uses createElement/textContent to prevent XSS.
const $ = (id) => document.getElementById(id);

function el(tag, opts = {}, ...children) {
  const node = document.createElement(tag);
  if (opts.className) node.className = opts.className;
  if (opts.text != null) node.textContent = opts.text;
  if (opts.attrs) Object.entries(opts.attrs).forEach(([k, v]) => node.setAttribute(k, v));
  if (opts.on) Object.entries(opts.on).forEach(([k, v]) => node.addEventListener(k, v));
  if (opts.style) Object.assign(node.style, opts.style);
  children.flat().forEach((c) => {
    if (c == null) return;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  });
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }


// ── CLI syntax highlighter + copyable code block ────────────────────────────

/**
 * Lightweight regex tokenizer for FRR / Junos / EOS CLI snippets.
 * Returns a DocumentFragment so callers can append it directly.
 */
const _CLI_KEYWORDS = new Set([
  "show","set","no","configure","commit","rollback","clear",
  "request","monitor","ping","traceroute","write","reload",
  "delete","activate","deactivate","edit","run","exit","quit",
]);
const _CLI_COMMANDS = new Set([
  "router","neighbor","interface","interfaces","protocols","bgp","ospf",
  "ospfv3","isis","static","vlan","vlans","mpls","ldp","rsvp","evpn",
  "vxlan","security","zone","policy","policies","firewall","filter",
  "syslog","logging","system","services","login","user","class",
  "snmp","ntp","tacplus","tacplus-server","tacacs","radius","radius-server",
  "lldp","stp","spanning-tree","rstp","mstp","lacp","redundancy",
  "address","peer","peer-as","remote-as","route","routing","authentication",
  "authentication-key","peer-address","group","family","unit","mtu","inet",
  "inet6","aggregate","aggregated-ether-options","bfd","graceful-restart",
  "vtysh",
]);

function highlightCli(text) {
  const frag = document.createDocumentFragment();
  if (!text) return frag;
  const lines = String(text).split("\n");
  lines.forEach((line, idx) => {
    if (idx > 0) frag.appendChild(document.createTextNode("\n"));
    // Comments (whole-line)
    if (/^\s*[#!]/.test(line)) {
      frag.appendChild(el("span", { className: "cli-cmt", text: line }));
      return;
    }
    // Tokenize: split on whitespace/punctuation we want to preserve
    const re = /("[^"]*"|'[^']*'|\d+\.\d+\.\d+\.\d+(?:\/\d+)?|--?[\w-]+|\b\d+\b|[a-zA-Z][\w-]*|\s+|[^\s\w])/g;
    const tokens = line.match(re) || [line];
    tokens.forEach((tok) => {
      if (!tok) return;
      if (/^\s+$/.test(tok)) {
        frag.appendChild(document.createTextNode(tok));
        return;
      }
      if (/^["']/.test(tok)) {
        frag.appendChild(el("span", { className: "cli-str", text: tok }));
        return;
      }
      if (/^\d+\.\d+\.\d+\.\d+/.test(tok)) {
        frag.appendChild(el("span", { className: "cli-ip", text: tok }));
        return;
      }
      if (/^--?[\w-]+$/.test(tok)) {
        frag.appendChild(el("span", { className: "cli-flag", text: tok }));
        return;
      }
      if (/^\d+$/.test(tok)) {
        frag.appendChild(el("span", { className: "cli-num", text: tok }));
        return;
      }
      const low = tok.toLowerCase();
      if (_CLI_KEYWORDS.has(low)) {
        frag.appendChild(el("span", { className: "cli-kw", text: tok }));
        return;
      }
      if (_CLI_COMMANDS.has(low)) {
        frag.appendChild(el("span", { className: "cli-cmd", text: tok }));
        return;
      }
      frag.appendChild(document.createTextNode(tok));
    });
  });
  return frag;
}

/**
 * Wrap a code string in a styled block with a 📋 Copy button.
 * Returns a div.code-block element.
 *   codeBlock("show ip bgp summary", { lang: "frr" })
 */
function codeBlock(text, { lang = "" } = {}) {
  const wrap = el("div", { className: "code-block" });
  const pre = el("pre");
  pre.appendChild(highlightCli(text));
  wrap.appendChild(pre);
  if (lang) wrap.appendChild(el("div", { className: "code-block-lang", text: lang }));
  const btn = el("button", { className: "code-copy-btn", text: "Copy" });
  btn.addEventListener("click", async (ev) => {
    ev.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied!";
      btn.classList.add("copied");
      setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
    } catch {
      btn.textContent = "Failed";
      setTimeout(() => { btn.textContent = "Copy"; }, 1500);
    }
  });
  wrap.appendChild(btn);
  return wrap;
}


// ── Recent file paths (localStorage-backed, exposed via <datalist>) ───────

const _RECENT_PATHS_KEY = "ai_log_analyzer:recent_paths";
const _RECENT_PATHS_MAX = 8;

function loadRecentPaths() {
  try {
    const raw = localStorage.getItem(_RECENT_PATHS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function pushRecentPath(path) {
  if (!path) return;
  try {
    let list = loadRecentPaths();
    // De-dupe — move existing entry to the front instead of duplicating.
    list = list.filter((p) => p !== path);
    list.unshift(path);
    if (list.length > _RECENT_PATHS_MAX) list = list.slice(0, _RECENT_PATHS_MAX);
    localStorage.setItem(_RECENT_PATHS_KEY, JSON.stringify(list));
    refreshRecentPathsDatalist(list);
  } catch {
    /* localStorage unavailable — silent no-op */
  }
}

function refreshRecentPathsDatalist(list) {
  const dl = $("recent-paths-list");
  if (!dl) return;
  while (dl.firstChild) dl.removeChild(dl.firstChild);
  (list || loadRecentPaths()).forEach((p) => {
    // `value` is not in el()'s top-level options — must go through attrs.
    dl.appendChild(el("option", { attrs: { value: p } }));
  });
}

// ── Score-history sparkline (localStorage-backed) ──────────────────────────

const _SCORE_HISTORY_KEY = "ai_log_analyzer:score_history";
const _SCORE_HISTORY_MAX = 10;

function pushScoreHistory(score) {
  try {
    const raw = localStorage.getItem(_SCORE_HISTORY_KEY);
    const hist = raw ? JSON.parse(raw) : [];
    hist.push({ score: Number(score) || 0, ts: Date.now() });
    while (hist.length > _SCORE_HISTORY_MAX) hist.shift();
    localStorage.setItem(_SCORE_HISTORY_KEY, JSON.stringify(hist));
    return hist;
  } catch {
    return [{ score: Number(score) || 0, ts: Date.now() }];
  }
}

function renderSparkline(hist) {
  const svg = $("spark-svg");
  const empty = $("spark-empty");
  if (!svg || !empty) return;
  // With 0 or 1 data points there is no meaningful trend to draw — show a
  // friendly placeholder + the single score as a labeled dot so the panel
  // doesn't look broken on the first run.
  if (!hist || hist.length === 0) {
    empty.innerHTML = "";
    empty.textContent = "Run more analyses to build a score trend.";
    empty.style.display = "block";
    svg.style.display = "none";
    return;
  }

  empty.style.display = "none";
  svg.style.display = "block";
  clear(svg);

  const w = 200, h = 36, pad = 4;
  const NS = "http://www.w3.org/2000/svg";
  const scores = hist.map((p) => p.score);
  const min = Math.min(...scores, 60);
  const max = Math.max(...scores, 100);
  const range = Math.max(1, max - min);
  const stepX = scores.length > 1 ? (w - 2 * pad) / (scores.length - 1) : 0;
  const points = scores.map((s, i) => {
    const x = pad + i * stepX;
    const y = h - ((s - min) / range) * (h - 2 * pad) - pad;
    return [x, y, s];
  });

  // Light dashed baseline at score=70 for visual reference (within domain only).
  if (min <= 70 && 70 <= max) {
    const refY = h - ((70 - min) / range) * (h - 2 * pad) - pad;
    const ref = document.createElementNS(NS, "line");
    ref.setAttribute("x1", "0"); ref.setAttribute("x2", String(w));
    ref.setAttribute("y1", refY.toFixed(1)); ref.setAttribute("y2", refY.toFixed(1));
    ref.setAttribute("stroke", "var(--border-hi)");
    ref.setAttribute("stroke-dasharray", "2 3");
    ref.setAttribute("stroke-width", "0.6");
    svg.appendChild(ref);
  }

  // Polyline (only when we have >= 2 points).
  if (points.length >= 2) {
    const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
    const polyline = document.createElementNS(NS, "path");
    polyline.setAttribute("d", path);
    polyline.setAttribute("fill", "none");
    polyline.setAttribute("stroke", "var(--accent-2)");
    polyline.setAttribute("stroke-width", "1.5");
    polyline.setAttribute("stroke-linecap", "round");
    polyline.setAttribute("stroke-linejoin", "round");
    svg.appendChild(polyline);
  }

  // Dots — last one larger; native SVG <title> for hover values.
  points.forEach((p, i) => {
    const dot = document.createElementNS(NS, "circle");
    dot.setAttribute("cx", p[0].toFixed(1));
    dot.setAttribute("cy", p[1].toFixed(1));
    dot.setAttribute("r", i === points.length - 1 ? "3" : "1.5");
    dot.setAttribute("fill", "var(--accent-2)");
    const ttl = document.createElementNS(NS, "title");
    ttl.textContent = `Run ${i + 1}: score ${p[2]}`;
    dot.appendChild(ttl);
    svg.appendChild(dot);
  });

  // Min/max labels at the ends of the line (only shown with >= 2 points).
  if (points.length >= 2) {
    const minLabel = document.createElementNS(NS, "text");
    minLabel.setAttribute("x", "2"); minLabel.setAttribute("y", String(h - 1));
    minLabel.setAttribute("fill", "var(--muted-2)");
    minLabel.setAttribute("font-size", "8");
    minLabel.textContent = String(scores[0]);
    svg.appendChild(minLabel);
    const maxLabel = document.createElementNS(NS, "text");
    maxLabel.setAttribute("x", String(w - 16)); maxLabel.setAttribute("y", String(h - 1));
    maxLabel.setAttribute("fill", "var(--accent-2)");
    maxLabel.setAttribute("font-size", "8");
    maxLabel.textContent = String(scores[scores.length - 1]);
    svg.appendChild(maxLabel);
  }
}


// ── Context breadcrumb ─────────────────────────────────────────────────────

function setContext(text) {
  const bar = $("context-bar");
  if (!bar) return;
  if (!text) { bar.style.display = "none"; return; }
  const t = $("context-text");
  t.textContent = text;
  // Full string survives in the title attr so the truncated ellipsis variant
  // can still be inspected on hover.
  t.title = text;
  bar.style.display = "flex";
}


// ── Chip-picker for FRR containers ─────────────────────────────────────────

function refreshChipsCount() {
  const sel = $("containers");
  if (!sel) return;
  const total = sel.options.length;
  const n = Array.from(sel.options).filter((o) => o.selected).length;
  const lbl = $("chips-count");
  if (lbl) {
    if (total === 0)       lbl.textContent = "no containers";
    else if (n === 0)      lbl.textContent = "none selected";
    else if (n === total)  lbl.textContent = `all ${total} selected`;
    else                   lbl.textContent = `${n}/${total} selected`;
  }
}

// Bulk toggle helpers — wired to the "All" / "None" sidebar buttons.
function setAllChips(selected) {
  const sel = $("containers");
  if (!sel) return;
  Array.from(sel.options).forEach((opt) => { opt.selected = selected; });
  // Sync visual chips too.
  const picker = $("chip-picker");
  if (picker) {
    Array.from(picker.children).forEach((chip) => {
      chip.classList.toggle("selected", selected);
      chip.setAttribute("aria-pressed", selected ? "true" : "false");
    });
  }
  refreshChipsCount();
}

function rebuildContainerChips() {
  const picker = $("chip-picker");
  const sel = $("containers");
  if (!picker || !sel) return;
  picker.setAttribute("role", "group");
  picker.setAttribute("aria-label", "Container picker (toggle to include)");
  clear(picker);
  Array.from(sel.options).forEach((opt) => {
    const chip = el("span", {
      className: "chip-pick" + (opt.selected ? " selected" : ""),
      text: opt.value,
      attrs: {
        role: "button",
        tabindex: "0",
        "aria-pressed": opt.selected ? "true" : "false",
        "aria-label": `Toggle container ${opt.value}`,
      },
    });
    const toggle = () => {
      opt.selected = !opt.selected;
      chip.classList.toggle("selected", opt.selected);
      chip.setAttribute("aria-pressed", opt.selected ? "true" : "false");
      refreshChipsCount();
    };
    chip.addEventListener("click", toggle);
    chip.addEventListener("keydown", (e) => {
      if (e.key === " " || e.key === "Enter") { e.preventDefault(); toggle(); }
    });
    picker.appendChild(chip);
  });
  refreshChipsCount();
}

async function fetchJSON(url, opts = {}) {
  const r = await fetch(url, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ error: r.statusText }));
    throw new Error(err.error || `HTTP ${r.status}`);
  }
  return r.json();
}

function setStatus(msg) {
  const el = $("status");
  el.textContent = msg || "";
  el.classList.toggle("show", !!msg);
}

// ── Toast notifications ─────────────────────────────────────────────────────
// kind: "info" | "success" | "error". duration in ms; 0 = sticky (manual close).
const _TOAST_ICONS = { info: "ℹ️", success: "✅", error: "⚠️" };
function toast(message, kind = "info", duration = 4000) {
  const stack = $("toast-stack");
  if (!stack) return;
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.setAttribute("role", kind === "error" ? "alert" : "status");
  const icon = document.createElement("span");
  icon.className = "toast-icon";
  icon.textContent = _TOAST_ICONS[kind] || "ℹ️";
  const body = document.createElement("div");
  body.className = "toast-body";
  body.textContent = String(message ?? "");
  const close = document.createElement("button");
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss notification");
  close.textContent = "✕";
  const dismiss = () => {
    if (!t.parentNode) return;
    t.classList.add("leaving");
    setTimeout(() => t.remove(), 200);
  };
  close.addEventListener("click", dismiss);
  t.appendChild(icon); t.appendChild(body); t.appendChild(close);
  stack.appendChild(t);
  if (duration > 0) setTimeout(dismiss, duration);
  return t;
}

// ── Panel-level loading/progress ────────────────────────────────────────────
// Inject an indeterminate progress bar at the top of `panel` and mark it busy.
// Returns a "clear" function that removes the bar + clears aria-busy.
function showPanelProgress(panelId, label) {
  const panel = $(panelId);
  if (!panel) return () => {};
  panel.style.display = "block";
  panel.setAttribute("aria-busy", "true");
  // Reuse existing bar if present
  let bar = panel.querySelector(".progress-bar");
  if (!bar) {
    bar = document.createElement("div");
    bar.className = "progress-bar";
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-label", label || "Loading");
    // Insert just after the first h2 (so it sits under the title)
    const h2 = panel.querySelector("h2");
    if (h2 && h2.nextSibling) panel.insertBefore(bar, h2.nextSibling);
    else panel.insertBefore(bar, panel.firstChild);
  }
  return () => {
    panel.removeAttribute("aria-busy");
    if (bar && bar.parentNode) bar.remove();
  };
}

// Chip badges have inner <span class="pulse"></span><span>text</span> structure.
// Update only the second span so the pulse dot is preserved.
function setChipText(badgeId, text) {
  const badge = $(badgeId);
  const spans = badge.querySelectorAll("span");
  const target = spans.length >= 2 ? spans[1] : spans[0] || badge;
  target.textContent = text;
}

// ── Provider / health badges ─────────────────────────────────────────────────
async function refreshLLMStatus() {
  try {
    const s = await fetchJSON("/api/llm/status");
    setChipText("llm-badge", `LLM: ${s.enabled ? "on" : "off"}`);
    $("llm-badge").classList.toggle("ok",   !!s.enabled);
    $("llm-badge").classList.toggle("warn", !s.enabled);

    const provInfo = (s.providers_available || []).find((p) => p.id === s.provider) || {};
    const lastErr = (s.last_errors || {})[s.provider];
    let label = `Provider: ${s.provider}`;
    if (!provInfo.available) label += " (unreachable)";
    if (lastErr) label += " ⚠";
    setChipText("prov-badge", label);
    $("prov-badge").title = lastErr ||
      ((provInfo.available ? "reachable" : "not reachable") + " — " + (provInfo.model || ""));
    $("prov-badge").classList.toggle("ok",   !!provInfo.available && !lastErr && !!s.enabled);
    $("prov-badge").classList.toggle("warn", !provInfo.available || !!lastErr || !s.enabled);
    $("provider").value = s.provider;

    // Visually dim the Provider chip + sidebar select when LLM is off — the
    // header badge alone is easy to miss when scanning the sidebar.
    $("prov-badge").classList.toggle("llm-disabled", !s.enabled);
    const provSection = $("provider").closest(".side-section-body");
    if (provSection) provSection.classList.toggle("llm-disabled", !s.enabled);
    // Sync the checkbox in the Provider section
    if ($("use-llm").checked !== !!s.enabled) {
      $("use-llm").checked = !!s.enabled;
    }
  } catch {
    setChipText("llm-badge", "LLM: error");
    $("llm-badge").classList.add("crit");
  }
}

async function refreshNetToolStatus() {
  try {
    const h = await fetchJSON("/api/health");
    const ok = !!h.network_tool_available;
    setChipText("ntool-badge", `NetTool: ${ok ? "online :5757" : "offline"}`);
    $("ntool-badge").classList.toggle("ok",   ok);
    $("ntool-badge").classList.toggle("warn", !ok);
  } catch {
    setChipText("ntool-badge", "NetTool: error");
    $("ntool-badge").classList.add("crit");
  }
}

async function loadContainers() {
  const btn = $("reload-containers");
  if (btn) {
    btn.disabled = true;
    btn.dataset.origText = btn.textContent;
    btn.textContent = "⏳ Reloading…";
    btn.classList.add("running");
  }
  try {
    const data = await fetchJSON("/api/lab/containers");
    const sel = $("containers");
    clear(sel);
    (data.containers || []).forEach((name) => {
      sel.appendChild(el("option", { text: name, attrs: { value: name } }));
    });
    rebuildContainerChips();
    setStatus(`Found ${data.containers.length} lab container(s)`);
    // Pre-fill Optimize hostname if empty
    if (!$("opt-host").value && data.containers.length > 0) {
      $("opt-host").value = data.containers[0];
    }
  } catch (e) {
    setStatus(`Error loading containers: ${e.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = btn.dataset.origText || "↻ Reload Containers";
      btn.classList.remove("running");
    }
  }
}

function showSourceControls() {
  const src = $("source").value;
  // Each control panel ships with hidden + aria-hidden + inert so screen readers
  // and keyboard nav skip them while collapsed. All three must be toggled in
  // sync — otherwise the input stays uneditable when revealed.
  const panels = [
    { id: "frr-controls",  active: src === "frr"  },
    { id: "raw-controls",  active: src === "raw"  },
    { id: "file-controls", active: src === "file" },
  ];
  for (const { id, active } of panels) {
    const el = $(id);
    if (!el) continue;
    el.classList.toggle("hidden", !active);
    el.toggleAttribute("inert", !active);
    if (active) {
      el.removeAttribute("aria-hidden");
    } else {
      el.setAttribute("aria-hidden", "true");
    }
  }
}

// ── Run analysis ─────────────────────────────────────────────────────────────
async function runAnalysis() {
  const btn = $("run-btn");
  btn.disabled = true;
  btn.classList.add("running");
  btn.setAttribute("aria-busy", "true");
  setStatus("Running analysis…");
  // Show indeterminate progress bar on the idle/welcome panel so the user sees
  // visible motion while the (possibly long) LLM call is in flight.
  const clearProgress = showPanelProgress("idle-state", "Running analysis");
  const source = $("source").value;
  const useLLM = $("use-llm").checked;
  const body = { source, use_llm: useLLM };

  if (source === "frr") {
    body.containers = Array.from($("containers").selectedOptions).map((o) => o.value);
    body.tail = parseInt($("tail").value, 10) || 500;
  } else if (source === "raw") {
    body.text = $("raw-text").value;
    body.hostname = $("raw-host").value;
  } else if (source === "file") {
    body.path = $("file-path").value;
  }

  try {
    const result = await fetchJSON("/api/analyze", { method: "POST", body: JSON.stringify(body) });
    render(result);
    // Persist the successful file path into the recent-paths history so the
    // user can autocomplete it next time via the datalist dropdown.
    if (source === "file" && body.path) {
      pushRecentPath(body.path);
    }
    const summary = `${result.classified_events.length} events analyzed (${result.llm_powered ? "LLM" : "KB"})`;
    setStatus(`Done — ${summary}`);
    toast(`Analysis complete — ${summary}`, "success");
  } catch (e) {
    setStatus(`Error: ${e.message}`);
    toast(`Analysis failed: ${e.message}`, "error", 6000);
  } finally {
    btn.disabled = false;
    btn.classList.remove("running");
    btn.removeAttribute("aria-busy");
    clearProgress();
  }
}

async function changeProvider() {
  const provider = $("provider").value;
  try {
    await fetchJSON("/api/llm/provider", { method: "POST", body: JSON.stringify({ provider }) });
    refreshLLMStatus();
  } catch (e) {
    setStatus(`Provider error: ${e.message}`);
    refreshLLMStatus();
  }
}

function sevBadge(severity) {
  return el("span", { className: `sev sev-${severity}`, text: severity });
}

/** Tiny origin pill next to a hostname — tells the user where the event
 *  came from (SecureCRT recording, FRR docker logs, etc). Returns null for
 *  generic syslog so the table stays uncluttered. */
function sourceBadge(appname) {
  const a = (appname || "").toLowerCase();
  if (a === "scrt-session") {
    return el("span", { className: "src-badge scrt", text: "SCRT" });
  }
  if (a === "frr" || a === "watchfrr" || a === "bgpd" || a === "ospfd" || a === "zebra") {
    return el("span", { className: "src-badge frr", text: "FRR" });
  }
  return null;
}

// ── Main render ──────────────────────────────────────────────────────────────

/** Circle stroke-dasharray for our gauge (r=74 → 2πr ≈ 464.96). */
const GAUGE_CIRC = 464.96;

function _updateGauge(score, grade) {
  const arc = $("gauge-arc");
  if (!arc) return;
  const pct = Math.max(0, Math.min(100, Number(score) || 0)) / 100;
  arc.setAttribute("stroke-dashoffset", String(GAUGE_CIRC * (1 - pct)));
  // Color the arc by grade
  const color = ({
    A: "var(--ok)", B: "#79c0ff", C: "var(--med)",
    D: "#ff7b72", F: "var(--crit)",
  })[grade] || "var(--ok)";
  arc.style.stroke = color;
}

function _setHealthStatZero(id, count) {
  const card = $(id);
  if (!card) return;
  card.classList.toggle("zero", !count);
}

function _updateKpiGrid(r) {
  $("kpi-grid").style.display = "grid";
  // Health
  $("kpi-health-val").textContent = r.score;
  $("kpi-health-val").className = "kpi-value grade-" + r.grade;
  $("kpi-health-sub").textContent = `${r.grade} — ${r.grade_label}`;
  const kpiHealth = $("kpi-health");
  kpiHealth.classList.remove("ok", "high", "crit", "med");
  if      (r.grade === "A") kpiHealth.classList.add("ok");
  else if (r.grade === "B" || r.grade === "C") kpiHealth.classList.add("med");
  else if (r.grade === "D" || r.grade === "F") kpiHealth.classList.add("crit");

  // Active alerts (critical + high)
  const alerts = (r.severity_counts.critical || 0) + (r.severity_counts.high || 0);
  $("kpi-alerts-val").textContent = alerts;
  $("kpi-alerts-val").style.color = alerts > 0 ? "var(--crit)" : "var(--ok)";
  const kpiAlerts = $("kpi-alerts");
  kpiAlerts.classList.remove("ok", "high", "crit");
  kpiAlerts.classList.add(alerts === 0 ? "ok" : alerts >= 3 ? "crit" : "high");

  // Devices monitored — from top_devices array
  $("kpi-devices-val").textContent = (r.top_devices || []).length || "—";

  // Last analysis time (from generated_at ISO string)
  const ts = r.generated_at || "";
  if (ts) {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) {
      const hh = String(d.getUTCHours()).padStart(2, "0");
      const mm = String(d.getUTCMinutes()).padStart(2, "0");
      $("kpi-time-val").textContent = `${hh}:${mm}`;
      $("kpi-time-sub").textContent = `${d.toISOString().slice(0,10)} UTC`;
    } else {
      $("kpi-time-val").textContent = "—";
    }
  }
}

function render(r) {
  // Hide the idle welcome panel once we have a real result
  const idle = $("idle-state");
  if (idle) idle.style.display = "none";

  // Context breadcrumb — describe what we're showing
  const source = $("source") ? $("source").value : "";
  const ctxParts = [];
  if (source === "frr") {
    const conts = Array.from($("containers").options).filter((o) => o.selected);
    if (conts.length) ctxParts.push(`FRR containers: ${conts.map((c) => c.value).join(", ")}`);
    else              ctxParts.push("FRR lab — all containers");
  } else if (source === "raw") {
    const h = ($("raw-host").value || "").trim();
    ctxParts.push(h ? `Raw logs · ${h}` : "Raw logs");
  } else if (source === "file") {
    ctxParts.push(`File: ${$("file-path").value || "(unspecified)"}`);
  }
  ctxParts.push(`${r.classified_events.length} events`);
  setContext(ctxParts.join("  ·  "));

  // KPI dashboard row
  _updateKpiGrid(r);

  // Score-history sparkline
  const hist = pushScoreHistory(r.score);
  renderSparkline(hist);

  // Health panel + circular gauge
  $("health-panel").style.display = "block";
  const score = $("score");
  score.textContent = r.score;
  score.className = "score-num grade-" + r.grade;
  $("grade-label").textContent = `${r.grade} — ${r.grade_label}`;
  _updateGauge(r.score, r.grade);

  const sc = r.severity_counts || {};
  $("stat-crit").textContent = sc.critical || 0;
  $("stat-high").textContent = sc.high     || 0;
  $("stat-med").textContent  = sc.medium   || 0;
  _setHealthStatZero("hs-crit", sc.critical);
  _setHealthStatZero("hs-high", sc.high);
  _setHealthStatZero("hs-med",  sc.medium);

  // Summary
  $("summary-panel").style.display = "block";
  const ul = $("summary-list");
  clear(ul);
  (r.executive_summary || []).forEach((b) => ul.appendChild(el("li", { text: b })));
  const eng = $("summary-engine");
  eng.textContent = r.llm_powered ? "LLM" : "KB";
  eng.className = "ai-badge " + (r.llm_powered ? "" : "kb-badge");

  // Action items
  $("actions-panel").style.display = "block";
  $("action-count").textContent = `(${r.action_items.length})`;
  const aTbody = $("actions-table").querySelector("tbody");
  clear(aTbody);
  r.action_items.forEach((item) => {
    const devLabel = `${item.devices.length}: ${item.devices.slice(0, 3).join(", ")}`;
    const tr = el("tr", { className: "action" },
      el("td", {}, sevBadge(item.severity)),
      el("td", { text: item.description }),
      el("td", { text: String(item.count) }),
      el("td", { text: devLabel }),
    );
    tr.addEventListener("click", () => togglePhasedPlan(tr, item));
    aTbody.appendChild(tr);
  });

  // Events
  $("events-panel").style.display = "block";
  const totalEvents = (r.classified_events || []).length;
  const shownEvents = Math.min(totalEvents, 100);
  const ec = $("events-count");
  if (ec) ec.textContent = totalEvents > shownEvents
    ? `${shownEvents} of ${totalEvents} shown`
    : `${totalEvents}`;
  const eTbody = $("events-table").querySelector("tbody");
  clear(eTbody);
  r.classified_events.slice(0, 100).forEach((e) => {
    const desc = (e.description || "").trim();
    const sample = (e.sample_message || "").trim();
    // De-dupe: only show sample_message if it adds info beyond description.
    const showSample = sample && sample !== desc && !desc.includes(sample);
    const descCell = showSample
      ? el("td", {},
          desc,
          el("br"),
          el("span", { className: "row-msg", text: sample }),
        )
      : el("td", { text: desc });
    // Source-origin badge (SCRT recording, FRR docker, etc.) — shown next to
    // the hostname so it's grouped with the device, not the description.
    const srcBadge = sourceBadge(e.appname);
    const hostCell = srcBadge
      ? el("td", {}, document.createTextNode(e.hostname || ""), srcBadge)
      : el("td", { text: e.hostname || "" });
    // Severity-tinted row for scannability
    const tr = el("tr", { className: `sev-row-${e.severity || "info"}` },
      el("td", {}, sevBadge(e.severity)),
      el("td", {}, el("span", { className: "row-msg", text: e.timestamp || "" })),
      hostCell,
      el("td", {}, el("span", { className: "row-msg", text: e.category })),
      descCell,
    );
    eTbody.appendChild(tr);
  });
}

// ── Phased incident playbook (the deep-dive panel) ───────────────────────────
function togglePhasedPlan(rowEl, item) {
  const next = rowEl.nextElementSibling;
  if (next && next.dataset.deep) { next.remove(); return; }

  const d = item.deep_analysis || {};
  const llmBadge = el("span", {
    className: d.llm_powered ? "ai-badge" : "ai-badge kb-badge",
    text: d.llm_powered ? "LLM" : "KB",
  });

  const deep = el("div", { className: "deep" },
    el("h3", {}, "Root Cause ", llmBadge),
    el("div", { text: d.root_cause || "—" }),
    el("h3", { text: "Risk" }),
    el("div", { text: d.risk || "—" }),
    el("h3", { text: "Context" }),
    el("div", {},
      el("div", { text: d.device_context || "" }),
      el("div", { text: d.urgency || "" }),
      el("div", { text: "Timeline: " + (d.timeline || "—") }),
    ),
    el("h3", { text: "Incident Playbook (5 phases)" }),
    ...renderPhases(d.phases || [], item.devices),
    el("h3", { text: "Preventive Config" }),
    el("pre", { text: (d.preventive_config || []).join("\n") || "—" }),
    el("h3", { text: "Monitoring Recommendations" }),
    renderListOrDash(d.monitoring),
    el("h3", { text: "Sample Log Lines" }),
    el("pre", { text: (d.sample_messages || []).join("\n") }),
  );

  const td = el("td", { attrs: { colspan: "4" } }, deep);
  const tr = el("tr", {}, td);
  tr.dataset.deep = "1";
  rowEl.after(tr);
  // Scroll the newly-expanded playbook into view — without this the user
  // clicks a row and sees no visible change because the deep panel renders
  // below the fold. scrollIntoView on a <tr> is unreliable across browsers,
  // so we compute the absolute target ourselves and use window.scrollTo.
  requestAnimationFrame(() => {
    const rect = tr.getBoundingClientRect();
    const target = window.scrollY + rect.top - 85;   // ~85px = sticky header height
    window.scrollTo({ top: target, behavior: "smooth" });
  });
}

function renderListOrDash(items) {
  if (!items || !items.length) return el("div", { text: "—" });
  const ul = el("ul");
  items.forEach((m) => ul.appendChild(el("li", { text: m })));
  return ul;
}

function renderPhases(phases, devices) {
  if (!phases.length) return [el("div", { text: "No phases produced." })];
  return phases.map((p) => renderPhase(p, devices));
}

function renderPhase(phase, devices) {
  const wrap = el("div", { className: "phase" });
  const body = el("div", { className: "phase-body" });
  const head = el("div", { className: "phase-head" },
    el("span", { className: "phase-name phase-" + (phase.name || "Diagnose"), text: phase.name || "—" }),
    el("span", { className: "phase-goal", text: phase.goal || "" }),
  );
  let open = phase.name !== "Optimize"; // Optimize collapsed by default
  body.style.display = open ? "block" : "none";
  head.addEventListener("click", () => {
    open = !open;
    body.style.display = open ? "block" : "none";
  });
  wrap.appendChild(head);

  (phase.actions || []).forEach((action) => {
    body.appendChild(renderAction(action, devices));
  });
  if (!phase.actions || !phase.actions.length) {
    body.appendChild(el("div", { className: "row-msg", text: "(no actions)" }));
  }
  wrap.appendChild(body);
  return wrap;
}

function renderAction(action, devices) {
  const card = el("div", { className: "action-card" });
  const cliDict = action.cli || {};
  const platforms = Object.keys(cliDict);

  // Platform selector (only show if multiple)
  let activePlatform = pickDefaultPlatform(platforms);
  const codeEl = el("code");
  const setCode = (txt) => { clear(codeEl); codeEl.appendChild(highlightCli(txt || "(no command for platform)")); };
  setCode(cliDict[activePlatform]);

  // Copy button for this CLI command — small inline icon (action-cli stays interactive)
  const copyBtn = el("button", {
    className: "tiny secondary",
    text: "📋",
    attrs: { title: "Copy command" },
    style: { padding: "2px 8px", margin: 0, width: "auto", flex: "0 0 auto" },
  });
  copyBtn.addEventListener("click", async (ev) => {
    ev.stopPropagation();
    try {
      await navigator.clipboard.writeText(cliDict[activePlatform] || "");
      copyBtn.textContent = "✓";
      setTimeout(() => { copyBtn.textContent = "📋"; }, 1200);
    } catch {
      copyBtn.textContent = "✗";
      setTimeout(() => { copyBtn.textContent = "📋"; }, 1200);
    }
  });

  const platformSel = el("select", { style: { width: "auto", padding: "2px 6px", fontSize: "11px" } });
  platforms.forEach((p) => {
    platformSel.appendChild(el("option", { text: p, attrs: { value: p } }));
  });
  platformSel.value = activePlatform;
  platformSel.addEventListener("change", () => {
    activePlatform = platformSel.value;
    setCode(cliDict[activePlatform]);
  });

  // ▶ Run on device button
  const hostInput = el("input", {
    attrs: { placeholder: pickDefaultHost(devices) || "hostname", value: pickDefaultHost(devices) || "" },
    style: { width: "140px", padding: "2px 6px", fontSize: "11px" },
  });
  const outputBox = el("div", { className: "action-output", style: { display: "none" } });

  const runBtn = el("button", {
    className: "tiny",
    text: "▶ Run",
    style: { background: "var(--ok)", color: "#0d1117" },
    on: {
      click: async () => {
        const host = hostInput.value.trim();
        const cmd = codeEl.textContent;
        if (!host || !cmd) return;
        runBtn.disabled = true;
        outputBox.style.display = "block";
        outputBox.classList.remove("err");
        outputBox.textContent = `→ ${host}: ${cmd}\n…running…`;
        try {
          const r = await fetchJSON("/api/run", {
            method: "POST",
            body: JSON.stringify({ hostname: host, command: cmd }),
          });
          outputBox.textContent = (r.output || "(no output)") + (r.error ? "\n[stderr] " + r.error : "");
          if (!r.ok) outputBox.classList.add("err");
        } catch (e) {
          outputBox.classList.add("err");
          outputBox.textContent = "Error: " + e.message;
        } finally {
          runBtn.disabled = false;
        }
      },
    },
  });

  card.appendChild(el("div", { className: "action-cli" },
    codeEl,
    copyBtn,
    platformSel,
    hostInput,
    runBtn,
  ));
  if (action.expected) {
    card.appendChild(el("div", { className: "action-meta" },
      el("span", { className: "expected", text: "✓ expected: " }),
      action.expected,
    ));
  }
  if (action.note) {
    card.appendChild(el("div", { className: "action-meta", text: "note: " + action.note }));
  }
  card.appendChild(outputBox);
  return card;
}

function pickDefaultPlatform(platforms) {
  // Prefer FRR for lab demo, then junos, then eos, then anything
  for (const p of ["frr", "junos", "eos", "any"]) {
    if (platforms.includes(p)) return p;
  }
  return platforms[0] || "frr";
}

function pickDefaultHost(devices) {
  return devices && devices.length ? devices[0] : "";
}

// ── Optimize panel ───────────────────────────────────────────────────────────
async function runOptimize() {
  const host = $("opt-host").value.trim();
  const platform = $("opt-platform").value;
  if (!host) { setStatus("Optimize: hostname required"); return; }
  setContext(`Device · ${host} (${platform})`);
  await runOptimizeRequest({ hostname: host, platform }, `Optimize: fetching config + analyzing ${host}…`, $("opt-btn"));
}

async function runSampleOptimize() {
  const sampleId = $("sample-picker").value;
  if (!sampleId) { setStatus("Sample optimize: pick a sample first"); return; }
  setContext(`Sample · ${sampleId}`);
  await runOptimizeRequest({ sample_id: sampleId }, `Optimize: analyzing sample ${sampleId}…`, $("sample-opt-btn"));
}

async function runOptimizeRequest(body, statusMsg, btn) {
  btn.disabled = true; btn.setAttribute("aria-busy", "true");
  setStatus(statusMsg);
  $("optimize-panel").style.display = "block";
  $("opt-summary").textContent = "Running…";
  clear($("opt-findings"));
  clear($("opt-monitoring"));
  const clearProgress = showPanelProgress("optimize-panel", "Optimizing config");
  try {
    const r = await fetchJSON("/api/optimize", {
      method: "POST",
      body: JSON.stringify(body),
    });
    renderOptimize(r);
    const n = r.findings ? r.findings.length : 0;
    setStatus(`Optimize: done (${n} findings, score ${r.score || 0}/100)`);
    toast(`Optimization complete — ${n} findings, score ${r.score || 0}/100.`, "success");
  } catch (e) {
    $("opt-summary").textContent = "Error: " + e.message;
    setStatus(`Optimize error: ${e.message}`);
    toast("Optimize error: " + e.message, "error", 6000);
  } finally {
    clearProgress();
    btn.disabled = false; btn.removeAttribute("aria-busy");
  }
}

async function loadSites() {
  try {
    const data = await fetchJSON("/api/sites");
    const picker = $("site-picker");
    clear(picker);
    picker.appendChild(el("option", { text: "— select a site —", attrs: { value: "" } }));
    (data.sites || []).forEach((s) => {
      const kb = Math.round((s.total_bytes || 0) / 1024);
      const label = `${s.site} — ${s.device_count} devices · ${s.vendor} · ${kb} KB · ${s.total_redactions} redactions`;
      picker.appendChild(el("option", { text: label, attrs: { value: s.id } }));
    });
  } catch (e) {
    setStatus(`Could not load sites: ${e.message}`);
  }
}

async function showSiteMeta() {
  const id = $("site-picker").value;
  const meta = $("site-meta");
  if (!id) { meta.textContent = ""; return; }
  try {
    const d = await fetchJSON("/api/sites");
    const site = (d.sites || []).find((s) => s.id === id);
    if (!site) { meta.textContent = ""; return; }
    const devList = site.devices.map((x) => `${x.hostname} (${x.function})`).join(", ");
    meta.textContent = devList;
  } catch (e) {
    meta.textContent = "(error)";
  }
}

async function runSiteOptimize() {
  const id = $("site-picker").value;
  if (!id) { toast("Site analysis: pick a site first.", "error"); return; }
  const btn = $("site-opt-btn");
  btn.disabled = true; btn.setAttribute("aria-busy", "true");
  setContext(`Site · ${id.toUpperCase()}`);
  setStatus(`Site analysis: running cross-device review on ${id.toUpperCase()}…`);
  $("site-panel").style.display = "block";
  $("site-summary").innerHTML =
    `<span style="color:var(--accent-2);">●</span> ` +
    `Analyzing <strong>${id.toUpperCase()}</strong> — sanitizing configs, ` +
    `building cross-device topology, querying LLM (this can take 15–30s on large bundles)…`;
  clear($("site-topology"));
  clear($("site-findings"));
  clear($("site-monitoring"));
  // Inject a few skeleton shimmer blocks so the user sees motion under the bar.
  const fakeWrap = $("site-findings");
  for (let i = 0; i < 3; i++) {
    fakeWrap.appendChild(el("div", { className: "skeleton",
      style: { height: "28px", margin: "8px 0", borderRadius: "6px" } }));
  }
  const clearProgress = showPanelProgress("site-panel", "Analyzing site");
  try {
    const r = await fetchJSON("/api/optimize/site", {
      method: "POST",
      body: JSON.stringify({ site_id: id }),
    });
    renderSiteAnalysis(r);
    const n = (r.cross_device_findings || []).length;
    setStatus(`Site analysis: done (${n} findings, score ${r.site_score || 0}/100)`);
    toast(`Site analysis complete — ${n} findings, score ${r.site_score || 0}/100.`, "success");
  } catch (e) {
    $("site-summary").textContent = "Error: " + e.message;
    setStatus(`Site analysis error: ${e.message}`);
    toast("Site analysis error: " + e.message, "error", 6000);
  } finally {
    clearProgress();
    btn.disabled = false; btn.removeAttribute("aria-busy");
  }
}

function renderSiteAnalysis(r) {
  $("site-engine").textContent = r.llm_powered ? "LLM" : "KB";
  $("site-engine").className = "ai-badge " + (r.llm_powered ? "" : "kb-badge");
  $("site-summary").textContent = `${r.site_summary || ""} — Site maturity: ${r.site_score || 0}/100`;

  // Topology
  const topo = r.topology || {};
  const topoWrap = $("site-topology");
  clear(topoWrap);
  if (topo.devices_seen && topo.devices_seen.length) {
    topoWrap.appendChild(el("div", { className: "row-msg",
      text: `Devices analyzed (${topo.devices_seen.length}): ${topo.devices_seen.join(", ")}` }));
  }
  if (topo.roles && typeof topo.roles === "object") {
    Object.entries(topo.roles).forEach(([role, devs]) => {
      if (!Array.isArray(devs)) return;
      topoWrap.appendChild(el("div", { className: "row-msg",
        text: `${role}: ${devs.join(", ")}` }));
    });
  }
  if (Array.isArray(topo.isp_uplinks) && topo.isp_uplinks.length) {
    topoWrap.appendChild(el("div", { className: "row-msg",
      text: `ISP uplinks: ${topo.isp_uplinks.join("; ")}` }));
  }

  // Findings
  const fWrap = $("site-findings");
  clear(fWrap);
  (r.cross_device_findings || []).forEach((f) => {
    const affected = (f.affected_devices || []).join(", ") || "—";
    const card = el("div", { className: "finding" },
      el("div", {},
        sevBadge(f.severity || "medium"),
        " ",
        el("strong", { text: f.title || "(no title)" }),
        " — ",
        el("span", { className: "row-msg", text: f.category || "" }),
      ),
      el("div", { className: "finding-evidence",
        text: "Affected devices: " + affected }),
      el("div", { className: "finding-evidence",
        text: "Evidence: " + (f.evidence || "—") }),
      el("div", { style: { margin: "6px 0", fontSize: "12px" },
        text: f.rationale || "" }),
    );
    const fpd = f.fix_per_device || {};
    if (Object.keys(fpd).length) {
      card.appendChild(el("h4", {
        text: "Per-Device Fix",
        style: { fontSize: "11px", color: "var(--muted)", marginTop: "8px" } }));
      Object.entries(fpd).forEach(([dev, cmds]) => {
        if (!Array.isArray(cmds) || !cmds.length) return;
        card.appendChild(el("div", { className: "row-msg",
          style: { marginTop: "4px" }, text: `▸ ${dev}` }));
        card.appendChild(el("pre", { text: cmds.join("\n") }));
      });
    }
    if (Array.isArray(f.verify_cli) && f.verify_cli.length) {
      card.appendChild(el("h4", { text: "Verify",
        style: { fontSize: "11px", color: "var(--muted)", marginTop: "8px" } }));
      card.appendChild(el("pre", { text: f.verify_cli.join("\n") }));
    }
    fWrap.appendChild(card);
  });

  const monUl = $("site-monitoring");
  clear(monUl);
  (r.monitoring_gaps || []).forEach((m) => monUl.appendChild(el("li", { text: m })));
}

async function loadSamples() {
  try {
    const data = await fetchJSON("/api/samples");
    const picker = $("sample-picker");
    clear(picker);
    picker.appendChild(el("option", { text: "— select a sample —", attrs: { value: "" } }));
    (data.samples || []).forEach((s) => {
      const kb = Math.round((s.sanitized_bytes || 0) / 1024);
      const label = `${s.id} — ${s.function} [${kb} KB, ${s.redacted} redactions]`;
      picker.appendChild(el("option", { text: label, attrs: { value: s.id } }));
    });
  } catch (e) {
    setStatus(`Could not load samples: ${e.message}`);
  }
}

async function showSampleMeta() {
  const id = $("sample-picker").value;
  const meta = $("sample-meta");
  if (!id) { meta.textContent = ""; return; }
  try {
    const d = await fetchJSON("/api/samples/" + encodeURIComponent(id));
    meta.textContent = `${d.total_lines} lines · ${Math.round(d.total_chars/1024)} KB sanitized`;
  } catch (e) {
    meta.textContent = "(preview error)";
  }
}

function renderOptimize(r) {
  $("opt-engine").textContent = r.llm_powered ? "LLM" : "KB";
  $("opt-engine").className = "ai-badge " + (r.llm_powered ? "" : "kb-badge");
  $("opt-summary").textContent = `${r.summary || ""} — Maturity score: ${r.score || 0}/100`;

  const fWrap = $("opt-findings");
  clear(fWrap);
  (r.findings || []).forEach((f) => {
    const card = el("div", { className: "finding" },
      el("div", {},
        sevBadge(f.severity || "medium"),
        " ",
        el("strong", { text: f.title || "(no title)" }),
        " — ",
        el("span", { className: "row-msg", text: f.category || "" }),
      ),
      el("div", { className: "finding-evidence", text: "Evidence: " + (f.evidence || "—") }),
      el("div", { style: { margin: "6px 0", fontSize: "12px" }, text: f.rationale || "" }),
    );
    // Colored section headers — left-border accent matches the severity color
    // language used elsewhere (cyan = action/patch, orange = rollback caution,
    // green = post-change verify).
    const h4 = (text, accent) => el("h4", {
      text,
      style: {
        fontSize: "11px", color: "var(--fg-dim)", marginTop: "10px",
        textTransform: "uppercase", letterSpacing: "0.5px",
        padding: "4px 0 4px 8px",
        borderLeft: `3px solid ${accent}`,
        background: "rgba(255,255,255,0.012)",
        borderRadius: "2px",
      },
    });
    if (f.patch && f.patch.length) {
      card.appendChild(h4("Proposed Patch", "var(--accent-2)"));
      card.appendChild(codeBlock(f.patch.join("\n"), { lang: r.platform || "" }));
    }
    if (f.rollback && f.rollback.length) {
      card.appendChild(h4("Rollback", "var(--high)"));
      card.appendChild(codeBlock(f.rollback.join("\n"), { lang: r.platform || "" }));
    }
    if (f.verify_cli && f.verify_cli.length) {
      card.appendChild(h4("Verify CLI", "var(--ok)"));
      card.appendChild(codeBlock(f.verify_cli.join("\n"), { lang: r.platform || "" }));
    }
    fWrap.appendChild(card);
  });

  // ── Wire "Copy All Patches" button (new) ───────────────────────────────
  const copyAllBtn = $("opt-copy-all-btn");
  if (copyAllBtn) {
    const allPatches = (r.findings || [])
      .filter((f) => f.patch && f.patch.length)
      .map((f, idx) => `# ── ${idx + 1}. ${f.title || "Finding"} ──\n${f.patch.join("\n")}`)
      .join("\n\n");
    copyAllBtn.disabled = !allPatches;
    copyAllBtn.onclick = async () => {
      if (!allPatches) return;
      try {
        await navigator.clipboard.writeText(allPatches);
        flashCopied(copyAllBtn, "✅ Copied!");
        toast("All patches copied to clipboard.", "success");
      } catch (e) { toast("Copy failed: " + e.message, "error"); }
    };
  }

  const monUl = $("opt-monitoring");
  monUl.className = "monitoring-gaps-list";
  clear(monUl);
  (r.monitoring_gaps || []).forEach((m) => {
    monUl.appendChild(el("li", { className: "monitoring-gap", text: m }));
  });
}

// ── Last site analysis result (for report exports) ────────────────────────────
let lastSiteResult = null;

// ── Topology rendering (D3 force-directed, animated) ─────────────────────────
async function renderTopology(siteId) {
  setStatus(`Topology: building graph for ${siteId.toUpperCase()}…`);
  $("topo-panel").style.display = "block";
  let topo;
  try {
    topo = await fetchJSON("/api/topology/" + encodeURIComponent(siteId));
  } catch (e) {
    setStatus("Topology error: " + e.message);
    return;
  }
  // Apply finding overlay if we have a recent site analysis for this site
  if (lastSiteResult && lastSiteResult.site_id && lastSiteResult.site_id.toLowerCase() === siteId.toLowerCase()) {
    const findings = lastSiteResult.cross_device_findings || [];
    const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, "": 0 };
    topo.nodes.forEach((n) => {
      let worst = "";
      findings.forEach((f) => {
        const aff = f.affected_devices || [];
        if (aff.includes(n.id)) {
          const s = (f.severity || "").toLowerCase();
          if ((sevOrder[s] || 0) > (sevOrder[worst] || 0)) worst = s;
        }
      });
      n.finding_severity = worst;
    });
  }
  drawD3Topology(topo);
  setStatus(`Topology: ${topo.nodes.length} nodes / ${topo.edges.length} edges`);
}

function drawD3Topology(topo) {
  if (typeof d3 === "undefined") {
    setStatus("D3 not loaded — refresh the page.");
    return;
  }
  const svg = d3.select("#topo-svg");
  svg.selectAll("*").remove();
  const width = svg.node().clientWidth || 800;
  const height = +svg.attr("height");

  const nodes = topo.nodes.map((n) => Object.assign({}, n));
  const links = topo.edges.map((e) => ({ source: e.source, target: e.target, label: e.label, kind: e.kind }));

  const sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id((d) => d.id).distance(110).strength(0.5))
    .force("charge", d3.forceManyBody().strength(-380))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(40));

  const g = svg.append("g");

  // Pan + zoom
  svg.call(d3.zoom().scaleExtent([0.3, 3]).on("zoom", (event) => g.attr("transform", event.transform)));

  // Links
  const link = g.append("g").selectAll("line").data(links).enter()
    .append("line").attr("class", "topo-link");

  // Nodes (g per node — for circle + label)
  const node = g.append("g").selectAll("g.node").data(nodes).enter()
    .append("g").attr("class", "node").call(
      d3.drag()
        .on("start", (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag",  (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on("end",   (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
    );

  function fillFor(d) {
    if (d.finding_severity === "critical") return "#f85149";
    if (d.finding_severity === "high")     return "#ff7b72";
    if (d.finding_severity === "medium")   return "#d29922";
    if (d.role === "firewall") return "#bc8cff";
    if (d.role === "router")   return "#58a6ff";
    if (d.role === "switch")   return "#3fb950";
    return "#8b949e";
  }
  function classFor(d) {
    if (d.finding_severity === "critical") return "node-critical";
    if (d.finding_severity === "high")     return "node-high";
    return "";
  }

  // Richer native tooltip: hostname · role · platform · protocols · finding sev.
  function nodeTooltip(d) {
    const protos = [];
    if (d.has_bgp)    protos.push("BGP");
    if (d.has_evpn)   protos.push("EVPN");
    if (d.has_vxlan)  protos.push("VXLAN");
    if (d.isp_uplink) protos.push("ISP-uplink");
    const lines = [
      `${d.id}`,
      `Role: ${d.role || "?"}`,
      d.platform ? `Platform: ${d.platform}` : null,
      protos.length ? `Protocols: ${protos.join(", ")}` : null,
      d.finding_severity ? `Finding: ${d.finding_severity.toUpperCase()}` : null,
      "(drag to move · scroll to zoom)",
    ].filter(Boolean);
    return lines.join("\n");
  }

  node.append("circle")
    .attr("r", 16)
    .attr("fill", fillFor)
    .attr("stroke", "#0d1117").attr("stroke-width", 2)
    .attr("class", classFor)
    .append("title").text(nodeTooltip);

  // Role glyph inside circle
  node.append("text").attr("class", "topo-role")
    .attr("text-anchor", "middle").attr("dy", 3)
    .text((d) => {
      if (d.role === "firewall") return "FW";
      if (d.role === "router")   return "RT";
      if (d.role === "switch")   return "SW";
      return "?";
    });

  // Label below
  node.append("text").attr("class", "topo-label")
    .attr("text-anchor", "middle").attr("dy", 30)
    .text((d) => d.id);

  // Tag pills (BGP/EVPN/ISP)
  node.append("text").attr("class", "topo-role").attr("text-anchor", "middle").attr("dy", 44)
    .text((d) => {
      const t = [];
      if (d.has_bgp)    t.push("BGP");
      if (d.has_evpn)   t.push("EVPN");
      if (d.has_vxlan)  t.push("VXLAN");
      if (d.isp_uplink) t.push("ISP");
      return t.join(" · ");
    });

  sim.on("tick", () => {
    link
      .attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
    node.attr("transform", (d) => `translate(${d.x},${d.y})`);
  });
}

// Flash a button to ✅ Copied! for 1.5s, then restore.
function flashCopied(btn, label) {
  if (!btn) return;
  const orig = btn.dataset.origLabel || btn.textContent;
  btn.dataset.origLabel = orig;
  btn.textContent = label || "✅ Copied!";
  btn.classList.add("copied");
  clearTimeout(btn._flashT);
  btn._flashT = setTimeout(() => {
    btn.textContent = btn.dataset.origLabel;
    btn.classList.remove("copied");
  }, 1500);
}

async function exportMermaid() {
  const id = $("site-picker").value;
  if (!id) { toast("Pick a site first.", "error"); return; }
  const btn = $("export-mermaid");
  try {
    const r = await fetch("/api/topology/" + encodeURIComponent(id) + "?format=mermaid");
    const t = await r.text();
    await navigator.clipboard.writeText(t);
    flashCopied(btn, "✅ Copied!");
    toast("Mermaid diagram copied to clipboard.", "success");
  } catch (e) { toast("Copy failed: " + e.message, "error"); }
}

async function exportDot() {
  const id = $("site-picker").value;
  if (!id) { toast("Pick a site first.", "error"); return; }
  const btn = $("export-dot");
  try {
    const r = await fetch("/api/topology/" + encodeURIComponent(id) + "?format=dot");
    const t = await r.text();
    await navigator.clipboard.writeText(t);
    flashCopied(btn, "✅ Copied!");
    toast("Graphviz DOT copied to clipboard.", "success");
  } catch (e) { toast("Copy failed: " + e.message, "error"); }
}

// ── Compliance ───────────────────────────────────────────────────────────────
async function runCompliance() {
  const id = $("site-picker").value;
  if (!id) { setStatus("Pick a site first."); return; }
  setStatus(`Compliance: running checks on ${id.toUpperCase()}…`);
  $("compliance-panel").style.display = "block";
  try {
    const r = await fetchJSON("/api/compliance/" + encodeURIComponent(id));
    $("comp-summary").textContent =
      `${r.passed}/${r.total_checks} checks passed (${r.pass_rate}%) — ${r.failed} failures`;
    const wrap = $("comp-rules"); clear(wrap);
    (r.rules || []).forEach((rule) => {
      const pct = rule.pass + rule.fail ? Math.round(100 * rule.pass / (rule.pass + rule.fail)) : 0;
      const card = el("div", { className: "finding" },
        el("div", {},
          sevBadge(rule.severity),
          " ",
          el("strong", { text: rule.rule_name }),
          el("span", { className: "row-msg", style: { float: "right" }, text: `${rule.pass} pass / ${rule.fail} fail (${pct}%)` }),
        ),
        el("div", { className: "row-msg", style: { marginTop: "4px" }, text: rule.description }),
      );
      if (rule.failing_devices && rule.failing_devices.length) {
        const ul = el("ul", { style: { marginTop: "6px" } });
        rule.failing_devices.forEach((fd) => {
          ul.appendChild(el("li", {},
            el("strong", { text: fd.device }),
            " — ",
            el("span", { className: "row-msg", text: fd.reason }),
          ));
        });
        card.appendChild(ul);
      }
      wrap.appendChild(card);
    });
    setStatus(`Compliance: ${r.failed} failures across ${r.total_checks} checks.`);
  } catch (e) {
    setStatus("Compliance error: " + e.message);
  }
}

// ── Copilot ──────────────────────────────────────────────────────────────────
async function askCopilot() {
  const q = $("copilot-q").value.trim();
  if (!q) { toast("Copilot: type a question first.", "error"); return; }
  const id = $("site-picker").value;
  if (!id) { toast("Copilot: pick a site under 🌐 Site first.", "error"); return; }
  const btn = $("copilot-btn");
  btn.disabled = true; btn.setAttribute("aria-busy", "true");
  setStatus(`Copilot: asking…`);
  $("copilot-panel").style.display = "block";
  $("copilot-answer").textContent = "Thinking…";
  const clearProgress = showPanelProgress("copilot-panel", "Asking copilot");
  try {
    const r = await fetchJSON("/api/copilot", {
      method: "POST",
      body: JSON.stringify({ question: q, site_id: id }),
    });
    $("copilot-answer").textContent = r.answer || "(no answer)";
    $("copilot-engine").textContent = r.llm_powered ? "LLM" : "OFF";
    $("copilot-engine").className = "ai-badge " + (r.llm_powered ? "" : "kb-badge");
    setStatus(`Copilot: done.`);
    toast("Copilot replied.", "success");
  } catch (e) {
    setStatus("Copilot error: " + e.message);
    toast("Copilot error: " + e.message, "error", 6000);
    $("copilot-answer").textContent = "Error: " + e.message;
  } finally {
    clearProgress();
    btn.disabled = false; btn.removeAttribute("aria-busy");
  }
}

// ── Post-mortem search ───────────────────────────────────────────────────────
async function postMortem() {
  const pattern = $("pm-pattern").value.trim();
  const id = $("site-picker").value;
  if (!pattern) { toast("Post-mortem: enter a pattern.", "error"); return; }
  if (!id)      { toast("Post-mortem: pick a site first.", "error"); return; }
  const btn = $("pm-btn");
  btn.disabled = true; btn.setAttribute("aria-busy", "true");
  setStatus(`Post-mortem: searching fleet for "${pattern}"…`);
  $("pm-panel").style.display = "block";
  const clearProgress = showPanelProgress("pm-panel", "Searching fleet");
  try {
    const r = await fetchJSON("/api/postmortem/" + encodeURIComponent(id), {
      method: "POST",
      body: JSON.stringify({ pattern }),
    });
    $("pm-summary").textContent =
      `Pattern "${r.pattern}" — ${r.devices_with_matches}/${r.total_devices_checked} devices, ${r.total_matches} total hits`;
    const wrap = $("pm-results"); clear(wrap);
    (r.matches || []).forEach((m) => {
      const card = el("div", { className: "finding" },
        el("div", {},
          el("strong", { text: m.device }),
          " ",
          el("span", { className: "row-msg", text: `[${m.platform}] · ${m.match_count} matches` }),
        ),
      );
      (m.snippets || []).forEach((s) => {
        card.appendChild(el("pre", { text: s }));
      });
      wrap.appendChild(card);
    });
    setStatus(`Post-mortem: ${r.devices_with_matches}/${r.total_devices_checked} devices matched.`);
    toast(`Found matches on ${r.devices_with_matches}/${r.total_devices_checked} devices.`, "success");
  } catch (e) {
    setStatus("Post-mortem error: " + e.message);
    toast("Post-mortem error: " + e.message, "error", 6000);
  } finally {
    clearProgress();
    const btn = $("pm-btn");
    btn.disabled = false; btn.removeAttribute("aria-busy");
  }
}

// ── Site-Wide Strategic Optimization ────────────────────────────────────────
async function runSiteWideOptimize() {
  const id = $("site-picker").value;
  if (!id) { toast("Pick a site first.", "error"); return; }
  const btn = $("site-wide-btn");
  btn.disabled = true; btn.setAttribute("aria-busy", "true");
  setStatus(`Site-Wide Optimization: analyzing ${id.toUpperCase()}…`);
  $("site-wide-panel").style.display = "block";
  $("site-wide-summary").textContent = "Running strategic analysis…";
  clear($("site-wide-score-row"));
  clear($("site-wide-gaps"));
  clear($("site-wide-bp-applied"));
  clear($("site-wide-roadmap"));
  const clearProgress = showPanelProgress("site-wide-panel", "Strategic optimization");
  try {
    const r = await fetchJSON(`/api/optimize/site-wide/${encodeURIComponent(id)}`, {
      method: "POST", body: JSON.stringify({}),
    });
    renderSiteWide(r);
    const n = (r.gaps || []).length;
    setStatus(`Site-Wide Optimization: ${n} gaps · maturity ${r.maturity_score || 0}/100`);
    toast(`Strategic analysis complete — ${n} gaps, maturity ${r.maturity_score || 0}/100.`, "success");
  } catch (e) {
    $("site-wide-summary").textContent = "Error: " + e.message;
    setStatus(`Site-Wide error: ${e.message}`);
    toast("Site-wide error: " + e.message, "error", 6000);
  } finally {
    clearProgress();
    btn.disabled = false; btn.removeAttribute("aria-busy");
  }
}

function renderSiteWide(r) {
  $("site-wide-engine").textContent = r.llm_powered ? "LLM" : "OFF";
  $("site-wide-engine").className = "ai-badge " + (r.llm_powered ? "" : "kb-badge");
  $("site-wide-summary").textContent = r.site_summary || "";

  // Score / tier row
  const row = $("site-wide-score-row");
  clear(row);
  const score = r.maturity_score || 0;
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  row.appendChild(el("div", { style: { textAlign: "center" } },
    el("div", { className: "score-num grade-" + grade, text: String(score) }),
    el("div", { style: { color: "var(--muted)", fontSize: "12px" }, text: "Maturity / 100" }),
  ));
  row.appendChild(el("div", { style: { textAlign: "center", flex: "1" } },
    el("div", { style: { fontSize: "22px", fontWeight: "700" }, text: r.maturity_tier || "—" }),
    el("div", { style: { color: "var(--muted)", fontSize: "12px" }, text: "Tier classification" }),
  ));
  if (r.facts) {
    row.appendChild(el("div", { style: { textAlign: "center", flex: "1" } },
      el("div", { style: { fontSize: "22px", fontWeight: "700" }, text: String(r.facts.device_count) }),
      el("div", { style: { color: "var(--muted)", fontSize: "12px" }, text: "Devices" }),
    ));
    row.appendChild(el("div", { style: { textAlign: "center", flex: "1" } },
      el("div", { style: { fontSize: "22px", fontWeight: "700" }, text: String(r.facts.isp_count_active) }),
      el("div", { style: { color: "var(--muted)", fontSize: "12px" }, text: "Active ISPs" }),
    ));
  }

  // Gaps
  const gapsWrap = $("site-wide-gaps");
  clear(gapsWrap);
  if (!r.gaps || !r.gaps.length) {
    gapsWrap.appendChild(el("div", { className: "row-msg", text: "No strategic gaps identified." }));
  }
  (r.gaps || []).forEach((g, idx) => {
    const card = el("div", { className: "finding" });
    const head = el("div", {},
      sevBadge(g.severity || "medium"),
      " ",
      el("strong", { text: `${idx + 1}. ${g.title || "(no title)"}` }),
      " — ",
      el("span", { className: "row-msg", text: g.category || "" }),
      el("span", { className: "row-msg", style: { float: "right" },
        text: `effort: ${g.estimated_effort || "?"} · ROI: ${g.roi || "?"}` }),
    );
    card.appendChild(head);
    if (g.current_state) {
      card.appendChild(el("div", { style: { marginTop: "8px" } },
        el("strong", { text: "Now: " }),
        el("span", { className: "row-msg", text: g.current_state })));
    }
    if (g.ideal_state) {
      card.appendChild(el("div", {},
        el("strong", { text: "Target: " }),
        el("span", { className: "row-msg", text: g.ideal_state })));
    }
    if (g.rationale) {
      card.appendChild(el("div", { style: { margin: "6px 0", fontSize: "12px" }, text: g.rationale }));
    }
    if (Array.isArray(g.implementation) && g.implementation.length) {
      card.appendChild(el("h4", { text: "Implementation Steps",
        style: { fontSize: "11px", color: "var(--muted)", marginTop: "8px" } }));
      const ol = el("ol");
      g.implementation.forEach((s) => ol.appendChild(el("li", { text: s })));
      card.appendChild(ol);
    }
    if (g.config_changes && typeof g.config_changes === "object") {
      Object.entries(g.config_changes).forEach(([host, cmds]) => {
        if (!Array.isArray(cmds) || !cmds.length) return;
        card.appendChild(el("h4", { text: `Config on ${host}`,
          style: { fontSize: "11px", color: "var(--muted)", marginTop: "8px" } }));
        card.appendChild(el("pre", { text: cmds.join("\n") }));
      });
    }
    gapsWrap.appendChild(card);
  });

  // Best practices applied
  const bpUl = $("site-wide-bp-applied");
  clear(bpUl);
  (r.best_practices_applied || []).forEach((b) =>
    bpUl.appendChild(el("li", { text: b })));
  if (!r.best_practices_applied || !r.best_practices_applied.length) {
    bpUl.appendChild(el("li", { className: "row-msg", text: "—" }));
  }

  // Raw LLM debug (only when parsing failed)
  if (r.raw) {
    const gapsWrap = $("site-wide-gaps");
    const det = el("details", { style: { marginTop: "12px" } });
    det.appendChild(el("summary", { text: `Show raw LLM response (${r.raw_length || r.raw.length} chars)` }));
    det.appendChild(el("pre", {
      text: r.raw,
      style: { whiteSpace: "pre-wrap", maxHeight: "400px", overflow: "auto",
               fontSize: "11px", background: "var(--panel)", padding: "8px" },
    }));
    gapsWrap.appendChild(det);
  }

  // Roadmap
  const rm = $("site-wide-roadmap");
  clear(rm);
  const phaseTitles = {
    phase_1_immediate_0_30_days: "Phase 1 — Immediate (0-30 days)",
    phase_2_short_term_30_90_days: "Phase 2 — Short-term (30-90 days)",
    phase_3_medium_term_90_180_days: "Phase 3 — Medium-term (90-180 days)",
    phase_4_long_term_6_12_months: "Phase 4 — Long-term (6-12 months)",
  };
  Object.entries(r.roadmap || {}).forEach(([k, items]) => {
    const title = phaseTitles[k] || k.replace(/_/g, " ");
    const card = el("div", { className: "finding" },
      el("strong", { text: title }),
    );
    if (Array.isArray(items) && items.length) {
      const ul = el("ul");
      items.forEach((it) => ul.appendChild(el("li", { text: it })));
      card.appendChild(ul);
    } else {
      card.appendChild(el("div", { className: "row-msg", text: "—" }));
    }
    rm.appendChild(card);
  });
}

// ── Comprehensive site documentation ────────────────────────────────────────
async function downloadSiteDoc(fmt) {
  const id = $("site-picker").value;
  if (!id) { setStatus("Pick a site first."); return; }
  setStatus(`Site Doc: generating ${fmt.toUpperCase()} for ${id.toUpperCase()}…`);
  try {
    const resp = await fetch(`/api/sitedoc/${encodeURIComponent(id)}?format=${fmt}`);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    const blob = await resp.blob();
    const ext = { md: "md", html: "html", pdf: "pdf" }[fmt] || "txt";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${id}-site-doc.${ext}`; a.click();
    URL.revokeObjectURL(url);
    setStatus(`Site Doc: downloaded ${id}-site-doc.${ext}`);
  } catch (e) {
    setStatus(`Site Doc error: ${e.message}`);
  }
}

// ── Report exports ───────────────────────────────────────────────────────────
async function exportReport(fmt) {
  if (!lastSiteResult) { setStatus("Run site analysis first."); return; }
  const id = $("site-picker").value || (lastSiteResult.site_id || "site").toLowerCase();
  setStatus(`Exporting ${fmt.toUpperCase()}…`);
  try {
    const resp = await fetch("/api/report/" + encodeURIComponent(id), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: fmt, analysis_result: lastSiteResult }),
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    const blob = await resp.blob();
    const ext = { md: "md", html: "html", csv: "csv", pdf: "pdf" }[fmt] || "txt";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${id}-report.${ext}`; a.click();
    URL.revokeObjectURL(url);
    setStatus(`Exported ${id}-report.${ext}`);
  } catch (e) {
    setStatus(`Export error: ${e.message}`);
  }
}

// Hook into renderSiteAnalysis to remember the last result
const _origRenderSite = renderSiteAnalysis;
renderSiteAnalysis = function (r) {
  lastSiteResult = r;
  _origRenderSite(r);
};

// ── Sidebar tab switching (ARIA-correct) ────────────────────────────────────
function switchSideTab(name) {
  document.querySelectorAll(".side-tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", active ? "true" : "false");
    t.setAttribute("tabindex", active ? "0" : "-1");
  });
  document.querySelectorAll(".side-group").forEach((g) => {
    const active = g.dataset.tab === name;
    g.classList.toggle("active", active);
    // Keep hidden/inert in sync so screen readers + keyboard focus skip inactive panels.
    if (active) { g.removeAttribute("hidden"); g.removeAttribute("inert"); }
    else        { g.setAttribute("hidden", ""); g.setAttribute("inert", ""); }
  });
  // Reset both the page scroll and the sidebar's internal scroll — avoids
  // landing on a tab at a confusing scroll position from the previous one.
  window.scrollTo({ top: 0, behavior: "smooth" });
  const aside = document.querySelector("aside");
  if (aside) aside.scrollTop = 0;
  // Recheck overflow class after the new tab's content settles — different
  // tabs have different sidebar heights (SITE is taller because of more
  // collapsible sections).
  setTimeout(() => {
    if (!aside) return;
    const overflowing = aside.scrollHeight > aside.clientHeight + 4;
    const scrolledToBottom = aside.scrollTop + aside.clientHeight >= aside.scrollHeight - 4;
    aside.classList.toggle("has-overflow", overflowing && !scrolledToBottom);
  }, 120);
}

// Hide the welcome/idle panel once any analytical panel appears. Observed via
// the same display change every renderer already does.
function hideIdleStateIfAnyPanelVisible() {
  const watch = ["health-panel", "summary-panel", "actions-panel", "optimize-panel",
                  "site-panel", "topo-panel", "compliance-panel", "copilot-panel",
                  "pm-panel", "site-wide-panel"];
  const anyVisible = watch.some((id) => {
    const el = $(id);
    return el && el.style.display !== "none" && el.style.display !== "";
  });
  const idle = $("idle-state");
  if (idle) idle.style.display = anyVisible ? "none" : "block";
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Sidebar tabs
  document.querySelectorAll(".side-tab").forEach((tab) => {
    tab.addEventListener("click", () => switchSideTab(tab.dataset.tab));
  });
  // Run-button running animation + idle hide
  const _origSetStatus = setStatus;
  // Periodically check if any panel surfaced and hide idle state accordingly
  setInterval(hideIdleStateIfAnyPanelVisible, 1000);

  $("source").addEventListener("change", showSourceControls);
  $("provider").addEventListener("change", changeProvider);
  $("run-btn").addEventListener("click", runAnalysis);
  $("opt-btn").addEventListener("click", runOptimize);
  $("sample-opt-btn").addEventListener("click", runSampleOptimize);
  $("sample-picker").addEventListener("change", showSampleMeta);
  $("site-opt-btn").addEventListener("click", runSiteOptimize);
  $("site-picker").addEventListener("change", showSiteMeta);
  $("reload-containers").addEventListener("click", loadContainers);
  // All/None bulk-toggle (previously dead handlers — the IDs existed in HTML
  // but no JS was wired, so clicking "All" only highlighted the button itself).
  const _allBtn = $("chips-all");
  const _noneBtn = $("chips-none");
  if (_allBtn)  _allBtn.addEventListener("click",  () => setAllChips(true));
  if (_noneBtn) _noneBtn.addEventListener("click", () => setAllChips(false));
  // New batch
  $("topo-btn").addEventListener("click", () => {
    const id = $("site-picker").value; if (!id) { setStatus("Pick a site first."); return; }
    renderTopology(id);
  });
  $("comply-btn").addEventListener("click", runCompliance);
  $("copilot-btn").addEventListener("click", askCopilot);
  $("pm-btn").addEventListener("click", postMortem);
  $("export-mermaid").addEventListener("click", exportMermaid);
  $("export-dot").addEventListener("click", exportDot);
  $("rep-md-btn").addEventListener("click",   () => exportReport("md"));
  $("rep-html-btn").addEventListener("click", () => exportReport("html"));
  $("rep-csv-btn").addEventListener("click",  () => exportReport("csv"));
  $("rep-pdf-btn").addEventListener("click",  () => exportReport("pdf"));
  $("sitedoc-md-btn").addEventListener("click",   () => downloadSiteDoc("md"));
  $("sitedoc-html-btn").addEventListener("click", () => downloadSiteDoc("html"));
  $("sitedoc-pdf-btn").addEventListener("click",  () => downloadSiteDoc("pdf"));
  $("site-wide-btn").addEventListener("click", runSiteWideOptimize);
  loadSamples();
  loadSites();
  $("use-llm").addEventListener("change", async (e) => {
    await fetchJSON("/api/llm/toggle", {
      method: "POST", body: JSON.stringify({ enabled: e.target.checked }),
    });
    refreshLLMStatus();
  });
  showSourceControls();
  loadContainers();
  refreshLLMStatus();
  refreshNetToolStatus();
  refreshRecentPathsDatalist();   // hydrate File Path autocomplete from localStorage

  // Sidebar overflow detection — toggles the bottom-fade scroll hint when the
  // sidebar has content below the visible area (typically on short viewports).
  const _aside = document.querySelector("main > aside");
  if (_aside) {
    const _updateOverflow = () => {
      const overflowing = _aside.scrollHeight > _aside.clientHeight + 4;
      const scrolledToBottom = _aside.scrollTop + _aside.clientHeight >= _aside.scrollHeight - 4;
      _aside.classList.toggle("has-overflow", overflowing && !scrolledToBottom);
    };
    _aside.addEventListener("scroll", _updateOverflow, { passive: true });
    window.addEventListener("resize",  _updateOverflow);
    // Re-check when collapsible sections toggle (height changes).
    document.querySelectorAll(".side-section").forEach((s) =>
      s.addEventListener("toggle", _updateOverflow)
    );
    // Initial + delayed run (containers/sites may inflate the sidebar async).
    _updateOverflow();
    setTimeout(_updateOverflow, 500);
    setTimeout(_updateOverflow, 2000);
  }
  // Polling — bumped from 15s to 30s to reduce server chatter.
  // (Health/Status are cheap reads, but a tool sitting idle shouldn't poll every 15s.)
  setInterval(refreshLLMStatus,     30000);
  setInterval(refreshNetToolStatus, 30000);

  // ── Keyboard shortcuts ────────────────────────────────────────────────────
  // 1/2/3 → switch sidebar tab (when not typing in an input).
  // Ctrl/Cmd+Enter → Run Analysis (global), or submit Copilot from textarea,
  // or submit Post-Mortem from input. Enter in pm-pattern also submits.
  document.addEventListener("keydown", (ev) => {
    const tag = (ev.target.tagName || "").toLowerCase();
    const inEditable = tag === "input" || tag === "textarea" || tag === "select" ||
                       ev.target.isContentEditable;
    const cmd = ev.ctrlKey || ev.metaKey;

    // Plain Enter in the Post-Mortem pattern field submits the search.
    if (!ev.shiftKey && !cmd && ev.key === "Enter" && ev.target.id === "pm-pattern") {
      ev.preventDefault();
      $("pm-btn").click();
      return;
    }

    if (cmd && ev.key === "Enter") {
      ev.preventDefault();
      if (ev.target.id === "copilot-q") {
        $("copilot-btn").click();
      } else if (ev.target.id === "pm-pattern") {
        $("pm-btn").click();
      } else {
        // Global: trigger Run Analysis when on Logs tab; SITE → Analyze Whole Site.
        const activeTab = document.querySelector(".side-tab.active")?.dataset.tab;
        if (activeTab === "site")        $("site-opt-btn").click();
        else if (activeTab === "device") $("opt-btn").click();
        else                              $("run-btn").click();
      }
      return;
    }

    // Number keys 1/2/3 switch tabs (only outside editable controls).
    if (!cmd && !ev.shiftKey && !ev.altKey && !inEditable && ["1","2","3"].includes(ev.key)) {
      const map = { "1": "logs", "2": "device", "3": "site" };
      switchSideTab(map[ev.key]);
      ev.preventDefault();
    }

    // Escape closes the most recent toast (if any).
    if (ev.key === "Escape" && !inEditable) {
      const last = document.querySelector("#toast-stack .toast:last-child .toast-close");
      if (last) last.click();
    }
  });
});
