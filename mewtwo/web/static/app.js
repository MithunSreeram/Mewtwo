"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (e) {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, 3500);
}

// --------------------------------------------------------------- state
let STATE = { tab: "overview", cache: {} };

// --------------------------------------------------------------- stats + status
async function loadStatus() {
  let s;
  try { s = await api("/api/status"); }
  catch (e) {
    $("stats").innerHTML = "";
    $("target-line").innerHTML = `<span class="no">${esc(e.message)}</span>`;
    return;
  }
  const c = s.counts;
  const cards = [
    { l: "Subdomains", n: c.subdomains, sub: `${c.alive} alive` },
    { l: "URLs", n: c.urls },
    { l: "Attack Vectors", n: c.vectors, sub: `${c.vectors_checked} checked` },
    { l: "JS Secrets", n: c.js_secrets },
    { l: "Findings", n: c.findings, hot: c.findings > 0 },
  ];
  $("stats").innerHTML = "";
  for (const card of cards) {
    const d = el("div", "stat" + (card.hot ? " hot" : ""));
    d.innerHTML = `<div class="n">${card.n}</div><div class="l">${card.l}</div>` +
      (card.sub ? `<div class="sub">${card.sub}</div>` : "");
    $("stats").appendChild(d);
  }
  const t = s.target;
  $("target-line").innerHTML =
    `Target <b>${esc(t.name)}</b>` +
    (t.root_domain ? ` · <span class="mono">${esc(t.root_domain)}</span>` : "") +
    (t.platform ? ` · ${esc(t.platform)}` : "") +
    (t.program_url ? ` · <a href="${esc(t.program_url)}" target="_blank" rel="noopener">program</a>` : "");
}

// --------------------------------------------------------------- tabs
async function loadTab(tab) {
  STATE.tab = tab;
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const panel = $("panel");
  panel.innerHTML = `<div class="empty">loading…</div>`;
  try {
    if (tab === "overview") return renderOverview(panel);
    if (tab === "subdomains") return renderSubdomains(panel);
    if (tab === "urls") return renderUrls(panel);
    if (tab === "vectors") return renderVectors(panel);
    if (tab === "findings") return renderFindings(panel);
    if (tab === "scope") return renderScope(panel);
  } catch (e) {
    panel.innerHTML = `<div class="empty no">${esc(e.message)}</div>`;
  }
}

function table(headers, rows) {
  if (!rows.length) return `<div class="empty">Nothing here yet.</div>`;
  const thead = `<tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr>`;
  return `<table><thead>${thead}</thead><tbody>${rows.join("")}</tbody></table>`;
}

function sevPill(sev) { return `<span class="pill sev-${esc(sev)}">${esc(sev)}</span>`; }

async function renderOverview(panel) {
  const findings = await api("/api/findings");
  STATE.cache.findings = findings;
  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  const rows = findings.slice(0, 15).map((f) =>
    `<tr class="click" data-fid="${esc(f.id)}"><td>${sevPill(f.severity)}</td><td>${esc(f.title)}</td><td class="mono">${esc(f.vuln_class)}</td><td class="mono">${esc((f.url || "").slice(0, 50))}</td></tr>`);
  panel.innerHTML = `<h3 style="color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px">Top findings</h3>` +
    table(["Severity", "Title", "Class", "URL"], rows);
  wireFindingClicks(panel);
}

async function renderSubdomains(panel) {
  const subs = await api("/api/subdomains");
  subs.sort((a, b) => (b.is_alive - a.is_alive) || a.hostname.localeCompare(b.hostname));
  const rows = subs.map((s) =>
    `<tr><td class="mono">${esc(s.hostname)}</td><td>${s.is_alive ? '<span class="yes">● alive</span>' : '<span class="no">○</span>'}</td><td class="mono">${esc(s.status_code ?? "—")}</td></tr>`);
  panel.innerHTML = table(["Hostname", "Alive", "Status"], rows);
}

async function renderUrls(panel) {
  const urls = await api("/api/urls");
  const rows = urls.map((u) =>
    `<tr><td class="mono">${esc((u.url || "").slice(0, 80))}</td><td class="mono">${esc(u.status_code ?? "—")}</td><td class="mono">${esc((u.params || []).join(", "))}</td></tr>`);
  panel.innerHTML = table(["URL", "Status", "Params"], rows);
}

async function renderVectors(panel) {
  const vectors = await api("/api/vectors");
  const rows = vectors.map((v) =>
    `<tr><td><span class="pill sev-${v.risk_rating === 'critical' || v.risk_rating === 'high' ? 'high' : 'medium'}">${esc(v.risk_rating)}</span></td><td class="mono">${esc(v.category)}</td><td>${esc(v.title)}</td><td>${v.checked ? '<span class="yes">✓</span>' : '<span class="no">○</span>'}</td></tr>`);
  panel.innerHTML = table(["Risk", "Category", "Title", "Checked"], rows);
}

async function renderFindings(panel) {
  const findings = await api("/api/findings");
  STATE.cache.findings = findings;
  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  const rows = findings.map((f) =>
    `<tr class="click" data-fid="${esc(f.id)}"><td>${sevPill(f.severity)}</td><td>${esc(f.title)}</td><td class="mono">${esc(f.vuln_class)}</td><td class="mono">${esc(f.status)}</td></tr>`);
  panel.innerHTML = table(["Severity", "Title", "Class", "Status"], rows);
  wireFindingClicks(panel);
}

function wireFindingClicks(panel) {
  panel.querySelectorAll("tr.click").forEach((tr) => {
    tr.setAttribute("tabindex", "0");
    tr.setAttribute("role", "button");
    const open = () => openFinding(tr.dataset.fid);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  });
}

// --------------------------------------------------------------- scope manager
async function renderScope(panel) {
  const entries = await api("/api/scope");
  const typeLabel = { in_scope: "in", out_of_scope: "out", informational: "info" };
  const rows = entries.map((e) => {
    const t = typeLabel[e.scope_type] || e.scope_type;
    return `<tr><td class="mono">${esc(e.pattern)}</td><td class="scope-type-${t}">${t}</td><td>${esc(e.notes || "")}</td><td><button class="btn-mini" data-del="${esc(e.pattern)}">remove</button></td></tr>`;
  });
  panel.innerHTML = `
    <div class="scope-add">
      <input class="grow mono" id="scope-pattern" placeholder="*.example.com" aria-label="Scope pattern">
      <select id="scope-type" aria-label="Scope type">
        <option value="in">in scope</option>
        <option value="out">out of scope</option>
        <option value="info">informational</option>
      </select>
      <button class="btn" id="scope-add-btn">Add</button>
    </div>
    ${table(["Pattern", "Type", "Notes", ""], rows)}
    <p class="hint">In-scope patterns are enforced at request time during Hunt — out-of-scope hosts are blocked before any request is sent.</p>`;

  $("scope-add-btn").addEventListener("click", async () => {
    const pattern = $("scope-pattern").value.trim();
    if (!pattern) return toast("Enter a pattern", true);
    try {
      await api("/api/scope", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, scope_type: $("scope-type").value }) });
      toast(`added ${pattern}`); renderScope(panel);
    } catch (e) { toast(e.message, true); }
  });
  $("scope-pattern").addEventListener("keydown", (e) => { if (e.key === "Enter") $("scope-add-btn").click(); });
  panel.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    try {
      await api(`/api/scope?pattern=${encodeURIComponent(b.dataset.del)}`, { method: "DELETE" });
      toast(`removed ${b.dataset.del}`); renderScope(panel);
    } catch (e) { toast(e.message, true); }
  }));
}

// --------------------------------------------------------------- finding drawer
async function openFinding(id) {
  let f;
  try { f = await api(`/api/findings/${encodeURIComponent(id)}`); }
  catch (e) { return toast(e.message, true); }
  $("drawer-title").innerHTML = sevPill(f.severity) + " " + esc(f.title);
  const body = $("drawer-body");
  let html = `<div class="kv"><b>Class</b><span class="mono">${esc(f.vuln_class)}</span></div>`;
  html += `<div class="kv"><b>Status</b><span class="mono">${esc(f.status)}</span></div>`;
  if (f.url) html += `<div class="kv"><b>URL</b><span class="mono">${esc(f.url)}</span></div>`;
  if (f.parameter) html += `<div class="kv"><b>Parameter</b><span class="mono">${esc(f.parameter)}</span></div>`;
  if (f.description) html += `<h4>Description</h4><p>${esc(f.description)}</p>`;
  if (f.impact) html += `<h4>Impact</h4><p>${esc(f.impact)}</p>`;
  if (Array.isArray(f.reproduction_steps) && f.reproduction_steps.length)
    html += `<h4>Reproduction</h4><ol>${f.reproduction_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>`;
  if (Array.isArray(f.evidence) && f.evidence.length) {
    html += `<h4>Evidence</h4>`;
    for (const ev of f.evidence) html += `<pre>${esc(typeof ev === "string" ? ev : (ev.content || JSON.stringify(ev)))}</pre>`;
  }
  if (f.remediation) html += `<h4>Remediation</h4><p>${esc(f.remediation)}</p>`;
  if (Array.isArray(f.references) && f.references.length)
    html += `<h4>References</h4>` + f.references.map((r) => `<div class="mono">${esc(r)}</div>`).join("");
  body.innerHTML = html;
  $("drawer").hidden = false;
  $("drawer-backdrop").hidden = false;
}
function closeDrawer() { $("drawer").hidden = true; $("drawer-backdrop").hidden = true; }

// --------------------------------------------------------------- jobs
function setJobStatus(cls, text) {
  const s = $("job-status");
  s.className = "job-status " + cls;
  s.textContent = text;
  const running = cls === "running";
  ["btn-recon", "btn-surface", "btn-hunt"].forEach((id) => { $(id).disabled = running; });
}

async function startJob(path, bodyObj) {
  try {
    await api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(bodyObj || {}) });
  } catch (e) { toast(e.message, true); }
}

// --------------------------------------------------------------- live log + websocket
function logLine(cls, text) {
  const log = $("log");
  const ts = new Date().toLocaleTimeString();
  const line = el("div", "line");
  line.innerHTML = `<span class="t">${ts}</span> <span class="${cls}">${esc(text)}</span>`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
  while (log.children.length > 400) log.removeChild(log.firstChild);
}

function handleEvent(ev) {
  if (ev.type === "state") {
    if (ev.status === "running") setJobStatus("running", `running: ${ev.job}`);
    return;
  }
  if (ev.type === "job_start") { setJobStatus("running", `running: ${ev.job}`); logLine("ev-start", `▶ ${ev.job} started`); return; }
  if (ev.type === "job_done") {
    setJobStatus("done", `done: ${ev.job}`);
    logLine("ev-done", `✓ ${ev.job} done — ${JSON.stringify(ev.summary || {})}`);
    loadStatus(); loadTab(STATE.tab);
    return;
  }
  if (ev.type === "job_error") { setJobStatus("error", `error: ${ev.job}`); logLine("ev-error", `✗ ${ev.job}: ${ev.error}`); return; }
  if (ev.type === "progress") {
    if (ev.phase === "finding") {
      logLine("ev-finding", `  → [${(ev.severity || "").toUpperCase()}] ${ev.title}`);
      if (STATE.tab === "overview" || STATE.tab === "findings") loadStatus();
    } else if (ev.phase === "vector") {
      logLine("ev-phase", `• vector: ${ev.title}`);
    } else {
      logLine("ev-phase", `• ${ev.phase}: ${ev.count != null ? ev.count : (ev.detail || "")}`);
      loadStatus();
    }
  }
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => $("conn").classList.add("live");
  ws.onclose = () => { $("conn").classList.remove("live"); setTimeout(connectWS, 2000); };
  ws.onmessage = (m) => { try { handleEvent(JSON.parse(m.data)); } catch (e) {} };
}

// --------------------------------------------------------------- workspaces + boot
async function loadWorkspaces() {
  const list = await api("/api/workspaces");
  const sel = $("ws-select");
  sel.innerHTML = "";
  for (const w of list) {
    const o = el("option");
    o.value = w.slug;
    o.textContent = `${w.slug} (${w.findings})`;
    o.selected = w.active;
    sel.appendChild(o);
  }
  return list;
}

// --------------------------------------------------------------- workspace modal
let _lastFocus = null;
function openModal() {
  _lastFocus = document.activeElement;
  $("ws-modal").hidden = false;
  $("modal-backdrop").hidden = false;
  setTimeout(() => $("ws-name").focus(), 50);
}
function closeModal() {
  $("ws-modal").hidden = true;
  $("modal-backdrop").hidden = true;
  if (_lastFocus && _lastFocus.focus) _lastFocus.focus();
}
async function submitWorkspace(e) {
  e.preventDefault();
  const name = $("ws-name").value.trim();
  if (!name) return toast("Name is required", true);
  try {
    const r = await api("/api/workspaces", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name, domain: $("ws-domain").value.trim(),
        platform: $("ws-platform").value, program_url: $("ws-program").value.trim(),
      }),
    });
    closeModal();
    $("ws-form").reset();
    toast(r.created ? `created ${r.slug}` : `switched to ${r.slug}`);
    hideOnboarding();
    await loadWorkspaces();
    await loadStatus();
    await loadTab(STATE.tab === "scope" ? "scope" : "overview");
    if (r.created) toast("Next: add in-scope patterns in the Scope tab");
  } catch (err) { toast(err.message, true); }
}

// --------------------------------------------------------------- onboarding
function showOnboarding() {
  $("stats").innerHTML = "";
  $("target-line").innerHTML = "";
  $("tabs").style.display = "none";
  $("panel").innerHTML = `
    <div class="onboard">
      <div class="big">🧬</div>
      <h2>Welcome to Mewtwo</h2>
      <p>Create a workspace for your target to start recon, surface mapping, and hunting — all from here.</p>
      <button class="btn btn-accent" id="onboard-create">Create workspace</button>
    </div>`;
  $("onboard-create").addEventListener("click", openModal);
}
function hideOnboarding() { $("tabs").style.display = ""; }

async function loadHealth() {
  try {
    const h = await api("/api/health");
    $("badge-ai").classList.toggle("on", h.ai_configured);
    $("badge-auth").classList.toggle("on", h.auth_configured);
  } catch (e) {}
}

function wire() {
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => loadTab(b.dataset.tab)));
  $("ws-select").addEventListener("change", async (e) => {
    try { await api(`/api/workspaces/${encodeURIComponent(e.target.value)}/activate`, { method: "POST" }); }
    catch (err) { return toast(err.message, true); }
    await loadStatus(); await loadTab(STATE.tab); toast(`switched to ${e.target.value}`);
  });
  $("btn-recon").addEventListener("click", () => startJob("/api/jobs/recon", {
    passive_only: $("recon-passive").checked, force: $("recon-force").checked,
  }));
  $("btn-surface").addEventListener("click", () => startJob("/api/jobs/surface", {}));
  $("btn-hunt").addEventListener("click", () => {
    const tier = $("hunt-tier").value;
    if (tier === "aggressive" && !confirm("Aggressive tier sends destructive/noisy payloads. Only run against authorised targets. Continue?")) return;
    startJob("/api/jobs/hunt", {
      tier, rate: parseFloat($("hunt-rate").value) || 0,
      enforce_scope: $("hunt-scope").checked, use_auth: $("hunt-auth").checked,
    });
  });
  $("log-clear").addEventListener("click", () => { $("log").innerHTML = ""; });
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  // workspace modal
  $("btn-new-ws").addEventListener("click", openModal);
  $("ws-modal-close").addEventListener("click", closeModal);
  $("ws-cancel").addEventListener("click", closeModal);
  $("modal-backdrop").addEventListener("click", closeModal);
  $("ws-form").addEventListener("submit", submitWorkspace);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); closeModal(); }
  });
}

async function boot() {
  wire();
  connectWS();
  await loadHealth();
  const workspaces = await loadWorkspaces();
  if (!workspaces.length) {
    showOnboarding();
    return;
  }
  hideOnboarding();
  await loadStatus();
  await loadTab("overview");
  const js = await api("/api/jobs").catch(() => null);
  if (js && js.status === "running") setJobStatus("running", `running: ${js.job}`);
}

boot();
