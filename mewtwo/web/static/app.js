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
  const corners = `<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>`;
  $("stats").innerHTML = "";
  for (const card of cards) {
    const d = el("div", "stat card blueprint" + (card.hot ? " hot" : ""));
    d.innerHTML = corners +
      `<div class="n">${card.n}</div><div class="l">${card.l}</div>` +
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
  return `<table class="table"><thead>${thead}</thead><tbody>${rows.join("")}</tbody></table>`;
}

function sevPill(sev) { return `<span class="tag sev-${esc(sev)}">${esc(sev)}</span>`; }

const _bp = `<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>`;

// Trigger a job from anywhere (overview steps, empty-state buttons).
function triggerJob(kind) {
  if (kind === "recon") return startJob("/api/jobs/recon",
    { passive_only: $("recon-passive").checked, force: $("recon-force").checked });
  if (kind === "surface") return startJob("/api/jobs/surface", {});
  if (kind === "hunt") {
    const checked = document.querySelector('input[name="tier"]:checked');
    const tier = checked ? checked.value : "normal";
    if (tier === "aggressive" && !confirm("Aggressive tier sends destructive/noisy payloads. Only run against authorised targets. Continue?")) return;
    return startJob("/api/jobs/hunt", { tier, rate: parseFloat($("hunt-rate").value) || 0,
      enforce_scope: $("hunt-scope").checked, use_auth: $("hunt-auth").checked });
  }
}

// A friendly empty state with an optional action (job to run or tab to open).
function emptyState(msg, action) {
  const btn = action
    ? `<button class="btn btn-primary" data-act-job="${action.job || ""}" data-act-tab="${action.tab || ""}">${esc(action.label)}</button>`
    : "";
  return `<div class="empty-state card blueprint">${_bp}<p>${esc(msg)}</p>${btn}</div>`;
}

function wireActions(panel) {
  panel.querySelectorAll("[data-act-job]").forEach((b) => {
    const job = b.getAttribute("data-act-job");
    const tab = b.getAttribute("data-act-tab");
    b.addEventListener("click", () => {
      if (job) triggerJob(job);
      else if (tab) loadTab(tab);
    });
  });
}

async function renderOverview(panel) {
  const [status, findings, scope] = await Promise.all([
    api("/api/status"), api("/api/findings"), api("/api/scope").catch(() => []),
  ]);
  STATE.cache.findings = findings;
  const c = status.counts;
  const inScope = scope.filter((s) => s.scope_type === "in_scope").length;

  // --- workflow progress ---
  const steps = [
    { label: "Define scope", done: inScope > 0, next: { tab: "scope", label: "Add scope" },
      detail: inScope ? `${inScope} in-scope pattern(s)` : "add in-scope patterns first" },
    { label: "Run recon", done: c.subdomains > 0 || c.urls > 0, next: { job: "recon", label: "Run recon" },
      detail: (c.subdomains || c.urls) ? `${c.subdomains} subdomains · ${c.urls} URLs` : "enumerate the target" },
    { label: "Map attack surface", done: c.vectors > 0, next: { job: "surface", label: "Map surface" },
      detail: c.vectors ? `${c.vectors} vectors (${c.vectors_checked} checked)` : "derive attack vectors from recon" },
    { label: "Hunt", done: c.findings > 0, next: { job: "hunt", label: "Run hunt" },
      detail: c.findings ? `${c.findings} findings` : "run vulnerability checks" },
  ];
  const nextIdx = steps.findIndex((s) => !s.done);
  const stepHtml = steps.map((s, i) => {
    const state = s.done ? "done" : (i === nextIdx ? "next" : "todo");
    const mark = s.done ? "✓" : String(i + 1);
    const act = state === "next"
      ? `<button class="btn btn-primary" data-act-job="${s.next.job || ""}" data-act-tab="${s.next.tab || ""}">${esc(s.next.label)}</button>`
      : "";
    return `<li class="step step-${state}"><span class="step-mark">${mark}</span>
      <div class="step-text"><div class="step-label">${esc(s.label)}</div>
      <div class="step-detail text-muted">${esc(s.detail)}</div></div>${act}</li>`;
  }).join("");
  const workflow = `<div class="card blueprint workflow">${_bp}
    <h6>Engagement workflow</h6><ol class="steps">${stepHtml}</ol></div>`;

  // --- severity breakdown + top findings (only when there are findings) ---
  let findingsBlock = "";
  if (findings.length) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    const counts = {};
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const chips = Object.keys(order).filter((s) => counts[s])
      .map((s) => `<span class="tag sev-${s}">${counts[s]} ${s}</span>`).join(" ");
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    const rows = findings.slice(0, 12).map((f) =>
      `<tr class="click" data-fid="${esc(f.id)}"><td>${sevPill(f.severity)}</td><td>${esc(f.title)}</td><td class="mono">${esc(f.vuln_class)}</td><td class="mono">${esc((f.url || "").slice(0, 50))}</td></tr>`);
    findingsBlock = `<div class="sev-summary">${chips}</div>
      <h6 class="section-label">Top findings</h6>` + table(["Severity", "Title", "Class", "URL"], rows);
  } else {
    const msg = nextIdx === -1 ? "No findings recorded."
      : "No findings yet — work through the steps above, then run a hunt.";
    findingsBlock = `<h6 class="section-label">Findings</h6>` + emptyState(msg,
      c.vectors > 0 ? { job: "hunt", label: "Run hunt" } : null);
  }

  panel.innerHTML = workflow + findingsBlock;
  wireActions(panel);
  wireFindingClicks(panel);
}

async function renderSubdomains(panel) {
  const subs = await api("/api/subdomains");
  subs.sort((a, b) => (b.is_alive - a.is_alive) || a.hostname.localeCompare(b.hostname));
  if (!subs.length) { panel.innerHTML = emptyState("No subdomains yet. Run recon to enumerate the target.", { job: "recon", label: "Run recon" }); return wireActions(panel); }
  const rows = subs.map((s) =>
    `<tr><td class="mono">${esc(s.hostname)}</td><td>${s.is_alive ? '<span class="yes">● alive</span>' : '<span class="no">○</span>'}</td><td class="mono">${esc(s.status_code ?? "—")}</td></tr>`);
  panel.innerHTML = table(["Hostname", "Alive", "Status"], rows);
}

async function renderUrls(panel) {
  const urls = await api("/api/urls");
  if (!urls.length) { panel.innerHTML = emptyState("No URLs yet. Recon crawls the target and harvests historical URLs.", { job: "recon", label: "Run recon" }); return wireActions(panel); }
  const rows = urls.map((u) =>
    `<tr><td class="mono">${esc((u.url || "").slice(0, 80))}</td><td class="mono">${esc(u.status_code ?? "—")}</td><td class="mono">${esc((u.params || []).join(", "))}</td></tr>`);
  panel.innerHTML = table(["URL", "Status", "Params"], rows);
}

async function renderVectors(panel) {
  const vectors = await api("/api/vectors");
  if (!vectors.length) { panel.innerHTML = emptyState("No attack vectors yet. Map the surface to derive them from recon data.", { job: "surface", label: "Map surface" }); return wireActions(panel); }
  const riskClass = (r) => (r === "critical" ? "sev-critical" : r === "high" ? "sev-high" : r === "low" ? "sev-low" : "sev-medium");
  const rows = vectors.map((v) =>
    `<tr><td><span class="tag ${riskClass(v.risk_rating)}">${esc(v.risk_rating)}</span></td><td class="mono">${esc(v.category)}</td><td>${esc(v.title)}</td><td>${v.checked ? '<span class="yes">✓</span>' : '<span class="no">○</span>'}</td></tr>`);
  panel.innerHTML = table(["Risk", "Category", "Title", "Checked"], rows);
}

async function renderFindings(panel) {
  const findings = await api("/api/findings");
  STATE.cache.findings = findings;
  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  if (!findings.length) { panel.innerHTML = emptyState("No findings yet. Run a hunt against your mapped attack surface.", { job: "hunt", label: "Run hunt" }); return wireActions(panel); }
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
    const tagClass = t === "in" ? "sev-low" : t === "out" ? "sev-critical" : "sev-informational";
    return `<tr><td class="mono">${esc(e.pattern)}</td><td><span class="tag ${tagClass}">${t}</span></td><td>${esc(e.notes || "")}</td><td><button class="btn btn-ghost" data-del="${esc(e.pattern)}">remove</button></td></tr>`;
  });
  panel.innerHTML = `
    <div class="scope-add">
      <input class="input grow" id="scope-pattern" placeholder="*.example.com" aria-label="Scope pattern">
      <select class="input" id="scope-type" aria-label="Scope type" style="width:auto">
        <option value="in">in scope</option>
        <option value="out">out of scope</option>
        <option value="info">informational</option>
      </select>
      <button class="btn btn-primary" id="scope-add-btn">Add</button>
    </div>
    ${table(["Pattern", "Type", "Notes", ""], rows)}
    <p class="hint text-muted">In-scope patterns are enforced at request time during Hunt — out-of-scope hosts are blocked before any request is sent.</p>`;

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
  if (f.description) html += `<h6>Description</h6><p>${esc(f.description)}</p>`;
  if (f.impact) html += `<h6>Impact</h6><p>${esc(f.impact)}</p>`;
  if (Array.isArray(f.reproduction_steps) && f.reproduction_steps.length)
    html += `<h6>Reproduction</h6><ol>${f.reproduction_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>`;
  if (Array.isArray(f.evidence) && f.evidence.length) {
    html += `<h6>Evidence</h6>`;
    for (const ev of f.evidence) html += `<pre>${esc(typeof ev === "string" ? ev : (ev.content || JSON.stringify(ev)))}</pre>`;
  }
  if (f.remediation) html += `<h6>Remediation</h6><p>${esc(f.remediation)}</p>`;
  if (Array.isArray(f.references) && f.references.length)
    html += `<h6>References</h6>` + f.references.map((r) => `<div class="mono">${esc(r)}</div>`).join("");
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
    <div class="onboard card blueprint">
      <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
      <div class="big"><svg class="icon" aria-hidden="true"><use href="#i-mark"/></svg></div>
      <h2>Welcome to Mewtwo</h2>
      <p>Create a workspace for your target to start recon, surface mapping, and hunting — all from here.</p>
      <button class="btn btn-primary" id="onboard-create">Create workspace</button>
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
    const checked = document.querySelector('input[name="tier"]:checked');
    const tier = checked ? checked.value : "normal";
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
