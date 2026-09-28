const view = document.getElementById("view");
const titleEl = document.getElementById("pageTitle");
const drawer = document.getElementById("drawer");
let OVERVIEW = null;
let page = "dashboard";
let QUEUE = [];

const TITLES = {
  dashboard: "Supervisor console",
  radar: "Entity Radar — 8 NCIIPC capabilities",
  peers: "Peer benchmarking — sector Z-score",
  queue: "Review Queue — Top 100 (human decides)",
  negspace: "Negative Space — silence is risk",
  trends: "Trends — entities and time (this extract)",
  coverage: "PS 26157 illustrative use cases",
  workflow: "Air-gapped workflow — USB in, sealed pack out",
  audit: "Trust & Audit — SHA3-256 hash chain",
  validate: "Validation — planted signals vs engine",
  report: "Supervisory advisory draft",
};

function esc(s) {
  return String(s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error("API " + r.status);
  return r.json();
}
function kpi(v, l, s, c) {
  return `<div class="kpi" style="border-left-color:${c}"><b>${v}</b><span>${l}<br>${s}</span></div>`;
}
function tag(x) {
  return `<span class="tag ${x}">${x}</span>`;
}
function go(name, extra) {
  page = name;
  document.querySelectorAll("#nav button").forEach((x) => x.classList.toggle("on", x.dataset.view === name));
  titleEl.textContent = TITLES[name];
  render(extra);
}

document.getElementById("nav").addEventListener("click", (e) => {
  const b = e.target.closest("button");
  if (b) go(b.dataset.view);
});

async function dashboard() {
  OVERVIEW = await api("/api/overview");
  const st = OVERVIEW.stats;
  const rules = Object.entries(OVERVIEW.by_rule).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = Math.max(...rules.map((x) => x[1]), 1);
  const q = document.getElementById("qent") ? document.getElementById("qent").value.toLowerCase() : "";
  const ents = OVERVIEW.entities.filter((e) => !q || (e.entity_id + e.entity_name + e.sector).toLowerCase().includes(q));
  view.innerHTML = `
    <p class="note"><b>DRISHTI</b> is a supervisory analytics tool for NCIIPC (PS 26157). Not a SIEM.
    High SPS = more attention. Examiners still decide.</p>
    <div class="kpis">
      ${kpi(st.entities, "Entities", "CSE extract", "#ea580c")}
      ${kpi(st.alerts.toLocaleString(), "Alerts analysed", "metadata only", "#1aa6c9")}
      ${kpi(st.findings, "Findings", st.eg + " gaps · " + st.ns + " negative space", "#f59e0b")}
      ${kpi(st.queue, "Top-100 queue", "human-in-the-loop", "#12b981")}
      ${kpi(OVERVIEW.bands.High, "High-attention CSEs", OVERVIEW.bands.Medium + " medium · " + OVERVIEW.bands.Low + " low", "#38bdf8")}
    </div>
    <div class="ingest-bar">
      <div>
        <b>USB ZIP ingest</b>
        <span>alerts.csv + cases.csv + assets.csv. Not a live SIEM API.</span>
        <input type="file" id="zipDash" accept=".zip,.json,.csv" />
        <p id="ingmsgDash" class="note" style="margin:8px 0 0"></p>
      </div>
      <div class="export-btns">
        <a class="btn ok" href="/api/export.json">Download sealed JSON</a>
        <a class="btn fp" href="/api/export.csv">Download findings CSV</a>
        <a class="btn no" href="/api/export.sqlite">Download SQLite</a>
      </div>
    </div>
    <div class="grid">
      <div class="card">
        <h3>Detectors firing</h3>
        ${rules.map(([k, v]) => `<div class="row"><label>${k}</label><div class="bar"><i style="width:${(100 * v) / max}%"></i></div><span>${v}</span></div>`).join("")}
      </div>
      <div class="card">
        <h3>Attention bands</h3>
        ${["High", "Medium", "Low"].map((b) => `<div class="row"><label>${b}</label><div class="bar"><i style="width:${(100 * OVERVIEW.bands[b]) / st.entities}%;background:${b === "High" ? "#ef4444" : b === "Medium" ? "#f59e0b" : "#12b981"}"></i></div><span>${OVERVIEW.bands[b]}</span></div>`).join("")}
      </div>
    </div>
    <div class="card">
      <h3>Entities by SPS — click a row for radar</h3>
      <input id="qent" class="search" placeholder="Filter CSE / sector…" value="${esc(q)}" />
      <div class="scroll">
      <table>
        <thead><tr><th>CSE</th><th>Sector</th><th>SPS</th><th>Peer</th><th>Z</th><th>Findings</th><th>Alerts</th><th>Band</th></tr></thead>
        <tbody>
          ${ents.map((e) => `<tr data-eid="${e.entity_id}">
            <td><b>${e.entity_id}</b> ${esc(e.entity_name)}</td>
            <td>${e.sector}</td>
            <td style="color:${e.sps >= 40 ? "#f87171" : "#34d399"}"><b>${e.sps}</b></td>
            <td>${e.peer_median}</td><td>${e.z_score}</td>
            <td>${e.findings}</td><td>${e.alerts}</td><td>${tag(e.band)}</td>
          </tr>`).join("")}
        </tbody>
      </table></div>
    </div>`;
  const box = document.getElementById("qent");
  box.oninput = () => dashboard();
  view.querySelectorAll("tr[data-eid]").forEach((tr) => {
    tr.onclick = () => go("radar", tr.dataset.eid);
  });
  bindZip("zipDash", "ingmsgDash");
}

function polar(cx, cy, r, i, n, v) {
  const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
  return [cx + r * v * Math.cos(a), cy + r * v * Math.sin(a)];
}

async function radar(eid) {
  if (!OVERVIEW) OVERVIEW = await api("/api/overview");
  eid = eid || OVERVIEW.entities[0].entity_id;
  const data = await api("/api/entities/" + eid);
  const caps = Object.keys(data.entity.capabilities);
  const n = caps.length, cx = 230, cy = 230, R = 160;
  const pts = (vals) => vals.map((v, i) => polar(cx, cy, R, i, n, v / 100).join(",")).join(" ");
  const self = caps.map((c) => data.entity.capabilities[c]);
  const peerAvg = caps.map((c) => {
    const xs = data.peer.map((p) => (OVERVIEW.entities.find((e) => e.entity_id === p.entity_id) || { capabilities: {} }).capabilities[c] || 0);
    return xs.reduce((a, b) => a + b, 0) / (xs.length || 1);
  });
  view.innerHTML = `
    <select id="ent">${OVERVIEW.entities.map((e) => `<option value="${e.entity_id}" ${e.entity_id === eid ? "selected" : ""}>${e.entity_id} · ${esc(e.entity_name)} · SPS ${e.sps}</option>`).join("")}</select>
    <div class="radar-grid" style="margin-top:12px">
      <div class="card">
        <h3>Capability radar vs sector peers (higher = more concern)</h3>
        <svg viewBox="0 0 460 460" width="100%" style="max-width:460px">
          ${[0.33, 0.66, 1].map((k) => `<polygon fill="none" stroke="#22324c" points="${caps.map((_, i) => polar(cx, cy, R, i, n, k).join(",")).join(" ")}"></polygon>`).join("")}
          <polygon fill="rgba(26,166,201,.15)" stroke="#1aa6c9" points="${pts(peerAvg)}"></polygon>
          <polygon fill="rgba(234,88,12,.35)" stroke="#ea580c" points="${pts(self)}"></polygon>
          ${caps.map((c, i) => {
            const [x, y] = polar(cx, cy, R + 24, i, n, 1);
            return `<text x="${x}" y="${y}" fill="#8fa0b8" font-size="11" text-anchor="middle">${esc(c.split(" ")[0])}</text>`;
          }).join("")}
        </svg>
      </div>
      <div class="card">
        <h3>${data.entity.entity_id} vs ${data.entity.sector} median ${data.entity.peer_median}</h3>
        ${caps.map((c, i) => `<div class="row"><label>${c}</label><div class="bar"><i style="width:${Math.min(100, self[i])}%"></i></div><span>${self[i]}</span></div>`).join("")}
        <p class="note">Z ${data.entity.z_score} · ${data.entity.findings} findings · ${data.entity.alerts} alerts</p>
      </div>
    </div>
    <div class="card" style="margin-top:12px">
      <h3>Findings — click for Trinity</h3>
      <div class="scroll"><table><thead><tr><th>ID</th><th>Rule</th><th>Kind</th><th>Conf</th><th>Why</th></tr></thead>
      <tbody>${data.findings.slice(0, 40).map((f) => `<tr data-fid="${f.finding_id}">
        <td>${f.finding_id}</td><td>${f.rule_id}</td><td>${f.kind}</td>
        <td>${f.confidence}</td><td>${esc(f.rationale).slice(0, 110)}</td></tr>`).join("")}</tbody></table></div>
    </div>`;
  document.getElementById("ent").onchange = (e) => radar(e.target.value);
  bindFid();
}

function paintQueue() {
  const ent = (document.getElementById("fent") || {}).value || "";
  const rule = (document.getElementById("frule") || {}).value || "";
  const q = ((document.getElementById("fsearch") || {}).value || "").toLowerCase();
  const rows = QUEUE.filter((f) =>
    (!ent || f.entity_id === ent) &&
    (!rule || f.rule_id === rule) &&
    (!q || (f.rationale + f.rule_id + f.entity_id).toLowerCase().includes(q))
  );
  const body = document.getElementById("qbody");
  if (!body) return;
  body.innerHTML = rows.map((f, i) => `<tr>
      <td style="color:#ea580c">${String(i + 1).padStart(2, "0")}</td>
      <td><b>${f.entity_id}</b></td><td>${f.rule_id}</td>
      <td style="color:#34d399">${f.confidence}</td><td>${f.sps ?? "—"}</td>
      <td class="link" data-fid="${f.finding_id}">${esc(f.rationale).slice(0, 80)}</td>
      <td class="btns" data-id="${f.finding_id}">
        ${f.decision && f.decision !== "Pending"
          ? `<span class="tag Low">${esc(f.decision)}</span>`
          : `<button class="btn ok" data-d="Accept">Accept</button>
             <button class="btn no" data-d="Reject">Reject</button>
             <button class="btn fp" data-d="False Positive">FP</button>`}
      </td></tr>`).join("") || `<tr><td colspan="7">No rows match filters.</td></tr>`;
  bindFid();
  body.querySelectorAll(".btn").forEach((b) => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      const id = b.parentElement.dataset.id;
      await api("/api/decide", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: id, decision: b.dataset.d }),
      });
      const item = QUEUE.find((x) => x.finding_id === id);
      if (item) item.decision = b.dataset.d;
      paintQueue();
    };
  });
}

async function queue() {
  const q = await api("/api/queue");
  QUEUE = q.items;
  const ents = [...new Set(QUEUE.map((x) => x.entity_id))].sort();
  const rules = [...new Set(QUEUE.map((x) => x.rule_id))].sort();
  view.innerHTML = `
    <p class="note">${q.total_findings} findings reduced to Top ${q.items.length}. Engine never closes a ticket.</p>
    <div class="filters">
      <select id="fent"><option value="">All CSEs</option>${ents.map((e) => `<option>${e}</option>`).join("")}</select>
      <select id="frule"><option value="">All rules</option>${rules.map((e) => `<option>${e}</option>`).join("")}</select>
      <input id="fsearch" class="search" placeholder="Search rationale…" />
    </div>
    <div class="card"><div class="scroll"><table>
      <thead><tr><th>#</th><th>CSE</th><th>Rule</th><th>Conf</th><th>SPS</th><th>Why</th><th>Decision</th></tr></thead>
      <tbody id="qbody"></tbody>
    </table></div></div>`;
  ["fent", "frule", "fsearch"].forEach((id) => {
    document.getElementById(id).oninput = paintQueue;
    document.getElementById(id).onchange = paintQueue;
  });
  paintQueue();
}

async function negspace() {
  const n = await api("/api/negspace");
  const ents = [...new Set(n.assets.map((a) => a.entity_id))].sort();
  const draw = () => {
    const e = document.getElementById("nent").value;
    const assets = n.assets.filter((a) => !e || a.entity_id === e);
    document.getElementById("grid").innerHTML = assets.slice(0, 140).map((a) =>
      `<div class="cell ${a.silent ? "badc" : a.alerts < 3 ? "midc" : "okc"}" title="${a.asset_id} · ${a.criticality} · ${a.alerts} alerts · ${a.entity_id}"></div>`
    ).join("");
  };
  view.innerHTML = `
    <p class="note">Critical/High assets with 0 alerts are treated as risk — PS Negative Space.</p>
    <select id="nent"><option value="">All entities</option>${ents.map((e) => `<option>${e}</option>`).join("")}</select>
    <div class="grid" style="margin-top:12px">
      <div class="card">
        <h3>Asset silence grid</h3>
        <div class="cells" id="grid"></div>
        <p class="note">Red = silent critical/high · Amber = thin · Teal = active</p>
      </div>
      <div class="card">
        <h3>Negative-space findings</h3>
        <div class="scroll"><table><thead><tr><th>Rule</th><th>CSE</th><th>Conf</th><th>Why</th></tr></thead>
        <tbody>${n.findings.slice(0, 30).map((f) => `<tr data-fid="${f.finding_id}">
          <td>${f.rule_id}</td><td>${f.entity_id}</td><td>${f.confidence}</td>
          <td>${esc(f.rationale).slice(0, 90)}</td></tr>`).join("")}</tbody></table></div>
      </div>
    </div>`;
  document.getElementById("nent").onchange = draw;
  draw();
  bindFid();
}

function workflow() {
  const steps = [
    ["1 Ingest", "CSE submits 6 CSVs as a ZIP on USB. Metadata only."],
    ["2 Air-gap", "No internet. No cloud. Docker --network=none."],
    ["3 Dual engine", "12 execution-gap + 8 negative-space + Isolation Forest + TF-IDF."],
    ["4 SPS", "0–100 priority across 8 capabilities. Peer Z > 2."],
    ["5 Top 100", "Ranked queue. Humans only review the worst 100."],
    ["6 Examiner", "Accept / Reject / FP. Tool never says guilty."],
    ["7 Prove", "SHA3-256 hash chain. Sealed advisory."],
  ];
  view.innerHTML = `
    <p class="note">PS 26157 workflow. Drop a ZIP of canonical CSVs to re-run the engine on this console.</p>
    <div class="steps">${steps.map(([t, b]) => `<div class="step"><b>${t}</b><span>${b}</span></div>`).join("")}</div>
    <div class="card" style="margin-top:16px">
      <h3>Ingest ZIP (alerts.csv + cases.csv + assets.csv required)</h3>
      <input type="file" id="zip" accept=".zip" />
      <p id="ingmsg" class="note"></p>
      <p class="export-btns" style="margin-top:12px">
        <a class="btn ok" href="/api/export.json">Download sealed JSON</a>
        <a class="btn fp" href="/api/export.csv">Download findings CSV</a>
        <a class="btn no" href="/api/export.sqlite">Download SQLite</a>
      </p>
    </div>
    <div class="card" style="margin-top:12px">
      <h3>JSON pack (PS: CSV, JSON, DB export — not a live SIEM API)</h3>
      <input type="file" id="jsonPack" accept=".json,application/json" />
      <p id="ingmsgJson" class="note"></p>
    </div>
    <div class="card" style="margin-top:12px" id="methodBox"><p class="note">Loading method…</p></div>`;
  bindZip("zip", "ingmsg");
  bindZip("jsonPack", "ingmsgJson");
  api("/api/method").then((m) => {
    const box = document.getElementById("methodBox");
    if (!box) return;
    box.innerHTML = `<h3>Where ML is used (PS §5)</h3>
      <p class="note">${esc(m.ml.architecture)}</p>
      <p class="note">Hardware: ${esc(m.ml.hardware)} · ${esc(m.ml.training)}</p>
      <p class="note">Update: ${esc(m.ml.update)}</p>
      <p class="note">Explain: ${esc(m.ml.explainability)}</p>
      <p class="note">Audit: ${esc(m.ml.auditability)}</p>
      <p class="note">Not: ${m.not.map(esc).join(" · ")}</p>`;
  });
}

async function peers() {
  if (!OVERVIEW) OVERVIEW = await api("/api/overview");
  const rows = [...OVERVIEW.entities].sort((a, b) => Math.abs(b.z_score) - Math.abs(a.z_score));
  view.innerHTML = `
    <p class="note">FR-8 peer comparison. Z &gt; 2 vs sector trimmed median = worth checking. Not a league table of guilt.</p>
    <div class="card"><div class="scroll"><table>
      <thead><tr><th>CSE</th><th>Sector</th><th>SPS</th><th>Peer median</th><th>Z</th><th>Flag</th><th>Findings</th></tr></thead>
      <tbody>${rows.map((e) => `<tr data-eid="${e.entity_id}">
        <td><b>${e.entity_id}</b> ${esc(e.entity_name)}</td>
        <td>${esc(e.sector)}</td><td><b>${e.sps}</b></td>
        <td>${e.peer_median}</td><td>${e.z_score}</td>
        <td>${e.peer_flag || Math.abs(e.z_score) > 2 ? tag("High") + " Z>2" : tag("Low")}</td>
        <td>${e.findings}</td></tr>`).join("")}</tbody>
    </table></div></div>`;
  view.querySelectorAll("tr[data-eid]").forEach((tr) => {
    tr.onclick = () => go("radar", tr.dataset.eid);
  });
}

async function coverage() {
  const u = await api("/api/usecases");
  view.innerHTML = `
    <p class="note">${esc(u.note)} Each row is a PS illustrative use case mapped to detectors that actually fire.</p>
    <div class="card"><div class="scroll"><table>
      <thead><tr><th>ID</th><th>PS example</th><th>Kind</th><th>Rules</th><th>Findings now</th></tr></thead>
      <tbody>${u.items.map((x) => `<tr>
        <td>${esc(x.id)}</td><td>${esc(x.ps)}</td><td>${tag(x.kind.includes("Negative") ? "High" : "Medium")}${esc(x.kind)}</td>
        <td class="mono">${esc(x.rules.join(" · "))}</td>
        <td><b>${x.findings}</b></td></tr>`).join("")}</tbody>
    </table></div></div>`;
}

function bindZip(inputId, msgId) {
  const el = document.getElementById(inputId);
  if (!el) return;
  el.onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const fd = new FormData();
    fd.append("file", f);
    const msg = document.getElementById(msgId);
    if (msg) msg.textContent = "Analysing…";
    try {
      const r = await fetch("/api/ingest", { method: "POST", body: fd });
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || r.status);
      OVERVIEW = null;
      if (msg) msg.textContent = "Loaded " + j.files + " files · " + j.stats.alerts + " alerts · " + j.stats.findings + " findings.";
    } catch (err) {
      if (msg) msg.textContent = "Ingest failed: " + err.message;
    }
  };
}

async function trends() {
  const t = await api("/api/trends");
  const maxA = Math.max(...t.weeks.map((w) => w.alerts), 1);
  const maxE = Math.max(...t.by_entity.map((e) => e.alerts), 1);
  view.innerHTML = `
    <p class="note">FR-16 trend of <b>this extract</b> (not live SIEM). Fast-critical = dwell &lt; 10 min + &lt; 2 steps.</p>
    <div class="card">
      <h3>Alerts by week</h3>
      ${t.weeks.map((w) => `<div class="row"><label>${esc(w.week)}</label>
        <div class="bar"><i style="width:${(100 * w.alerts) / maxA}%"></i></div>
        <span>${w.alerts} · ${w.critical} crit · ${w.fast_critical} fast</span></div>`).join("") || "<p class='note'>No timestamps.</p>"}
    </div>
    <div class="card" style="margin-top:12px">
      <h3>Volume by CSE</h3>
      ${t.by_entity.map((e) => `<div class="row"><label>${esc(e.entity_id)}</label>
        <div class="bar"><i style="width:${(100 * e.alerts) / maxE}%;background:#1aa6c9"></i></div>
        <span>${e.alerts}</span></div>`).join("")}
    </div>`;
}

async function validatePage() {
  const v = await api("/api/validate");
  if (!v.ok) {
    view.innerHTML = `<p class="note">${esc(v.reason)}</p>`;
    return;
  }
  view.innerHTML = `
    <p class="note">${esc(v.note)} Planted ${v.planted} · recovered ${v.recovered} · engine also has ${v.engine_findings} findings (extra rules are expected).</p>
    <div class="kpis">
      ${kpi(v.planted, "Planted", "ground_truth.csv", "#ea580c")}
      ${kpi(v.recovered, "Recovered", "entity + rule match", "#12b981")}
      ${kpi(v.engine_findings, "Engine findings", "not a production F1", "#1aa6c9")}
    </div>
    <div class="card"><div class="scroll"><table>
      <thead><tr><th>Rule</th><th>CSE</th><th>Planted key</th><th>Hit</th><th>How</th><th>Finding</th></tr></thead>
      <tbody>${v.rows.map((r) => `<tr>
        <td>${esc(r.rule_id)}</td><td>${esc(r.entity_id)}</td><td class="mono">${esc(r.planted)}</td>
        <td>${r.hit ? tag("Low") : tag("High")}${r.hit ? " yes" : " no"}</td>
        <td>${esc(r.how)}</td><td class="link" ${r.finding_id ? `data-fid="${esc(r.finding_id)}"` : ""}>${esc(r.finding_id)}</td>
      </tr>`).join("")}</tbody>
    </table></div></div>`;
  bindFid();
}

async function audit() {
  const a = await api("/api/audit");
  view.innerHTML = `<p class="note">${a.length} sealed events. SHA3-256 chain.</p>
    <div class="card"><div class="scroll"><table><thead><tr><th>Action</th><th>When</th><th>Chain</th></tr></thead>
    <tbody>${a.entries.slice().reverse().map((e) => `<tr>
      <td>${e.action}</td><td>${esc(e.ts || "")}</td>
      <td class="mono">${(e.chain_hash || "").slice(0, 28)}…</td></tr>`).join("")}</tbody></table></div></div>`;
}

async function report() {
  if (!OVERVIEW) OVERVIEW = await api("/api/overview");
  const top = OVERVIEW.entities.slice(0, 3);
  const st = OVERVIEW.stats;
  view.innerHTML = `<div class="letter" id="letter">
    <h2>NCIIPC supervisory advisory — SAT-SA extract</h2>
    <p>DRISHTI · CYBERNOVA2026 · PS 26157 · ${st.entities} CSEs · ${st.alerts.toLocaleString()} alerts · ${st.findings} findings.</p>
    <p>Entities <b>worth checking</b> — not a finding of guilt.</p>
    <ol>${top.map((e) => `<li><b>${e.entity_id} ${esc(e.entity_name)}</b> (${e.sector}) — SPS ${e.sps} vs peer ${e.peer_median} (Z ${e.z_score}). ${e.findings} findings.</li>`).join("")}</ol>
    <p>Next: review the Top-100 queue, then issue the statutory letter.</p>
    <p>— DRISHTI SAT-SA · Offline · SHA3-256 sealed</p>
  </div>
  <p style="margin-top:12px"><button class="btn ok" id="printAdv" type="button">Print / save</button></p>`;
  document.getElementById("printAdv").onclick = () => window.print();
}

function bindFid() {
  view.querySelectorAll("[data-fid]").forEach((el) => {
    el.onclick = (ev) => { ev.stopPropagation(); openFinding(el.dataset.fid); };
  });
}

async function openFinding(id) {
  const r = await api("/api/findings/" + id);
  const f = r.finding;
  const evid = (f.evidence || []).filter((x) => String(x).startsWith("AL-"));
  drawer.hidden = false;
  drawer.innerHTML = `
    <h2>${f.finding_id} · ${f.rule_id}</h2>
    <p>${tag(f.kind)} ${tag(f.severity)} · ${esc(f.capability)} · conf ${f.confidence}</p>
    <h3>Rationale</h3><p>${esc(f.rationale)}</p>
    <h3>Evidence</h3>
    <p>${(f.evidence || []).map((x) =>
      String(x).startsWith("AL-") ? `<button class="btn fp evid" data-al="${esc(x)}" type="button">${esc(x)}</button>` : `<span class="mono">${esc(x)}</span>`
    ).join(" ") || "entity-level signal"}</p>
    <div id="alertbox"></div>
    <h3>Confidence</h3><p>${f.confidence} — not a verdict of guilt.</p>
    <h3>Trust</h3><p>Chain ${r.chain_ok ? "VERIFIED" : "BREAK"}</p>
    <p class="mono">${f.sha3_256 || ""}</p>
    <h3>Examiner (engine never closes)</h3>
    <p class="btns" data-id="${f.finding_id}">
      <button class="btn ok" data-d="Accept" type="button">Accept</button>
      <button class="btn no" data-d="Reject" type="button">Reject</button>
      <button class="btn fp" data-d="False Positive" type="button">FP</button>
    </p>
    <p class="note" id="decmsg">${esc(f.decision || "Pending")}</p>
    <button class="btn fp" type="button" id="closeDrawer">Close</button>`;
  document.getElementById("closeDrawer").onclick = () => { drawer.hidden = true; };
  drawer.querySelectorAll("[data-d]").forEach((b) => {
    b.onclick = async (ev) => {
      ev.stopPropagation();
      await api("/api/decide", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: id, decision: b.dataset.d }),
      });
      const msg = document.getElementById("decmsg");
      if (msg) msg.textContent = b.dataset.d;
    };
  });
  drawer.querySelectorAll(".evid").forEach((b) => {
    b.onclick = async () => {
      try {
        const a = await api("/api/alerts/" + b.dataset.al);
        const rec = a.alert;
        document.getElementById("alertbox").innerHTML = `<h3>Alert ${esc(b.dataset.al)}</h3>
          <table>${Object.entries(rec).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join("")}</table>`;
      } catch (e) {
        document.getElementById("alertbox").innerHTML = `<p class="note">${esc(e.message)}</p>`;
      }
    };
  });
  if (evid[0]) drawer.querySelector(".evid")?.click();
}

async function render(extra) {
  view.innerHTML = "<p class='note'>Loading…</p>";
  try {
    if (page === "dashboard") await dashboard();
    else if (page === "radar") await radar(extra);
    else if (page === "peers") await peers();
    else if (page === "queue") await queue();
    else if (page === "negspace") await negspace();
    else if (page === "trends") await trends();
    else if (page === "coverage") await coverage();
    else if (page === "workflow") workflow();
    else if (page === "audit") await audit();
    else if (page === "validate") await validatePage();
    else await report();
  } catch (err) {
    view.innerHTML = `<p class="note">Could not load: ${esc(err.message)}</p>`;
  }
}

render();
