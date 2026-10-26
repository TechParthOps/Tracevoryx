/* TrustWeave dashboard — vanilla JS. Live via SSE; polling fallback.
   Every metric comes from the local API; unavailable features say so. */
"use strict";

let TOKEN = localStorage.getItem("tw_token") || "";
let POLL = null;
let SSE = null;
let liveConnected = false;

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json",
               ...(TOKEN ? { Authorization: "Bearer " + TOKEN } : {}) },
  });
  if (res.status === 401) { showLogin(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res.json();
}

function toast(msg, ok = true) {
  const t = $("#toast");
  t.textContent = msg;
  t.style.borderColor = ok ? "var(--green)" : "var(--red)";
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2600);
}

function esc(s) {
  // \x26 = "&" — numeric entities survive any transport
  return String(s ?? "")
    .replace(/&/g, "\x26amp;").replace(/</g, "\x26lt;")
    .replace(/>/g, "\x26gt;").replace(/"/g, "\x26quot;")
    .replace(/'/g, "\x26#39;");
}

function badge(v) { return `<span class="badge b-${esc(v)}">${esc(v)}</span>`; }
function tshort(ts) { return (ts || "").replace("T", " ").slice(0, 19); }

/* ---------------- auth ---------------- */
function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  if (POLL) { clearInterval(POLL); POLL = null; }
}
$("#login-btn").onclick = async () => {
  TOKEN = $("#token-input").value.trim();
  try {
    await api("/api/v1/status");
    localStorage.setItem("tw_token", TOKEN);
    $("#login").classList.add("hidden");
    $("#app").classList.remove("hidden");
    startPolling();
  } catch (e) { $("#login-error").textContent = "failed: " + e.message; }
};
$("#token-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#login-btn").click();
});

/* ---------------- nav ---------------- */
$$("#nav a").forEach((a) => {
  a.onclick = () => {
    $$("#nav a").forEach((x) => x.classList.remove("active"));
    a.classList.add("active");
    $("#view-title").textContent = a.textContent.replace(/^[^\s]+\s/, "");
    $$(".view").forEach((v) => v.classList.add("hidden"));
    $("#view-" + a.dataset.view).classList.remove("hidden");
    render(a.dataset.view);
  };
});
function render(v) {
  ({ overview: rOverview, graph: rGraph, events: rEvents, guard: rGuard,
     approvals: rApprovals, privacy: rPrivacy, apimap: rApiMap,
     findings: rFindings, settings: rSettings }[v] || (() => {}))();
}

/* ---------------- live stream (SSE) ---------------- */
async function startStream() {
  if (SSE) SSE.close();
  try {
    // short-lived stream ticket instead of a long-lived bearer token in the
    // URL; a fresh ticket is fetched for (re)connection attempts
    const t = await api("/api/v1/stream/ticket", { method: "POST" });
    SSE = new EventSource("/api/v1/stream?ticket=" + encodeURIComponent(t.ticket));
    SSE.addEventListener("hello", () => {
      liveConnected = true;
      $("#live-dot").style.background = "var(--green)";
      $("#live-dot").title = "live stream connected";
    });
    SSE.onmessage = (m) => {
      try {
        const e = JSON.parse(m.data);
        const box = $("#stream-feed");
        if (box) {
          const row = document.createElement("div");
          row.className = "row";
          row.innerHTML = `<div class="title">${esc(e.event_type)} ${e.sensitive ? "🔒" : ""}</div>
            <div class="sub">${esc(e.actor)} → ${esc((e.target || "").slice(0, 48))} · ${esc(e.trust_label)}</div>`;
          box.prepend(row);
          while (box.children.length > 12) box.lastChild.remove();
        }
      } catch (err) { /* malformed frame ignored, stream stays up */ }
    };
    SSE.onerror = () => {
      liveConnected = false;
      $("#live-dot").style.background = "var(--red)";
      $("#live-dot").title = "stream disconnected — polling fallback";
      // EventSource auto-reconnects with the same ticket within its TTL;
      // after that, the next poll cycle refreshes the stream
      setTimeout(() => { if (!liveConnected) startStream(); }, 30000);
    };
  } catch (e) {
    liveConnected = false;
  }
}

/* ---------------- overview ---------------- */
async function rOverview() {
  const s = (await api("/api/v1/status"));
  const st = s.stats;
  const cards = [
    ["Events", st.total_events], ["Sensitive", st.sensitive_events],
    ["Open findings", st.open_findings],
    ["Tainted actors", st.provenance.tainted_actors],
    ["Graph nodes", Object.values(st.provenance.nodes).reduce((a, b) => a + b, 0)],
    ["Graph edges", Object.values(st.provenance.edges).reduce((a, b) => a + b, 0)],
    ["Chain", st.chain.valid ? "valid" : "BROKEN"],
  ];
  $("#stat-cards").innerHTML = cards.map(([k, v]) =>
    `<div class="card"><div class="k">${esc(k)}</div><div class="v" style="color:${k === "Chain" && v !== "valid" ? "var(--red)" : "inherit"}">${esc(v)}</div></div>`).join("");
  $("#shadow-badge").textContent = s.shadow_mode ? "SHADOW MODE (observe only)" : "ENFORCING";
  $("#side-status").innerHTML =
    `events: ${st.total_events}<br>findings open: ${st.open_findings}<br>` +
    `mode: ${s.shadow_mode ? "shadow" : "enforce"}<br>` +
    `stream: ${liveConnected ? "live" : "polling"}`;
  $("#ov-types").innerHTML = Object.entries(st.by_type).map(([t, n]) =>
    `<div class="row"><span>${esc(t)}</span><b style="margin-left:auto">${n}</b></div>`).join("") ||
    '<span class="muted">no events</span>';
  // pipeline health — real counters, honest states
  const p = s.pipeline || {};
  $("#ov-types").innerHTML += `<div class="row"><span>queue depth</span><b style="margin-left:auto">${p.queue_depth ?? "?"}</b></div>
    <div class="row"><span>dropped (backpressure)</span><b style="margin-left:auto;color:${(p.dropped || 0) > 0 ? "var(--red)" : "inherit"}">${p.dropped ?? 0}</b></div>
    <div class="row"><span>duplicates</span><b style="margin-left:auto">${p.duplicates ?? 0}</b></div>
    <div class="row"><span>ingest avg ms</span><b style="margin-left:auto">${p.avg_ingest_latency_ms ?? "?"}</b></div>`;
  // sensor health with staleness
  const sensors = s.sensors || [];
  if (sensors.length) {
    $("#ov-types").innerHTML += sensors.map((r) =>
      `<div class="row"><span>${esc(r.sensor)}</span>
       <span style="margin-left:auto">${badge(r.health)}</span>
       <span class="sub">${esc(String(r.seconds_since_beat ?? "?") + "s")}</span></div>`).join("");
  }
  const f = await api("/api/v1/findings");
  $("#ov-findings").innerHTML = f.findings.slice(0, 5).map((x) =>
    `<div class="row"><div class="title">${badge(x.severity)} ${esc(x.title)}</div>
     <div class="sub">${esc(x.rule)} · conf ${esc(x.confidence)}</div></div>`).join("")
    || '<span class="muted">no findings — no evidence-backed risk detected</span>';
}

/* ---------------- provenance graph ---------------- */
async function rGraph() {
  const g = await api("/api/v1/provenance/graph");
  drawGraph(g.nodes, g.edges);
  $("#graph-info").textContent =
    `${g.nodes.length} nodes, ${g.edges.length} edges shown ` +
    `(tainted: ${g.nodes.filter((n) => n.tainted).length}, ` +
    `sensitive: ${g.nodes.filter((n) => n.sensitive).length})`;
}

function drawGraph(nodes, edges) {
  const svg = $("#graph-svg");
  const W = svg.clientWidth || 900, H = 520;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  // deterministic circular layout grouped by kind
  const kinds = ["agent", "tool", "content", "clipboard", "file", "process", "destination"];
  const groups = {};
  for (const n of nodes) (groups[n.kind] = groups[n.kind] || []).push(n);
  const pos = {};
  let ci = 0;
  const R = Math.min(W, H) * 0.38, cx = W / 2, cy = H / 2;
  for (const k of kinds) {
    const arr = groups[k] || [];
    const gr = R * (0.55 + 0.09 * ci);
    arr.forEach((n, i) => {
      const a = (i / Math.max(arr.length, 1)) * Math.PI * 2 + ci * 0.7;
      pos[n.node_id] = [cx + gr * Math.cos(a), cy + gr * Math.sin(a)];
    });
    ci += 1;
  }
  const color = { agent: "#5aa7ff", content: "#ff8c98", clipboard: "#b18cff",
                  file: "#ffb454", process: "#2fd67b", destination: "#ff5d6c",
                  tool: "#7fd0c8", endpoint: "#888" };
  let out = "";
  for (const e of edges) {
    const a = pos[e.src], b = pos[e.dst];
    if (!a || !b) continue;
    out += `<line x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"
      stroke="${e.relation === "sent_data" || e.relation === "opened_connection" ? "#ff5d6c" : "#33477a"}"
      stroke-width="${e.relation === "sent_data" ? 2.4 : 1.3}"
      ${e.observed ? "" : 'stroke-dasharray="5,4"'} opacity="0.75">
      <title>${esc(e.relation)} (observed: ${e.observed}, conf ${esc(e.confidence)}, event ${esc(e.event_id)})</title></line>`;
  }
  for (const n of nodes) {
    const p = pos[n.node_id];
    if (!p) continue;
    const c = color[n.kind] || "#888";
    out += `<g><circle cx="${p[0]}" cy="${p[1]}" r="${n.sensitive || n.tainted ? 11 : 8}"
      fill="${n.sensitive ? "#ffb454" : c}" stroke="${n.tainted ? "#ff2d3f" : "#0a0f1c"}"
      stroke-width="${n.tainted ? 2.5 : 1}">
      <title>${esc(n.kind)}: ${esc(n.key)}\ntrust: ${esc(n.trust_label)}\ntainted: ${n.tainted} sensitive: ${n.sensitive}</title></circle>
      <text x="${p[0]}" y="${p[1] + 22}" text-anchor="middle" font-size="9"
        fill="#7f92bb">${esc(n.key.slice(0, 26))}</text></g>`;
  }
  svg.innerHTML = out;
}

/* ---------------- events ---------------- */
async function rEvents() {
  const types = [...new Set((await api("/api/v1/events?limit=1")).events.map(() => ""))];
  const q = new URLSearchParams();
  const t = $("#f-type").value, a = $("#f-actor").value.trim();
  if (t) q.set("event_type", t);
  if (a) q.set("actor", a);
  q.set("limit", "200");
  const evs = await api("/api/v1/events?" + q);
  const rows = evs.events;
  const allTypes = ["agent_registered","tool_registered","tool_call","tool_result",
    "content_ingested","clipboard_content","file_access","file_write",
    "process_started","connection","pcap_ingested","har_ingested",
    "approval_requested","approval_decided","system","handoff_transfer"];
  if (!$("#f-type").options.length) {
    $("#f-type").innerHTML = '<option value="">type: all</option>' +
      allTypes.map((t2) => `<option>${t2}</option>`).join("");
  }
  $("#ev-table").innerHTML = rows.length ?
    `<table><thead><tr><th>time</th><th>type</th><th>actor</th><th>target</th><th>dest</th><th>trust</th><th>sens</th><th>conf</th></tr></thead><tbody>` +
    rows.map((e) => `<tr><td>${esc(tshort(e.timestamp))}</td><td>${esc(e.event_type)}</td>
      <td>${esc(e.actor)}</td><td>${esc((e.target || "").slice(0, 40))}</td>
      <td>${esc((e.destination || "").slice(0, 30))}</td>
      <td>${esc(e.trust_label)}</td><td>${e.sensitive ? "yes" : "—"}</td>
      <td>${esc(e.correlation_confidence)}</td></tr>`).join("") +
    "</tbody></table>" : '<span class="muted">no events</span>';
}
$("#f-type").onchange = () => rEvents();
$("#f-actor").onkeydown = (e) => { if (e.key === "Enter") rEvents(); };

/* ---------------- agent guard ---------------- */
async function rGuard() {
  const reg = await api("/api/v1/registry");
  $("#reg-list").innerHTML =
    reg.agents.map((a) => `<div class="row"><div class="title">agent: ${esc(a.name)}</div>
      <div class="sub">permissions: ${esc(a.permissions.join(", ") || "none")}</div></div>`).join("") +
    reg.tools.map((t) => `<div class="row"><div class="title">tool: ${esc(t.name)}
      ${t.privileged ? badge("deny") + "<span class='sub'> privileged, " +
        (t.allowed === true ? "explicitly allowed" : "not allowed (deny-by-default)") + "</span>" : badge("allow")}</div></div>`).join("");
  const evs = await api("/api/v1/events?event_type=tool_call&limit=50");
  $("#gc-events").innerHTML = evs.events.length ?
    `<table><thead><tr><th>time</th><th>agent</th><th>tool</th><th>sensitive</th><th>decision</th><th>shadow</th><th>reason</th></tr></thead><tbody>` +
    evs.events.map((e) => `<tr><td>${esc(tshort(e.timestamp))}</td>
      <td>${esc(e.actor)}</td><td>${esc(e.target)}</td>
      <td>${e.sensitive ? "yes" : "—"}</td>
      <td>${badge(e.details.decision || "?")}</td>
      <td>${e.details.shadow ? "yes" : "no"}</td>
      <td class="muted small">${esc((e.details.decision_reason || "").slice(0, 80))}</td></tr>`).join("") +
    "</tbody></table>" : '<span class="muted">no tool calls yet</span>';
}
$("#rg-agent").onclick = async () => {
  const perms = $("#rg-perms").value.split(",").map((s) => s.trim()).filter(Boolean);
  await api("/api/v1/registry/agents", { method: "POST",
    body: JSON.stringify({ name: $("#rg-name").value, permissions: perms }) });
  toast("agent registered"); rGuard();
};
$("#rt-tool").onclick = async () => {
  const allowed = $("#rt-allowed").value;
  await api("/api/v1/registry/tools", { method: "POST",
    body: JSON.stringify({ name: $("#rt-name").value,
      allowed: allowed === "" ? null : allowed === "true" }) });
  toast("tool registered"); rGuard();
};
$("#gc-run").onclick = async () => {
  try {
    const r = await api("/api/v1/agent/inspect-call", { method: "POST",
      body: JSON.stringify({ agent: $("#gc-agent").value,
        tool: $("#gc-tool").value,
        arguments: JSON.parse($("#gc-args").value || "{}") }) });
    $("#gc-result").innerHTML =
      `<div class="row"><div class="title">decision: ${badge(r.action)} ${r.shadow_applied ? "(shadow)" : ""}</div>
       <div class="sub">${esc(r.reason)}</div>
       <div class="sub">sensitive in args: ${r.sensitive_in_args.length ?
         esc(r.sensitive_in_args.join(", ")) : "none"} · agent tainted: ${r.agent_tainted}</div></div>`;
    rGuard();
  } catch (e) { toast(e.message, false); }
};

/* ---------------- approvals ---------------- */
async function rApprovals() {
  const ap = await api("/api/v1/approvals");
  $("#ap-list").innerHTML = ap.approvals.map((a) =>
    `<div class="row"><div class="title">${esc(a.tool)} — ${badge(a.status)}</div>
     <div class="sub">${esc(a.agent)} · ${esc(a.reason)}</div>
     <div class="sub">requested ${esc(tshort(a.created_at))} · expires ${esc(tshort(a.expires_at))}</div>
     ${a.status === "pending" ? `<button onclick="decide('${esc(a.approval_id)}',true)">Approve</button>
       <button onclick="decide('${esc(a.approval_id)}',false)">Deny</button>` : ""}</div>`).join("")
    || '<span class="muted">no approvals requested</span>';
}
window.decide = async (id, ok) => {
  await api(`/api/v1/approvals/${id}/decide`, { method: "POST",
    body: JSON.stringify({ approved: ok }) });
  toast(ok ? "approved" : "denied");
  rApprovals();
};

/* ---------------- privacy ---------------- */
async function rPrivacy() {
  const s = await api("/api/v1/status");
  $("#pv-clip").innerHTML = s.clipboard_running ?
    badge("up") + " sensor running" : badge("down") + " sensor stopped";
}
$("#pv-scan").onclick = async () => {
  const r = await api("/api/v1/privacy/inspect", { method: "POST",
    body: JSON.stringify({ text: $("#pv-text").value,
      reversible: $("#pv-reversible").checked }) });
  let html = `<p>${r.detections.length ?
    `decision: ${badge("redact")} — ${r.detections.length} detection(s)` :
    "no secrets or sensitive data found"}</p>`;
  html += "<ul>" + r.detections.map((d) =>
    `<li>${esc(d.label)} <span class="badge b-info">${Math.round(d.confidence * 100)}%</span>
     <br><code>${esc(d.preview)}</code></li>`).join("") + "</ul>";
  if (r.redacted_text) {
    html += `<p class="muted small">redacted:</p><pre>${esc(r.redacted_text)}</pre>`;
  }
  $("#pv-result").innerHTML = html;
};
$("#rv-go").onclick = async () => {
  try {
    const r = await api("/api/v1/privacy/reveal", { method: "POST",
      body: JSON.stringify({ session_id: "default", placeholder: $("#rv-ph").value }) });
    $("#rv-out").innerHTML = `<code>${esc(r.original)}</code>`;
  } catch (e) { $("#rv-out").innerHTML = '<span class="muted">' + esc(e.message) + "</span>"; }
};
$("#pv-clip-start").onclick = async () => {
  await api("/api/v1/privacy/clipboard/control", { method: "POST",
    body: JSON.stringify({ action: "start" }) });
  rPrivacy();
};
$("#pv-clip-stop").onclick = async () => {
  await api("/api/v1/privacy/clipboard/control", { method: "POST",
    body: JSON.stringify({ action: "stop" }) });
  rPrivacy();
};

/* ---------------- api mapper ---------------- */
async function rApiMap() {
  const inv = await api("/api/v1/apimapper/inventory");
  $("#am-inv").innerHTML = inv.endpoints.length ?
    `<table><thead><tr><th>host</th><th>method</th><th>path</th><th>samples</th><th>auth seen</th><th>openapi</th></tr></thead><tbody>` +
    inv.endpoints.map((e) => `<tr><td>${esc(e.host)}</td><td>${esc(e.method)}</td>
      <td>${esc(e.path_template)}</td><td>${e.sample_count}</td>
      <td>${esc(e.auth_indicators.join(", ") || "—")}</td>
      <td>${e.in_openapi ? "yes" : "no"}</td></tr>`).join("") + "</tbody></table>"
    : '<span class="muted">no endpoints — ingest a PCAP/HAR</span>';
  const f = await api("/api/v1/apimapper/findings");
  $("#am-findings").innerHTML = f.findings.map((x) =>
    `<div class="row"><div class="title">${esc(x.label)} — ${esc(x.title)}</div>
     <div class="sub">${esc(x.explanation)}</div></div>`).join("")
    || '<span class="muted">no findings</span>';
}
$("#am-ingest").onclick = async () => {
  const f = $("#am-file").files[0];
  if (!f) { toast("choose a file", false); return; }
  const kind = f.name.toLowerCase().endsWith(".har") ? "har" : "pcap";
  const fd = new FormData();
  fd.append("file", f);
  const res = await fetch(`/api/v1/apimapper/ingest/${kind}`, {
    method: "POST", headers: { Authorization: "Bearer " + TOKEN }, body: fd });
  const data = await res.json();
  $("#am-result").textContent = JSON.stringify(data).slice(0, 140);
  rApiMap();
};

/* ---------------- findings ---------------- */
async function rFindings() {
  const f = await api("/api/v1/findings");
  $("#fd-list").innerHTML = f.findings.map((x) =>
    `<div class="row"><div class="title">${badge(x.severity)} ${esc(x.detection_id)}
      v${esc(x.detection_version)} — ${esc(x.title)}</div>
     <div class="sub">rule: ${esc(x.rule)} · confidence: ${esc(x.confidence)} · action: ${esc(x.action_taken)}</div>
     <div class="sub">timeline: ${x.timeline.map((t) => esc(t.what)).join("  →  ")}</div>
     ${x.contradictory_evidence.length ? `<div class="sub">contradictions: ${x.contradictory_evidence.map((c) => esc(c)).join(" | ")}</div>` : ""}
     <div class="sub">blind spots: ${x.blind_spots.map((b) => esc(b)).join(" | ")}</div>
     <div class="sub">suggested: ${esc(x.suggested_response)}</div>
     <div class="sub">evidence events: ${x.supporting_events.map((e) => `<code>${esc(e)}</code>`).join(" ")}</div>
     ${x.status === "open" ? `<button onclick="fp('${esc(x.finding_id)}')">Mark false positive</button>` : ""}
     </div>`).join("") || '<span class="muted">no findings</span>';
}
window.fp = async (id) => {
  await api(`/api/v1/findings/${id}/feedback`, { method: "POST",
    body: JSON.stringify({ false_positive: true }) });
  toast("marked as false positive");
  rFindings();
};

/* ---------------- settings ---------------- */
async function rSettings() {
  const s = await api("/api/v1/status");
  $("#set-shadow").innerHTML = s.shadow_mode ?
    badge("pending") + " shadow mode — decisions logged, not enforced" :
    badge("deny") + " ENFORCING — policy blocks/holds actions";
  $("#set-chain").innerHTML = s.stats.chain.valid ?
    badge("up") + ` chain valid (${s.stats.chain.checked} events)` :
    badge("deny") + " CHAIN BROKEN";
}
$("#set-shadow-on").onclick = async () => {
  await api("/api/v1/shadow-mode", { method: "POST", body: JSON.stringify({ enabled: true }) });
  toast("shadow mode on"); rSettings();
};
$("#set-shadow-off").onclick = async () => {
  await api("/api/v1/shadow-mode", { method: "POST", body: JSON.stringify({ enabled: false }) });
  toast("ENFORCEMENT enabled"); rSettings();
};
$("#set-verify").onclick = async () => {
  const r = await api("/api/v1/audit/verify", { method: "POST" });
  toast(r.valid ? `chain valid (${r.checked})` : "CHAIN BROKEN", r.valid);
  rSettings();
};
$("#set-rotate").onclick = async () => {
  if (!confirm("Rotate API token? Current token stops working immediately.")) return;
  const r = await api("/api/v1/auth/rotate", { method: "POST" });
  TOKEN = r.token;
  localStorage.setItem("tw_token", TOKEN);
  toast("token rotated");
};
$("#set-cleanup").onclick = async () => {
  const r = await api("/api/v1/retention", { method: "POST" });
  toast(`removed ${r.removed} old events`);
};

/* ---------------- polling ---------------- */
function startPolling() {
  if (POLL) clearInterval(POLL);
  startStream();
  render("overview");
  POLL = setInterval(() => {
    const v = $("#nav a.active")?.dataset.view || "overview";
    render(v);
  }, 5000);
}

if (TOKEN) {
  api("/api/v1/status").then(() => {
    $("#login").classList.add("hidden");
    $("#app").classList.remove("hidden");
    startPolling();
  }).catch(() => showLogin());
} else showLogin();
