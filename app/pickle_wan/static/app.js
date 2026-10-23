const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

let hours = 24;
try { hours = Number(localStorage.getItem("pickle.hours")) || 24; } catch (e) {}

const GROUPS = [
  { title: "From the internet → his connection", test: (c) => c.via === "external" && c.role !== "control" },
  { title: "Control: the monitor's own connection", test: (c) => c.role === "control" },
  { title: "Through his router (WireGuard)", test: (c) => c.via === "vpn" && c.role !== "gateway_api" },
  { title: "His gateway (UniFi API)", test: (c) => c.role === "gateway_api" },
];
const STATUS = {
  good: { label: "Up", icon: "✓" },
  warning: { label: "Lossy", icon: "!" },
  critical: { label: "Down", icon: "✕" },
  none: { label: "Waiting", icon: "…" },
};
const VERDICT_STATUS = { isp: "critical", last_mile: "critical", upstream: "critical", isp_session: "critical",
  router: "warning", dns: "warning", tunnel: "none", monitor: "none", unknown: "none" };

// Times arrive as UTC epochs and are shown in the monitor's display timezone (from /api/status),
// so every viewer sees the same clock as the report, wherever their browser is.
let TZ;
const fmtTime = (ts) => new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric",
  hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: TZ });
const fmtClock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", timeZone: TZ });
const fmtDay = (ts) => new Date(ts * 1000).toLocaleDateString([], { month: "short", day: "numeric", timeZone: TZ });
const fmtDur = (s) => {
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
};
const fmtPct = (x) => x == null ? "–" : (x >= 0.9995 ? "100%" : (x * 100).toFixed(x > 0.99 ? 2 : 1) + "%");
const fmtBytes = (b) => b == null ? "–" : b > 1e9 ? (b / 1e9).toFixed(2) + " GB" : b > 1e6 ? (b / 1e6).toFixed(1) + " MB" : (b / 1e3).toFixed(0) + " kB";

function bucketClass(b) {
  if (!b) return "none";
  if (b.bad / b.n >= 0.5) return "critical";
  if (b.bad > 0 || (b.loss ?? 0) > 0.02) return "warning";
  return "good";
}

function badge(cls, label) {
  const s = STATUS[cls];
  return `<span class="badge"><span class="ic ${cls}">${s.icon}</span>${esc(label || s.label)}</span>`;
}

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + ": " + r.status);
  return r.json();
}

function setExports() {
  const q = `hours=${hours}`;
  $("#x-results-csv").href = `/export/results.csv?${q}`;
  $("#x-results-json").href = `/export/results.json?${q}`;
  $("#x-outages-csv").href = `/export/outages.csv?${q}`;
  $("#x-events-csv").href = `/export/events.csv?${q}`;
  $("#x-load-csv").href = `/export/load.csv?${q}`;
  $("#x-report").href = `/report?${q}`;
}

function renderHeader(st) {
  $("#wan").textContent = `Watching ${st.wan_host}` + (st.wan_ip && st.wan_ip !== st.wan_host ? ` (${st.wan_ip})` : "")
    + (st.display_timezone ? ` · times in ${st.display_timezone}` : "");
  const o = st.ongoing_outage;
  let cls = "good", text = "All clear";
  if (o) {
    cls = VERDICT_STATUS[o.verdict] || "warning";
    text = `Outage in progress (${fmtDur(o.duration)}): ${o.verdict_label}`;
  } else if (st.checks.some((c) => c.in_incident)) {
    cls = "warning"; text = "Some checks failing";
  }
  $("#overall").innerHTML = `<span class="dot ${cls}"></span>${esc(text)}`;

  const banners = [];
  if (st.tunnel && st.tunnel.error) banners.push(`<b>WireGuard failed to start:</b> ${esc(st.tunnel.error)}`);
  const wanPing = st.checks.find((c) => c.id === "ext_wan_ping");
  if (wanPing && !wanPing.ever_ok && wanPing.last && Date.now() / 1000 - st.started > 300)
    banners.push(`<b>His gateway has never answered a ping from the internet.</b> Allow ICMP echo on the WAN in UniFi (Settings → Security / firewall), or add a TCP port under <code>target.tcp_ports</code>. Until then, WAN checks can't tell up from down.`);
  if (!st.hops.gateway && !st.hops.external && Date.now() / 1000 - st.started > 180)
    banners.push(`The ISP's router hasn't been found yet. It comes from the UniFi API or a traceroute through the tunnel; you can also set <code>target.isp_gateway</code> manually.`);
  if (st.unifi_enabled && !st.unifi && st.tunnel && st.tunnel.up)
    banners.push(`UniFi API hasn't answered yet. Check the URL and API key; raw responses are at <a href="/api/unifi/raw">/api/unifi/raw</a>.`);
  $("#banners").innerHTML = banners.map((b) => `<div class="banner">${b}</div>`).join("");
}

function renderChecks(st, tl) {
  const html = GROUPS.map((g) => {
    const checks = st.checks.filter(g.test);
    if (!checks.length) return "";
    return `<div class="group"><h3>${esc(g.title)}</h3>` + checks.map((c) => {
      let cls = "none", label = c.waiting ? "Waiting" : "No data";
      if (c.last) {
        cls = !c.last.ok ? "critical" : (c.last.loss ?? 0) > 0 ? "warning" : "good";
        label = STATUS[cls].label;
      }
      const series = tl.series[c.id] || [];
      const strip = series.map((b, i) => `<i class="${bucketClass(b)}" data-c="${esc(c.id)}" data-i="${i}"></i>`).join("");
      const lat = c.last && c.last.latency_ms != null ? `${c.last.latency_ms.toFixed(1)} ms` : "–";
      return `<div class="row">
        <div><div class="name" title="${esc(c.name)}">${esc(c.name)}</div>
          <div class="target" title="${esc(c.last?.detail || c.waiting || "")}">${esc(c.target || "")} · ${esc(c.last?.detail || c.waiting || "")}</div></div>
        <div>${badge(cls, label)}</div>
        <div class="stat"><b class="num">${fmtPct(c.uptime_24h)}</b>${lat}</div>
        <div class="strip" aria-label="${esc(c.name)} history">${strip}</div>
      </div>`;
    }).join("") + `</div>`;
  }).join("");
  $("#groups").innerHTML = html;

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const t = tl.since + (tl.until - tl.since) * f;
    return `<span>${hours > 24 ? fmtDay(t) + " " : ""}${fmtClock(t)}</span>`;
  }).join("");
  $("#axis").innerHTML = `<span></span><span></span><span class="muted">24h up · latency</span><span class="ticks">${ticks}</span>`;
  window._tl = tl;
}

// While a note editor is open, the periodic refresh leaves the outages table alone.
let editingNote = null;
let _outages = [];

function noteHTML(o) {
  if (editingNote != null && Math.abs(editingNote - o.start) < 1) {
    const n = o.note || {};
    return `<form class="note-form" data-start="${o.start}">
      <textarea name="note" rows="2" maxlength="2000" placeholder="e.g. Ed moved router to wall power ~10:59 PM">${esc(n.text || "")}</textarea>
      <label><input type="checkbox" name="human" ${n.human_action ? "checked" : ""}> Human action: someone on site caused the reboot / port changes in this window, so they shouldn't decide the verdict</label>
      <div><button type="submit">Save note</button> <button type="button" class="note-cancel">Cancel</button></div>
    </form>`;
  }
  const n = o.note;
  const shown = n ? `<br><span class="note"><b>Note${n.human_action ? " (human action)" : ""}:</b> ${esc(n.text || "(no text)")}</span>` : "";
  return `${shown}<br><a class="note-edit" data-start="${o.start}">${n ? "Edit note" : "Add note"}</a>`;
}

function renderOutages(list) {
  _outages = list;
  if (editingNote == null) drawOutages();
}

function drawOutages() {
  const list = _outages;
  $("#outage-count").textContent = list.length ? `(${list.length})` : "";
  $("#outages tbody").innerHTML = list.map((o) => `<tr>
      <td class="num">${fmtTime(o.start)}${o.ongoing ? " · <b>ongoing</b>" : ""}</td>
      <td class="num">${fmtDur(o.duration)}</td>
      <td>${badge(VERDICT_STATUS[o.verdict] || "none", o.verdict_label)}</td>
      <td class="why">${esc(o.explanation)}<br><span class="muted">Failed: ${esc(o.checks.join(", "))}</span>${
        o.unifi_events.map((e) => `<br><span class="muted">UniFi ${fmtTime(e.ts)}: ${esc(e.message)}${e.human_action ? " (set aside: human action)" : ""}</span>`).join("")}${
        o.lease && !o.explanation.includes(o.lease.note) ? `<br><span class="muted">DHCP lease: ${esc(o.lease.note)}</span>` : ""}${
        o.recovery ? `<br><span class="muted">Right after recovery: ${esc(recoveryText(o.recovery))}</span>` : ""}${
        routerLogHTML(o)}${
        o.load_before ? `<br><span class="muted">10 min before: ${esc(loadText(o.load_before))}</span>` : ""}${noteHTML(o)}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">No outages in this range.</td></tr>`;
}

function openNoteEditor(start) {
  editingNote = start;
  drawOutages();
  const ta = document.querySelector("#outages .note-form textarea");
  if (ta) ta.focus();
}

document.addEventListener("click", (ev) => {
  const edit = ev.target.closest("#outages .note-edit");
  if (edit) { ev.preventDefault(); openNoteEditor(Number(edit.dataset.start)); return; }
  if (ev.target.closest("#outages .note-cancel")) { editingNote = null; drawOutages(); }
});

document.addEventListener("submit", async (ev) => {
  const form = ev.target.closest("#outages .note-form");
  if (!form) return;
  ev.preventDefault();
  const btn = form.querySelector("button[type=submit]");
  btn.disabled = true; btn.textContent = "Saving…";
  try {
    const r = await fetch("/api/outage_note", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ start: Number(form.dataset.start), note: form.note.value, human_action: form.human.checked }) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    editingNote = null;
    await refresh();
  } catch (e) {
    btn.disabled = false; btn.textContent = `Save failed (${e.message}); retry`;
  }
});

const fmtMbps = (bps) => bps == null ? "–" : (bps / 1e6 >= 100 ? (bps / 1e6).toFixed(0) : (bps / 1e6).toFixed(1)) + " Mbps";

function routerLogHTML(o) {
  const rl = o.router_log;
  if (!rl) return "";
  let out = rl.note && !o.explanation.includes(rl.note) ? `<br><span class="muted">Router log: ${esc(rl.note)}</span>` : "";
  if (rl.lines.length) {
    out += `<details class="rlog"><summary>Router log, 10 min before to the end (${rl.lines.length} line${rl.lines.length === 1 ? "" : "s"})</summary><pre>${
      rl.lines.slice(-60).map((l) => esc(l.message)).join("\n")}</pre></details>`;
  }
  return out;
}

const SSH_STATE = {
  connected: ["good", "Connected"], auth_failed: ["critical", "Auth failed"],
  host_key_mismatch: ["critical", "Host key mismatch"], unreachable: ["warning", "Unreachable"],
  no_tunnel: ["warning", "Waiting for tunnel"], error: ["critical", "Error"], starting: ["none", "Starting"],
};

function sshRows(ssh) {
  if (!ssh || ssh.state === "disabled") return [["Router SSH", `<span class="muted">off (ssh.enabled)</span>`]];
  const [cls, label] = SSH_STATE[ssh.state] || ["none", ssh.state];
  const rows = [["Router SSH", `${badge(cls, label)} <span class="muted">${esc(ssh.detail || "")}</span>`]];
  if (ssh.last_ok) rows.push(["Router log read", `${fmtTime(ssh.last_ok)}${ssh.source ? " · " + esc(ssh.source) : ""}`]);
  if (ssh.fingerprint) rows.push(["Pinned host key", `<code>${esc(ssh.fingerprint)}</code>`]);
  if (ssh.clock_skew != null) rows.push(["Router clock", `${ssh.clock_skew >= 0 ? "+" : ""}${ssh.clock_skew}s vs monitor · ${esc(ssh.tz || "")}`]);
  return rows;
}

function recoveryText(r) {
  const parts = [fmtTime(r.ts)];
  if (r.wan_ip) parts.push(`WAN IP ${r.wan_ip}`);
  if (r.isp_gateway) parts.push(`gateway ${r.isp_gateway}`);
  if (r.wan_port && "up" in r.wan_port) parts.push(`WAN port ${r.wan_port.up ? "up" : "DOWN"}`);
  if (r.wan_uptime != null) parts.push(`WAN up ${fmtDur(r.wan_uptime)}`);
  const l = r.lease || {};
  if (l.obtained) parts.push(`lease obtained ${fmtTime(l.obtained)}`);
  if (l.lease_time) parts.push(`lease time ${fmtDur(l.lease_time)}`);
  if (!r.lease) parts.push("lease details not reported");
  return parts.join(", ");
}

function loadText(lb) {
  const parts = [];
  for (const [k, label] of [["rx_bps", "down"], ["tx_bps", "up"]]) {
    if (lb[k] == null) continue;
    const u = lb[k + "_util"];
    parts.push(`${fmtMbps(lb[k])} ${label}${u != null ? ` (${Math.round(u * 100)}% of line)` : ""}`);
  }
  if (lb.cpu != null) parts.push(`CPU ${Math.round(lb.cpu)}%`);
  if (lb.mem != null) parts.push(`memory ${Math.round(lb.mem)}%`);
  if (lb.temp != null) parts.push(`${Math.round(lb.temp)}°C`);
  if (lb.clients != null) parts.push(`${lb.clients} clients`);
  return parts.join(", ");
}

// Line chart over time buckets: one y-axis, outage bands, crosshair tooltip.
function lineChart(title, ld, opts) {
  const s = ld.series, W = Math.max(300, $("#load-charts").clientWidth), H = 150;
  const pad = { l: 44, r: 8, t: 8, b: 20 }, iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
  const n = s.buckets.length;
  const vals = opts.series.flatMap((ser) => s.buckets.map((b) => b ? b[ser.key] : null)).filter((v) => v != null);
  let ymax = Math.max(opts.min || 0, ...vals, opts.cap || 0);
  if (!vals.length) return `<div class="chart"><div class="chart-head"><b>${esc(title)}</b><span class="muted">no data in this range</span></div></div>`;
  const nice = (v) => { const p = 10 ** Math.floor(Math.log10(v || 1)); return Math.ceil(v / p / (v / p > 5 ? 2 : 1)) * p * (v / p > 5 ? 2 : 1); };
  ymax = opts.fixedMax || nice(ymax * 1.05);
  const x = (i) => pad.l + (i + 0.5) / n * iw, y = (v) => pad.t + ih - v / ymax * ih;
  const tx = (t) => pad.l + (t - s.since) / (s.until - s.since) * iw;
  let g = "";
  for (const f of [0, 0.5, 1]) {
    const yy = pad.t + ih - f * ih;
    g += `<line class="gridline" x1="${pad.l}" x2="${W - pad.r}" y1="${yy}" y2="${yy}"/><text class="axis-label" x="${pad.l - 6}" y="${yy + 4}" text-anchor="end">${opts.fmt(f * ymax)}</text>`;
  }
  const bands = ld.outages.map((o) => {
    const a = Math.max(pad.l, tx(o.start)), b = Math.min(W - pad.r, tx(o.end ?? s.until));
    return `<rect class="band" x="${a}" y="${pad.t}" width="${Math.max(2, b - a)}" height="${ih}"/>`;
  }).join("");
  const cap = opts.cap ? `<line class="cap" x1="${pad.l}" x2="${W - pad.r}" y1="${y(opts.cap)}" y2="${y(opts.cap)}"/>` : "";
  const lines = opts.series.map((ser) => {
    let d = "", pen = false;
    s.buckets.forEach((b, i) => {
      const v = b ? b[ser.key] : null;
      if (v == null) { pen = false; return; }
      d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`; pen = true;
    });
    return `<path class="line" d="${d}" stroke="var(${ser.color})"/>`;
  }).join("");
  const ticks = [0, 0.5, 1].map((f) => {
    const t = s.since + (s.until - s.since) * f;
    const lab = (hours > 24 ? fmtDay(t) + " " : "") + fmtClock(t);
    return `<text class="axis-label" x="${pad.l + f * iw}" y="${H - 4}" text-anchor="${["start", "middle", "end"][f * 2]}">${lab}</text>`;
  }).join("");
  const keys = opts.series.length > 1 ? opts.series.map((ser) => `<span class="key"><i style="background:var(${ser.color})"></i>${esc(ser.label)}</span>`).join("") : "";
  const capKey = opts.cap ? `<span class="key"><i style="background:var(--muted)"></i>${esc(opts.capLabel)}</span>` : "";
  return `<div class="chart" data-chart="${opts.id}"><div class="chart-head"><b>${esc(title)}</b><span>${keys}${capKey}</span></div>
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(title)}">${bands}${g}${cap}${lines}<g class="hover"></g>${ticks}
    <rect x="${pad.l}" y="0" width="${iw}" height="${H}" fill="transparent" class="hit"/></svg></div>`;
}

let _load = null;
function renderLoad(ld) {
  _load = ld;
  const card = $("#load-card");
  card.hidden = !ld.unifi_enabled;
  if (!ld.unifi_enabled) return;
  const cap = ld.capacity || {};
  $("#load-charts").innerHTML =
    lineChart("WAN throughput (Mbps)", ld, { id: "tput", fmt: (v) => v === 0 ? "0" : fmtMbps(v).replace(" Mbps", ""),
      series: [{ key: "rx", label: "Download", color: "--series-1" }, { key: "tx", label: "Upload", color: "--series-2" }],
      cap: cap.rx_bps, capLabel: `Plan download (${cap.source === "config" ? "config" : "speed test"})`, min: 1e6 }) +
    lineChart("Gateway CPU and memory (%)", ld, { id: "cpu", fmt: (v) => Math.round(v) + "%", fixedMax: 100,
      series: [{ key: "cpu", label: "CPU", color: "--series-1" }, { key: "mem", label: "Memory", color: "--series-2" }] });
  const c = ld.correlation || { metrics: [] };
  const word = { linked: badge("warning", "Linked"), none: badge("good", "No link"), unclear: badge("none", "Unclear"), pending: badge("none", "Not yet") };
  const counted = (m) => m.outages && m.verdict !== "pending";
  $("#load-corr tbody").innerHTML = c.metrics.map((m) => `<tr><td>${esc(m.label)}</td><td class="num">${counted(m) ? `${m.busy} of ${m.outages}` : "–"}</td><td class="num">${counted(m) ? m.expected : "–"}</td><td>${word[m.verdict] || ""} <span class="muted">${esc(m.explanation)}</span></td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">No load data yet. It comes from the UniFi API once polls succeed.</td></tr>`;
  $("#load-note").textContent = c.history_hours
    ? `Based on all ${c.history_hours} h of load history and ${c.outages} outage(s), not just the range above. "Peak load" means the 10 minutes before an outage were busier than 90% of all 10-minute stretches on record.`
    : "";
}

// Crosshair + tooltip for the load charts
document.addEventListener("mousemove", (ev) => {
  const hit = ev.target.closest && ev.target.closest(".chart .hit");
  document.querySelectorAll(".chart .hover").forEach((h) => { if (!hit || !h.closest(".chart").contains(hit)) h.innerHTML = ""; });
  if (!hit || !_load) return;
  const svg = hit.ownerSVGElement, box = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
  const px = (ev.clientX - box.left) / box.width * vb.width;
  const s = _load.series, n = s.buckets.length, pad = 44, iw = vb.width - pad - 8;
  const i = Math.max(0, Math.min(n - 1, Math.floor((px - pad) / iw * n)));
  const b = s.buckets[i], cx = pad + (i + 0.5) / n * iw;
  svg.querySelector(".hover").innerHTML = `<line class="cross" x1="${cx}" x2="${cx}" y1="8" y2="${vb.height - 20}"/>`;
  const t0 = s.since + i * s.width;
  let body = "No data";
  if (b) {
    const rows = [];
    if (b.rx != null) rows.push(`Download ${fmtMbps(b.rx)} avg · ${fmtMbps(b.rx_max)} peak`);
    if (b.tx != null) rows.push(`Upload ${fmtMbps(b.tx)} avg · ${fmtMbps(b.tx_max)} peak`);
    if (b.cpu != null) rows.push(`CPU ${b.cpu.toFixed(0)}% avg · ${b.cpu_max.toFixed(0)}% peak`);
    if (b.mem != null) rows.push(`Memory ${b.mem.toFixed(0)}%`);
    if (b.temp != null) rows.push(`Temperature ${b.temp.toFixed(0)}°C`);
    if (b.clients != null) rows.push(`${b.clients} clients`);
    body = rows.join("<br>");
  }
  const inOutage = _load.outages.find((o) => o.start <= t0 + s.width && (o.end ?? s.until) >= t0);
  if (inOutage) body += `<br><b>Outage: ${esc(inOutage.verdict_label)}</b>`;
  tip.innerHTML = `<b>${fmtTime(t0)}</b>${body}`;
  tip.hidden = false;
  tip.style.left = Math.min(ev.clientX + 12, window.innerWidth - tip.offsetWidth - 8) + "px";
  tip.style.top = (ev.clientY + 14) + "px";
});

function renderGateway(st) {
  const u = st.unifi, t = st.tunnel;
  const rows = [];
  if (t) {
    rows.push(["Tunnel", t.up ? `${t.source} → ${esc(t.endpoint || "")}` : "down"]);
    rows.push(["Last handshake", t.handshake_age == null ? "never" : `${Math.round(t.handshake_age)}s ago`]);
    rows.push(["Tunnel traffic", `${fmtBytes(t.rx)} in / ${fmtBytes(t.tx)} out`]);
  }
  if (u) {
    if (u.gateway_name) rows.push(["Gateway", `${esc(u.gateway_name)} ${u.firmware ? "· fw " + esc(u.firmware) : ""}`]);
    if (u.uptime) rows.push(["Gateway uptime", fmtDur(u.uptime)]);
    if (u.wan_ip) rows.push(["WAN IP (UniFi)", esc(u.wan_ip)]);
    if (u.wan_port && Object.keys(u.wan_port).length) {
      const p = u.wan_port;
      rows.push(["WAN port", `${p.up === false ? "DOWN" : p.up ? "up" : "?"}${p.speed ? " · " + p.speed + " Mbps" : ""}${p.type ? " · " + esc(p.type) : ""}${p.gateway ? " · next hop " + esc(p.gateway) : ""}`]);
    }
    if (u.wan_status) rows.push(["UniFi WAN status", esc(u.wan_status)]);
    if (u.rx_bps != null) rows.push(["WAN throughput", `${fmtMbps(u.rx_bps)} down / ${fmtMbps(u.tx_bps)} up`]);
    const sys = [u.cpu != null && `CPU ${Math.round(u.cpu)}%`, u.mem != null && `memory ${Math.round(u.mem)}%`,
      u.temp != null && `${Math.round(u.temp)}°C`].filter(Boolean);
    if (sys.length) rows.push(["Gateway load", sys.join(" · ")]);
    if (u.clients != null) rows.push(["Clients", esc(u.clients)]);
    if (u.lease) {
      const l = u.lease, bits = [];
      if (l.obtained) bits.push(`obtained ${fmtTime(l.obtained)}`);
      if (l.lease_time) bits.push(`lease ${fmtDur(l.lease_time)}`);
      if (l.obtained && l.lease_time) bits.push(`renews ${fmtTime(l.obtained + l.lease_time / 2)}`);
      if (l.expires) bits.push(`expires ${fmtTime(l.expires)}`);
      rows.push(["DHCP lease", esc(bits.join(" · "))]);
    }
    if (u.lease_fields) rows.push(["Lease fields (raw)", `<span class="muted">${esc(Object.entries(u.lease_fields).map(([k, v]) => `${k}=${v}`).join(", "))}</span>`]);
    else if (u.polled_at) rows.push(["DHCP lease", `<span class="muted">not reported by this firmware</span>`]);
    if (u.wan_uptime != null) rows.push(["WAN uptime", fmtDur(u.wan_uptime)]);
    if (u.speedtest_down_mbps) rows.push(["Last UniFi speed test", `${Math.round(u.speedtest_down_mbps)} down / ${Math.round(u.speedtest_up_mbps || 0)} up Mbps`]);
    if (u.www_drops != null) rows.push(["UniFi-counted drops", esc(u.www_drops)]);
    const mon = u.unifi_wan_monitor;
    if (mon && typeof mon === "object") {
      for (const [k, v] of Object.entries(mon)) {
        if (v && typeof v === "object" && v.availability != null)
          rows.push([`UniFi monitor (${esc(k)})`, `${Number(v.availability).toFixed(2)}% available${v.latency_average != null ? ", " + v.latency_average + " ms" : ""}`]);
      }
    }
    rows.push(["Last poll", fmtTime(u.polled_at)]);
    rows.push(...sshRows(st.ssh));
  } else if (st.unifi_enabled) {
    rows.push(["UniFi", "no data yet"]);
    rows.push(...sshRows(st.ssh));
  } else {
    rows.push(["UniFi", "not configured"]);
    rows.push(...sshRows(st.ssh));
  }
  $("#gateway").innerHTML = `<dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
}

function renderPath(st) {
  const src = { UniFi: "reported by UniFi", traceroute: "from a traceroute through his router", config: "set in config" };
  const parts = [`<dl class="kv">
    <dt>ISP gateway</dt><dd>${esc(st.hops.gateway || "not found yet")}${st.hops.gateway ? ` <span class="muted">· his WAN's default gateway, ${esc(src[st.hops.gateway_source] || "")}</span>` : ""}</dd>
    <dt>Last hop before him</dt><dd>${esc(st.hops.external || "not found yet")} <span class="muted">· traceroute from the monitor</span></dd></dl>`];
  for (const [which, label] of [["external", "Monitor → his WAN"], ["inside", "His router → internet"]]) {
    const tr = st.hop_traces?.[which];
    if (!tr || !tr.hops.length) continue;
    const mark = which === "external" ? st.hops.external : st.hops.gateway;
    parts.push(`<h3 class="muted" style="font-size:12px;margin:12px 0 4px">${label} · ${fmtTime(tr.ts)}</h3>
      <div class="table-wrap"><table class="hops"><tbody>${tr.hops.map((h) =>
        `<tr class="${h.host === mark || h.host === st.wan_ip ? "mark" : ""}"><td>${h.hop}</td><td>${esc(h.host)}</td><td class="num">${h.loss}% loss</td><td class="num">${h.avg_ms == null ? "" : h.avg_ms + " ms"}</td></tr>`).join("")}</tbody></table></div>`);
  }
  parts.push(`<p><a id="rediscover">Re-run path discovery</a>${st.ntfy_enabled ? ` · <a id="ntfytest">Send test notification</a> <span id="ntfyresult" class="muted"></span>` : ""}</p>`);
  $("#path").innerHTML = parts.join("");
  $("#rediscover").onclick = async () => {
    $("#rediscover").textContent = "Running traceroutes…";
    try { await fetch("/api/rediscover", { method: "POST" }); } finally { refresh(); }
  };
  if (st.ntfy_enabled) $("#ntfytest").onclick = async () => {
    $("#ntfyresult").textContent = "sending…";
    try {
      const r = await (await fetch("/api/ntfy/test", { method: "POST" })).json();
      $("#ntfyresult").textContent = r.ok ? "sent" : `failed: ${r.detail}`;
    } catch (e) { $("#ntfyresult").textContent = `failed: ${e}`; }
  };
}

function renderAlerts(list) {
  const word = { true: badge("critical", "Yes, his WAN was unreachable"),
    false: badge("good", "No, his WAN answered"), null: badge("none", "No data") };
  $("#alerts tbody").innerHTML = list.map((a) => `<tr><td class="num">${fmtTime(a.ts)}</td><td>${esc(a.message)}</td><td>${word[a.corroborated]}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">No UniFi WAN alerts in this range.</td></tr>`;
}

function renderEvents(list) {
  $("#events tbody").innerHTML = list.slice(0, 200).map((e) => `<tr><td class="num">${fmtTime(e.ts)}</td><td>${esc(e.source)}</td><td>${esc(e.message)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">No events in this range.</td></tr>`;
}

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const q = `hours=${hours}`;
    const [st, tl, outs, alerts, events, ld] = await Promise.all([
      getJSON("/api/status"), getJSON(`/api/timeline?${q}&buckets=${hours <= 1 ? 60 : 120}`),
      getJSON(`/api/outages?${q}`), getJSON(`/api/unifi_alerts?${q}`), getJSON(`/api/events?${q}`),
      getJSON(`/api/load?${q}&buckets=${hours <= 1 ? 60 : 120}`)]);
    TZ = st.display_timezone || undefined;
    renderHeader(st); renderChecks(st, tl); renderOutages(outs); renderLoad(ld);
    renderGateway(st); renderPath(st); renderAlerts(alerts); renderEvents(events);
  } catch (e) {
    $("#overall").innerHTML = `<span class="dot none"></span>Can't reach monitor: ${esc(e.message)}`;
  } finally {
    refreshing = false;
  }
}

// Tooltip for timeline buckets
const tip = $("#tip");
document.addEventListener("mousemove", (ev) => {
  const el = ev.target.closest(".strip i");
  if (!el || !window._tl) { if (!ev.target.closest(".chart .hit")) tip.hidden = true; return; }
  const tl = window._tl, i = Number(el.dataset.i), b = tl.series[el.dataset.c]?.[i];
  const t0 = tl.since + i * tl.width, t1 = t0 + tl.width;
  let body = "No data";
  if (b) {
    body = `${b.n - b.bad}/${b.n} succeeded` +
      (b.lat != null ? `<br>avg ${b.lat.toFixed(1)} ms` : "") +
      (b.loss != null && b.loss > 0 ? `<br>${(b.loss * 100).toFixed(1)}% packet loss` : "");
  }
  tip.innerHTML = `<b>${fmtTime(t0)} – ${new Date(t1 * 1000).toLocaleTimeString([], { timeZone: TZ })}</b>${body}`;
  tip.hidden = false;
  const x = Math.min(ev.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = x + "px";
  tip.style.top = (ev.clientY + 14) + "px";
});

document.querySelectorAll("#range button").forEach((b) => {
  b.classList.toggle("on", Number(b.dataset.h) === hours);
  b.onclick = () => {
    hours = Number(b.dataset.h);
    try { localStorage.setItem("pickle.hours", hours); } catch (e) {}
    document.querySelectorAll("#range button").forEach((x) => x.classList.toggle("on", x === b));
    setExports(); refresh();
  };
});

setExports();
refresh();
setInterval(refresh, 15000);
