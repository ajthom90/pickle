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
const VERDICT_STATUS = { isp: "critical", last_mile: "critical", upstream: "critical",
  router: "warning", dns: "warning", tunnel: "none", monitor: "none", unknown: "none" };

const fmtTime = (ts) => new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric",
  hour: "2-digit", minute: "2-digit", second: "2-digit" });
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
  $("#x-report").href = `/report?${q}`;
}

function renderHeader(st) {
  $("#wan").textContent = `Watching ${st.wan_host}` + (st.wan_ip && st.wan_ip !== st.wan_host ? ` (${st.wan_ip})` : "");
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
    const d = new Date(t * 1000);
    return `<span>${hours > 24 ? d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " : ""}${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>`;
  }).join("");
  $("#axis").innerHTML = `<span></span><span></span><span class="muted">24h up · latency</span><span class="ticks">${ticks}</span>`;
  window._tl = tl;
}

function renderOutages(list) {
  $("#outage-count").textContent = list.length ? `(${list.length})` : "";
  $("#outages tbody").innerHTML = list.map((o) => `<tr>
      <td class="num">${fmtTime(o.start)}${o.ongoing ? " · <b>ongoing</b>" : ""}</td>
      <td class="num">${fmtDur(o.duration)}</td>
      <td>${badge(VERDICT_STATUS[o.verdict] || "none", o.verdict_label)}</td>
      <td class="why">${esc(o.explanation)}<br><span class="muted">Failed: ${esc(o.checks.join(", "))}</span>${
        o.unifi_events.map((e) => `<br><span class="muted">UniFi ${fmtTime(e.ts)}: ${esc(e.message)}</span>`).join("")}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">No outages in this range.</td></tr>`;
}

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
    if (u.www_drops != null) rows.push(["UniFi-counted drops", esc(u.www_drops)]);
    const mon = u.unifi_wan_monitor;
    if (mon && typeof mon === "object") {
      for (const [k, v] of Object.entries(mon)) {
        if (v && typeof v === "object" && v.availability != null)
          rows.push([`UniFi monitor (${esc(k)})`, `${Number(v.availability).toFixed(2)}% available${v.latency_average != null ? ", " + v.latency_average + " ms" : ""}`]);
      }
    }
    rows.push(["Last poll", fmtTime(u.polled_at)]);
  } else if (st.unifi_enabled) {
    rows.push(["UniFi", "no data yet"]);
  } else {
    rows.push(["UniFi", "not configured"]);
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
    const [st, tl, outs, alerts, events] = await Promise.all([
      getJSON("/api/status"), getJSON(`/api/timeline?${q}&buckets=${hours <= 1 ? 60 : 120}`),
      getJSON(`/api/outages?${q}`), getJSON(`/api/unifi_alerts?${q}`), getJSON(`/api/events?${q}`)]);
    renderHeader(st); renderChecks(st, tl); renderOutages(outs);
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
  if (!el || !window._tl) { tip.hidden = true; return; }
  const tl = window._tl, i = Number(el.dataset.i), b = tl.series[el.dataset.c]?.[i];
  const t0 = tl.since + i * tl.width, t1 = t0 + tl.width;
  let body = "No data";
  if (b) {
    body = `${b.n - b.bad}/${b.n} succeeded` +
      (b.lat != null ? `<br>avg ${b.lat.toFixed(1)} ms` : "") +
      (b.loss != null && b.loss > 0 ? `<br>${(b.loss * 100).toFixed(1)}% packet loss` : "");
  }
  tip.innerHTML = `<b>${fmtTime(t0)} – ${new Date(t1 * 1000).toLocaleTimeString()}</b>${body}`;
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
