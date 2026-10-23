"""Web app: JSON API, CSV/JSON exports, a printable report, and the dashboard."""
import asyncio
import base64
import csv
import html
import io
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import analysis, config, load
from .db import DB
from .monitor import Monitor

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)

CFG = config.load()
# Times are stored and compared as UTC epochs; this zone is only for showing them.
DISPLAY_TZ = ZoneInfo(CFG["display_timezone"])
db = DB()
monitor = Monitor(CFG, db)
STATIC = os.path.join(os.path.dirname(__file__), "static")
USER = os.environ.get("PICKLE_USERNAME")
PASSWORD = os.environ.get("PICKLE_PASSWORD")


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(monitor.start())
    yield
    task.cancel()


app = FastAPI(title="pickle", lifespan=lifespan)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if PASSWORD:
        header = request.headers.get("authorization", "")
        ok = False
        if header.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
                ok = (secrets.compare_digest(user, USER or user)
                      and secrets.compare_digest(pw, PASSWORD))
            except ValueError:
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="pickle"'})
    return await call_next(request)


def _range(hours, since, until):
    until = until or time.time()
    since = since or until - hours * 3600
    return since, until


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else ""


def _check_meta(c):
    return {k: c.get(k) for k in ("id", "name", "via", "type", "role", "interval")} | {
        "target": monitor.resolve_target(c.get("target")) or c.get("target")}


# ---- API ---------------------------------------------------------------------

@app.get("/api/status")
def status():
    now = time.time()
    since = now - 86400
    agg = {r["check_id"]: r for r in db.q(
        "SELECT check_id, COUNT(*) n, SUM(ok) good, AVG(CASE WHEN ok THEN latency_ms END) lat "
        "FROM results WHERE ts >= ? GROUP BY check_id", (since,))}
    ever_ok = {r["check_id"] for r in db.q("SELECT DISTINCT check_id FROM results WHERE ok = 1")}
    checks = []
    for c in monitor.checks:
        st = monitor.state.get(c["id"], {})
        a = agg.get(c["id"])
        checks.append(_check_meta(c) | {
            "last": st.get("last"),
            "waiting": st.get("waiting"),
            "in_incident": bool(st.get("incident")),
            "uptime_24h": (a["good"] / a["n"]) if a and a["n"] else None,
            "avg_latency_24h": a["lat"] if a else None,
            "ever_ok": c["id"] in ever_ok,
        })
    tunnel = None
    if monitor.tunnel:
        t = monitor.tunnel
        rx, tx = t.transfer() if t.up else (None, None)
        tunnel = {"up": t.up, "error": t.error, "source": t.source,
                  "endpoint": f"{t.endpoint_host}:{t.endpoint_port}" if t.endpoint_host else None,
                  "handshake_age": t.handshake_age() if t.up else None, "rx": rx, "tx": tx}
    open_outages = [o for o in analysis.outages(db, monitor.by_id, now - 3600, now) if o["ongoing"]]
    return {
        "now": now, "started": monitor.started,
        "display_timezone": CFG["display_timezone"],
        "wan_host": CFG["target"]["wan_host"], "wan_ip": monitor.wan_ip,
        "hops": monitor.effective_hops(), "hop_traces": monitor.hop_traces,
        "checks": checks, "tunnel": tunnel,
        "unifi": monitor.unifi.snapshot if monitor.unifi else None,
        "unifi_enabled": CFG["unifi"]["enabled"],
        "ssh": monitor.routerlog.status if monitor.routerlog else (
            {"state": "disabled"} if not CFG["ssh"]["enabled"] else {"state": "starting"}),
        "ntfy_enabled": CFG["ntfy"]["enabled"],
        "ongoing_outage": open_outages[-1] if open_outages else None,
    }


@app.get("/api/timeline")
def timeline(hours: float = 24, since: float | None = None, until: float | None = None,
             buckets: int = Query(120, ge=10, le=1000)):
    since, until = _range(hours, since, until)
    width = (until - since) / buckets
    rows = db.q("SELECT check_id, CAST((ts - ?) / ? AS INTEGER) b, COUNT(*) n, SUM(ok = 0) bad, "
                "AVG(CASE WHEN ok THEN latency_ms END) lat, AVG(loss) loss "
                "FROM results WHERE ts >= ? AND ts < ? GROUP BY check_id, b",
                (since, width, since, until))
    out = {c["id"]: [None] * buckets for c in monitor.checks}
    for r in rows:
        if r["check_id"] in out and 0 <= r["b"] < buckets:
            out[r["check_id"]][r["b"]] = {"n": r["n"], "bad": r["bad"], "lat": r["lat"],
                                          "loss": r["loss"]}
    return {"since": since, "until": until, "width": width, "buckets": buckets, "series": out}


def _capacity():
    return load.capacity(CFG["unifi"], monitor.unifi.snapshot if monitor.unifi else None)


def _outages(since, until):
    """Outages with the gateway's load just before each one."""
    return load.before(db, analysis.outages(db, monitor.by_id, since, until), _capacity())


_corr_cache = {"at": 0, "value": None}


def _correlation():
    """Load vs outages over all stored history. Expensive-ish, so cached for 5 minutes."""
    now = time.time()
    if now - _corr_cache["at"] > 300:
        outs = analysis.outages(db, monitor.by_id, now - CFG["retention_days"] * 86400, now)
        _corr_cache.update(at=now, value=load.correlate(db, [o for o in outs if not o["ongoing"]],
                                                        now))
    return _corr_cache["value"]


@app.get("/api/outages")
def outages(hours: float = 24, since: float | None = None, until: float | None = None):
    since, until = _range(hours, since, until)
    return list(reversed(_outages(since, until)))


@app.post("/api/outage_note")
async def save_outage_note(request: Request):
    """Attach, change or remove the note on an outage. Body: {start, note, human_action}.
    A note with empty text and no flag is removed."""
    try:
        body = await request.json()
        start = float(body["start"])
    except (ValueError, KeyError, TypeError):
        return JSONResponse({"error": "body must be JSON with a numeric start"}, status_code=400)
    text = str(body.get("note") or "").strip()[:2000]
    human = bool(body.get("human_action"))
    # Replace whatever note this outage already has (matched the same way as on read).
    o = next((o for o in analysis.outages(db, monitor.by_id, start - 1, start + 1)
              if abs(o["start"] - start) < 1), None)
    end = (o["end"] or time.time()) if o else start
    db.x("DELETE FROM outage_notes WHERE start >= ? AND start <= ?",
         (start - analysis.MERGE_GAP, end))
    if text or human:
        db.x("INSERT INTO outage_notes (start, note, human_action, updated) VALUES (?, ?, ?, ?)",
             (start, text, 1 if human else 0, time.time()))
    return {"ok": True}


@app.get("/api/load")
def load_api(hours: float = 24, since: float | None = None, until: float | None = None,
             buckets: int = Query(120, ge=10, le=1000)):
    since, until = _range(hours, since, until)
    return {"series": load.series(db, since, until, buckets), "capacity": _capacity(),
            "outages": [{"start": o["start"], "end": o["end"], "verdict": o["verdict"],
                         "verdict_label": o["verdict_label"]}
                        for o in analysis.outages(db, monitor.by_id, since, until)],
            "correlation": _correlation(),
            "unifi_enabled": CFG["unifi"]["enabled"]}


@app.get("/api/unifi_alerts")
def unifi_alerts(hours: float = 24, since: float | None = None, until: float | None = None):
    since, until = _range(hours, since, until)
    return analysis.unifi_alerts(db, monitor.by_id, since, until)


@app.get("/api/events")
def events(hours: float = 24, since: float | None = None, until: float | None = None):
    since, until = _range(hours, since, until)
    return [dict(r) | {"data": json.loads(r["data"]) if r["data"] else None}
            # Plain router log lines are many; they're shown with each outage instead.
            for r in db.q("SELECT ts, source, kind, message, data FROM events "
                          "WHERE ts >= ? AND ts <= ? AND NOT (source = 'router_log' "
                          "AND kind IN ('log', 'link_up', 'link_down', 'dhcpv6_probe', 'dhcp_renew', "
                          "'dhcp_lease', 'dhcp_select', 'dhcp_offer', 'dhcp_discover', "
                          "'dhcp_client_start', 'dhcp_client_stop')) "
                          "ORDER BY ts DESC LIMIT 500", (since, until))]


@app.get("/api/unifi/raw")
def unifi_raw():
    if not monitor.unifi:
        return {"enabled": False}
    return {"snapshot": monitor.unifi.snapshot, "unsupported": sorted(monitor.unifi.unsupported),
            "raw": monitor.unifi.raw}


@app.post("/api/rediscover")
async def rediscover():
    await monitor.discover_hops()
    return {"hops": monitor.hops}


@app.post("/api/ntfy/test")
async def ntfy_test():
    """Send a test notification, to check the server, topic, and credentials."""
    if not monitor.ntfy:
        return {"enabled": False, "ok": False, "detail": "ntfy is not enabled in config.yaml"}
    ok, detail = await monitor.ntfy.send(
        f"pickle test ({CFG['target']['wan_host']})",
        "Notifications from pickle are working.", "default", ["test_tube"])
    return {"enabled": True, "ok": ok, "detail": detail}


# ---- exports -----------------------------------------------------------------

RESULT_COLS = ["timestamp_utc", "unix_ts", "check_id", "check_name", "via", "role", "target",
               "result", "latency_ms", "packet_loss_pct", "detail"]


def _result_rows(since, until, check):
    sql = "SELECT * FROM results WHERE ts >= ? AND ts <= ?"
    args = [since, until]
    if check:
        sql += " AND check_id = ?"
        args.append(check)
    for r in db.stream(sql + " ORDER BY ts", args):
        c = monitor.by_id.get(r["check_id"], {})
        yield {"timestamp_utc": _iso(r["ts"]), "unix_ts": round(r["ts"], 3),
               "check_id": r["check_id"], "check_name": c.get("name", ""),
               "via": c.get("via", ""), "role": c.get("role", ""), "target": r["target"],
               "result": "success" if r["ok"] else "failure",
               "latency_ms": round(r["latency_ms"], 2) if r["latency_ms"] is not None else None,
               "packet_loss_pct": round(r["loss"] * 100, 1) if r["loss"] is not None else None,
               "detail": r["detail"]}


def _csv_stream(cols, rows, filename):
    def gen():
        buf = io.StringIO()
        w = csv.DictWriter(buf, cols)
        w.writeheader()
        for i, row in enumerate(rows):
            w.writerow(row)
            if i % 500 == 0:
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()
        yield buf.getvalue()
    return StreamingResponse(gen(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _stamp(since, until):
    f = "%Y%m%d-%H%M"
    return (datetime.fromtimestamp(since, timezone.utc).strftime(f) + "_"
            + datetime.fromtimestamp(until, timezone.utc).strftime(f))


@app.get("/export/results.csv")
def export_results_csv(hours: float = 24, since: float | None = None,
                       until: float | None = None, check: str | None = None):
    since, until = _range(hours, since, until)
    return _csv_stream(RESULT_COLS, _result_rows(since, until, check),
                       f"pickle-results_{_stamp(since, until)}.csv")


@app.get("/export/results.json")
def export_results_json(hours: float = 24, since: float | None = None,
                        until: float | None = None, check: str | None = None):
    since, until = _range(hours, since, until)

    def gen():
        yield json.dumps({"exported_at": _iso(time.time()), "wan_host": CFG["target"]["wan_host"],
                          "since": _iso(since), "until": _iso(until),
                          "checks": [_check_meta(c) for c in monitor.checks]})[:-1]
        yield ', "results": ['
        for i, row in enumerate(_result_rows(since, until, check)):
            yield ("," if i else "") + json.dumps(row)
        yield "]}"
    return StreamingResponse(gen(), media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="pickle-results_{_stamp(since, until)}.json"'})


OUTAGE_COLS = ["start_utc", "end_utc", "start_local", "end_local", "duration_s", "verdict", "explanation", "note",
               "human_action", "failed_checks",
               "role_failure_rates", "unifi_events", "lease_obtained_utc", "lease_time_s",
               "lease_expires_utc", "lease_due_in_window", "lease_note", "after_recovery_utc",
               "after_recovery_wan_ip", "after_recovery_gateway", "after_recovery_wan_port",
               "after_recovery_lease", "router_log_finding", "router_log_note", "router_log_lines",
               "download_mbps_before",
               "upload_mbps_before", "cpu_pct_before", "mem_pct_before", "temp_c_before",
               "clients_before"]


def _lease_cols(o):
    lease, rec = o.get("lease") or {}, o.get("recovery") or {}
    rl = rec.get("lease") or {}
    port = rec.get("wan_port") or {}
    return {
        "lease_obtained_utc": _iso(lease.get("obtained")),
        "lease_time_s": round(lease["lease_time"]) if lease.get("lease_time") else None,
        "lease_expires_utc": _iso(lease.get("expires")),
        "lease_due_in_window": " | ".join(f"{d['what']} {_iso(d['at'])}"
                                          for d in lease.get("due", [])),
        "lease_note": lease.get("note", ""),
        "after_recovery_utc": _iso(rec.get("ts")),
        "after_recovery_wan_ip": rec.get("wan_ip"),
        "after_recovery_gateway": rec.get("isp_gateway"),
        "after_recovery_wan_port": " ".join(f"{k}={v}" for k, v in port.items()),
        "after_recovery_lease": " ".join(
            f"{k}={_iso(rl[k]) if k != 'lease_time' else round(rl[k])}"
            for k in ("obtained", "expires", "lease_time") if rl.get(k)),
    }


def _router_cols(o):
    rl = o.get("router_log") or {}
    return {"router_log_finding": rl.get("finding") or "",
            "router_log_note": rl.get("note", ""),
            "router_log_lines": " | ".join(x["message"] for x in rl.get("lines", [])[-40:])}


def _load_cols(o):
    lb = o.get("load_before") or {}
    mbps = lambda v: round(v / 1e6, 2) if v is not None else None  # noqa: E731
    return {"download_mbps_before": mbps(lb.get("rx_bps")),
            "upload_mbps_before": mbps(lb.get("tx_bps")),
            "cpu_pct_before": lb.get("cpu"), "mem_pct_before": lb.get("mem"),
            "temp_c_before": lb.get("temp"), "clients_before": lb.get("clients")}


@app.get("/export/outages.csv")
def export_outages_csv(hours: float = 24 * 7, since: float | None = None,
                       until: float | None = None):
    since, until = _range(hours, since, until)
    rows = ({"start_utc": _iso(o["start"]), "end_utc": _iso(o["end"]) or "ongoing",
             "start_local": _ts(o["start"]), "end_local": _ts(o["end"]) or "ongoing",
             "duration_s": round(o["duration"]), "verdict": o["verdict_label"],
             "explanation": o["explanation"],
             "note": (o.get("note") or {}).get("text", ""),
             "human_action": "yes" if (o.get("note") or {}).get("human_action") else "",
             "failed_checks": " ".join(o["checks"]),
             "role_failure_rates": json.dumps(o["role_failure"]),
             "unifi_events": " | ".join(f"{_iso(e['ts'])} {e['message']}" for e in o["unifi_events"])}
            | _lease_cols(o) | _router_cols(o) | _load_cols(o)
            for o in _outages(since, until))
    return _csv_stream(OUTAGE_COLS, rows, f"pickle-outages_{_stamp(since, until)}.csv")


@app.get("/export/load.csv")
def export_load_csv(hours: float = 24 * 7, since: float | None = None,
                    until: float | None = None):
    since, until = _range(hours, since, until)

    def num(v, scale=1, nd=2):
        return round(v / scale, nd) if v is not None else None
    rows = ({"timestamp_utc": _iso(r["ts"]), "unix_ts": round(r["ts"], 3),
             "download_mbps": num(r["rx_bps"], 1e6), "upload_mbps": num(r["tx_bps"], 1e6),
             "cpu_pct": num(r["cpu"]), "mem_pct": num(r["mem"]), "temp_c": num(r["temp"], 1, 1),
             "clients": r["clients"]}
            for r in db.stream("SELECT * FROM load WHERE ts >= ? AND ts <= ? ORDER BY ts",
                                     (since, until)))
    return _csv_stream(["timestamp_utc", "unix_ts", "download_mbps", "upload_mbps", "cpu_pct",
                        "mem_pct", "temp_c", "clients"], rows,
                       f"pickle-load_{_stamp(since, until)}.csv")


@app.get("/export/events.csv")
def export_events_csv(hours: float = 24 * 7, since: float | None = None,
                      until: float | None = None):
    since, until = _range(hours, since, until)
    rows = ({"timestamp_utc": _iso(r["ts"]), "source": r["source"], "kind": r["kind"],
             "message": r["message"]}
            for r in db.q("SELECT * FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts",
                          (since, until)))
    return _csv_stream(["timestamp_utc", "source", "kind", "message"], rows,
                       f"pickle-events_{_stamp(since, until)}.csv")


# ---- printable report ------------------------------------------------------------

@app.get("/report", response_class=HTMLResponse)
def report(hours: float = 24 * 7, since: float | None = None, until: float | None = None):
    since, until = _range(hours, since, until)
    e = html.escape
    outs = _outages(since, until)
    alerts = analysis.unifi_alerts(db, monitor.by_id, since, until)
    corr = _correlation()
    agg = {r["check_id"]: r for r in db.q(
        "SELECT check_id, COUNT(*) n, SUM(ok) good, AVG(CASE WHEN ok THEN latency_ms END) lat, "
        "AVG(loss) loss FROM results WHERE ts >= ? AND ts <= ? GROUP BY check_id", (since, until))}

    counts = {}
    for o in outs:
        counts[o["verdict_label"]] = counts.get(o["verdict_label"], 0) + 1

    check_rows = "".join(
        f"<tr><td>{e(c['name'])}</td><td>{_path_label(c)}</td>"
        f"<td>{e(str(monitor.resolve_target(c.get('target')) or ''))}</td>"
        f"<td class=num>{a['n']}</td><td class=num>{a['good'] / a['n'] * 100:.3f}%</td>"
        f"<td class=num>{'' if a['lat'] is None else f'{a['lat']:.1f}'}</td></tr>"
        for c in monitor.checks if (a := agg.get(c["id"])) and a["n"])
    outage_rows = "".join(
        f"<tr><td>{_ts(o['start'])}</td><td>{_ts(o['end']) or 'ongoing'}</td>"
        f"<td class=num>{_fmt_dur(o['duration'])}</td><td><b>{e(o['verdict_label'])}</b></td>"
        f"<td>{e(o['explanation'])}<br><small>Failed: {e(', '.join(o['checks']))}</small>"
        + (f"<br><small><b>Note{' (human action)' if o['note']['human_action'] else ''}:</b> "
           f"{e(o['note']['text'] or '(no text)')}</small>" if o.get("note") else "")
        + "".join(f"<br><small>UniFi {_ts(ev['ts'])}: {e(ev['message'])}"
                  f"{' (set aside: human action)' if ev.get('human_action') else ''}</small>"
                  for ev in o["unifi_events"])
        + (f"<br><small>DHCP lease: {e(o['lease']['note'])}</small>"
           if o.get("lease") and o["lease"]["note"] not in o["explanation"] else "")
        + (f"<br><small>Right after recovery: {e(_recovery_text(o['recovery']))}</small>"
           if o.get("recovery") else "")
        + (f"<br><small>Router log: {e(o['router_log']['note'])}</small>"
           if o.get("router_log") and o["router_log"]["note"]
           and o["router_log"]["note"] not in o["explanation"] else "")
        + "".join(f"<br><small><code>{e(x['message'])}</code></small>"
                  for x in (o.get("router_log") or {}).get("lines", [])[-30:])
        + (f"<br><small>Load in the 10 min before: {e(_load_text(o['load_before']))}</small>"
           if o.get("load_before") else "") + "</td></tr>"
        for o in outs) or "<tr><td colspan=5>No outages recorded in this period.</td></tr>"
    alert_rows = "".join(
        f"<tr><td>{_ts(a['ts'])}</td><td>{e(a['message'])}</td><td>"
        + {True: "Yes, external checks failed", False: "No, his WAN answered from the internet",
           None: "No data"}[a["corroborated"]] + "</td></tr>"
        for a in alerts) or "<tr><td colspan=3>No UniFi WAN alerts in this period.</td></tr>"
    summary = ", ".join(f"{v} × {e(k)}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))
    load_rows = "".join(
        f"<tr><td>{e(m['label'])}</td><td class=num>{m['busy']} of {m['outages']}</td>"
        f"<td class=num>{m['expected']}</td><td>{e(m['explanation'])}</td></tr>"
        for m in (corr or {}).get("metrics", [])) or (
        "<tr><td colspan=4>No load data yet (needs the UniFi API).</td></tr>")

    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>Connectivity report</title>
<style>
body{{font:14px/1.45 system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#0b0b0b;background:#fff}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 8px}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #d6d5d0;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f2ee}} .num{{text-align:right;font-variant-numeric:tabular-nums}} small{{color:#52514e}}
.meta{{color:#52514e}} @media print{{a{{display:none}}}}
</style></head><body>
<h1>Internet connectivity report: {e(CFG['target']['wan_host'])}</h1>
<div class=meta>Period {_ts(since)} to {_ts(until)}. Generated {_ts(time.time())}. Times in {e(CFG['display_timezone'])}; the CSV exports are in UTC. <a href="javascript:print()">Print / save as PDF</a></div>
<h2>Summary</h2>
<p>{len(outs)} outage window(s){': ' + summary if summary else ''}.</p>
<h2>Method</h2>
<p>A monitor outside his network probes his WAN IP and the ISP's own router immediately upstream of it,
plus control hosts to prove the monitor's own connection was healthy. Through a WireGuard tunnel to his gateway,
it also probes internet hosts and DNS <i>from his connection</i>, and reads the gateway's uptime, WAN port state and event log.
Every result is timestamped; a failure that hits his WAN IP <i>and</i> the ISP's upstream router at the same time, while
the gateway's uptime is unbroken, places the fault in the ISP network. When his WAN stops answering while
the ISP's gateway still does, his router's link stays up, and service returns only when the router makes a fresh DHCP
request (reconnecting the cable or renewing its lease), the ISP had stopped serving his router's existing session.</p>
<h2>Outages</h2>
<table><tr><th>Start</th><th>End</th><th>Duration</th><th>Verdict</th><th>Evidence</th></tr>{outage_rows}</table>
<h2>Load vs. outages</h2>
<p>Gateway load comes from the UniFi API. For each outage, pickle takes the peak of each measure in the 10 minutes
before it began and ranks it against every 10-minute window on record ({(corr or {}).get('history_hours', 0)} h of history,
not just this period). If load played no part, about 10% of outages would start in the busiest 10% of windows by chance.</p>
<table><tr><th>Measure</th><th class=num>Outages in busiest 10%</th><th class=num>Expected by chance</th><th>Finding</th></tr>{load_rows}</table>
<h2>UniFi WAN alerts vs. external evidence</h2>
<table><tr><th>Time</th><th>UniFi alert</th><th>Confirmed from outside?</th></tr>{alert_rows}</table>
<h2>Check availability</h2>
<table><tr><th>Check</th><th>Path</th><th>Target</th><th class=num>Samples</th><th class=num>Success</th><th class=num>Avg ms</th></tr>{check_rows}</table>
<p class=meta>Raw per-check results for this period: <a href="/export/results.csv?since={since}&until={until}">CSV</a> · <a href="/export/results.json?since={since}&until={until}">JSON</a></p>
</body></html>"""


def _recovery_text(rec):
    """One line describing his gateway's WAN state at the first poll after an outage."""
    parts = [_ts(rec["ts"])]
    if rec.get("wan_ip"):
        parts.append(f"WAN IP {rec['wan_ip']}")
    if rec.get("isp_gateway"):
        parts.append(f"gateway {rec['isp_gateway']}")
    port = rec.get("wan_port") or {}
    if "up" in port:
        parts.append("WAN port " + ("up" if port["up"] else "DOWN"))
    if rec.get("wan_uptime") is not None:
        parts.append(f"WAN up {_fmt_dur(rec['wan_uptime'])}")
    lease = rec.get("lease") or {}
    if lease.get("obtained"):
        parts.append(f"lease obtained {_ts(lease['obtained'])}")
    if lease.get("lease_time"):
        parts.append(f"lease time {_fmt_dur(lease['lease_time'])}")
    if not lease:
        parts.append("lease details not reported")
    return ", ".join(parts)


def _load_text(lb):
    parts = []
    for key, label in (("rx_bps", "down"), ("tx_bps", "up")):
        if lb.get(key) is not None:
            util = lb.get(key + "_util")
            parts.append(f"{lb[key] / 1e6:.1f} Mbps {label}"
                         + (f" ({util * 100:.0f}% of line)" if util is not None else ""))
    if lb.get("cpu") is not None:
        parts.append(f"CPU {lb['cpu']:.0f}%")
    if lb.get("mem") is not None:
        parts.append(f"memory {lb['mem']:.0f}%")
    if lb.get("temp") is not None:
        parts.append(f"{lb['temp']:.0f}°C")
    if lb.get("clients") is not None:
        parts.append(f"{lb['clients']:.0f} clients")
    return ", ".join(parts)


def _path_label(c):
    if c["role"] == "control":
        return "Monitor's own connection"
    return "Internet → him" if c["via"] == "external" else "Through his router"


def _ts(ts):
    """A time for people to read: in the display timezone, with its abbreviation."""
    return datetime.fromtimestamp(ts, DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S %Z") if ts else ""


def _fmt_dur(s):
    s = int(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {s % 3600 // 60}m"


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC, "index.html")) as f:
        return f.read()


app.mount("/static", StaticFiles(directory=STATIC), name="static")
