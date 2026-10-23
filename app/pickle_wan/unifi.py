"""Polls his UniFi gateway through the tunnel.

Collects what the gateway itself knows: its uptime (to catch reboots), the WAN
port state and IP, UniFi's own WAN-monitor stats and drop counter, its
alarm/event log, its load (WAN throughput, CPU, memory, temperature, clients),
and whatever DHCP lease details the firmware exposes. After the gateway has been
unreachable (usually an outage, since the tunnel runs over his line), the first
successful poll is saved as a recovery snapshot. Endpoint shapes differ between UniFi Network versions, so every
piece is optional; whatever came back raw is viewable at /api/unifi/raw.
"""
import logging
import re
import time

import httpx

log = logging.getLogger("pickle.unifi")

GATEWAY_TYPES = {"udm", "ugw", "uxg", "udr"}
WAN_WORDS = re.compile(r"wan|internet|isp|uplink", re.I)

# DHCP lease details aren't documented and vary by firmware, so pickle collects every field
# whose name looks lease-related (shown raw on the dashboard and in /api/unifi/raw) and only
# interprets values whose meaning is unambiguous: epoch timestamps and plausible durations.
LEASE_NAME = re.compile(r"lease|dhcp|expir|obtain|acquir|renew|rebind", re.I)
LEASE_OBTAINED = re.compile(r"obtain|acquir|lease_?start|renewed|bound", re.I)
LEASE_EXPIRES = re.compile(r"expir", re.I)
LEASE_RELATIVE = re.compile(r"remain|left|_in$|ttl", re.I)
LEASE_DURATION = re.compile(r"lease.*(time|duration|secs?|length|period)$", re.I)
MAX_LEASE = 30 * 86400


class UniFi:
    def __init__(self, cfg, db, source):
        self.cfg = cfg
        self.db = db
        self.source = source
        self.site = cfg["site"]
        self.snapshot = {}
        self.raw = {}
        self.unsupported = set()
        self._cookies = None
        self._counters = None    # (ts, rx_bytes, tx_bytes) from the previous poll
        self._integration = {}
        # Last successful poll in this process. Not persisted: after a restart, the gap is
        # pickle's own downtime, which says nothing about whether his gateway was reachable.
        self._last_ok = None

    def _client(self):
        headers = {"Accept": "application/json"}
        if self.cfg["api_key"]:
            headers["X-API-KEY"] = self.cfg["api_key"]
        transport = httpx.AsyncHTTPTransport(local_address=self.source,
                                             verify=self.cfg["verify_tls"])
        return httpx.AsyncClient(base_url=self.cfg["url"].rstrip("/"), headers=headers,
                                 transport=transport, timeout=10, cookies=self._cookies)

    async def _login(self, client):
        r = await client.post("/api/auth/login", json={
            "username": self.cfg["username"], "password": self.cfg["password"]})
        r.raise_for_status()
        self._cookies = client.cookies

    async def _get(self, client, path):
        if path in self.unsupported:
            return None
        r = await client.get(path)
        if r.status_code == 401 and self.cfg["username"] and not self.cfg["api_key"]:
            await self._login(client)
            r = await client.get(path)
        if r.status_code in (400, 404, 405):
            self.unsupported.add(path)
            return None
        r.raise_for_status()
        body = r.json()
        self.raw[path] = body
        return body

    async def poll(self):
        """One poll. Returns (ok, latency_ms, loss, detail) like a probe."""
        start = time.monotonic()
        s = f"/proxy/network/api/s/{self.site}"
        try:
            async with self._client() as client:
                if self.cfg["username"] and not self.cfg["api_key"] and self._cookies is None:
                    await self._login(client)
                health = await self._get(client, f"{s}/stat/health")
                devices = await self._get(client, f"{s}/stat/device")
                alarms = await self._get(client, f"{s}/stat/alarm")
                events = await self._get(client, f"{s}/stat/event?within=24&_limit=200")
                if not devices:
                    await self._integration_stats(client)
        except httpx.HTTPError as e:
            return False, None, None, f"UniFi API: {type(e).__name__}: {e}"
        except ValueError as e:
            return False, None, None, f"UniFi API returned non-JSON: {e}"
        latency = (time.monotonic() - start) * 1000

        snap = {"polled_at": time.time()}
        rates = (None, None)
        counters = (None, None)
        lease_fields = {}
        for sub in _data(health):
            if sub.get("subsystem") == "wan":
                lease_fields.update(_lease_fields(sub, "health.wan"))
                snap["wan_status"] = sub.get("status")
                snap["wan_ip"] = sub.get("wan_ip")
                snap["isp_name"] = sub.get("isp_name") or sub.get("isp_organization")
                gss = sub.get("gw_system-stats") or {}
                if gss.get("uptime"):
                    snap["uptime"] = int(gss["uptime"])
                snap["unifi_wan_monitor"] = sub.get("uptime_stats")
                gws = sub.get("gateways") or []
                if gws and isinstance(gws, list) and isinstance(gws[0], str):
                    snap["isp_gateway"] = gws[0]
                snap["speedtest_down_mbps"] = sub.get("xput_down")
                snap["speedtest_up_mbps"] = sub.get("xput_up")
                rates = (sub.get("rx_bytes-r"), sub.get("tx_bytes-r"))
            elif sub.get("subsystem") in ("lan", "wlan"):
                n = (sub.get("num_user") or 0) + (sub.get("num_guest") or 0)
                snap["clients"] = snap.get("clients", 0) + n
            elif sub.get("subsystem") == "www":
                snap["www_status"] = sub.get("status")
                snap["www_drops"] = sub.get("drops")
                snap["www_latency_ms"] = sub.get("latency")
                snap["www_uptime"] = sub.get("uptime")
        for dev in _data(devices):
            if dev.get("type") in GATEWAY_TYPES:
                snap["gateway_name"] = dev.get("name") or dev.get("model")
                snap["gateway_model"] = dev.get("model")
                snap["firmware"] = dev.get("version")
                if dev.get("uptime"):
                    snap["uptime"] = int(dev["uptime"])
                wan1 = dev.get("wan1") or {}
                for prefix, obj in (("device", dev), ("wan1", wan1), ("uplink", dev.get("uplink"))):
                    lease_fields.update(_lease_fields(obj, prefix))
                if _num(wan1.get("uptime")) is not None:
                    snap["wan_uptime"] = int(_num(wan1["uptime"]))
                snap["wan_port"] = {k: wan1.get(k) for k in
                                    ("up", "ip", "gateway", "type", "speed", "full_duplex", "name")
                                    if k in wan1}
                snap["wan_ip"] = snap.get("wan_ip") or wan1.get("ip")
                gw = wan1.get("gateway") or wan1.get("gateway_ip")
                if gw:
                    snap["isp_gateway"] = gw
                port = wan1 if "rx_bytes" in wan1 else (dev.get("uplink") or {})
                counters = (port.get("rx_bytes"), port.get("tx_bytes"))
                if port.get("rx_bytes-r") is not None:
                    rates = (port.get("rx_bytes-r"), port.get("tx_bytes-r"))
                sysstats = dev.get("system-stats") or {}
                snap["cpu"] = _num(sysstats.get("cpu"))
                snap["mem"] = _num(sysstats.get("mem"))
                temps = [_num(t.get("value")) for t in dev.get("temperatures") or []
                         if isinstance(t, dict)]
                temps = [t for t in temps if t is not None]
                snap["temp"] = max(temps) if temps else _num(dev.get("general_temperature"))
                break
        if self._integration:
            i = self._integration
            snap.setdefault("uptime", i.get("uptime"))
            snap["cpu"] = snap.get("cpu") if snap.get("cpu") is not None else i.get("cpu")
            snap["mem"] = snap.get("mem") if snap.get("mem") is not None else i.get("mem")
            if rates == (None, None) and i.get("rx_bps") is not None:
                rates = (i["rx_bps"] / 8, (i.get("tx_bps") or 0) / 8)
        if not snap.get("uptime"):
            snap.pop("uptime", None)
        if lease_fields:
            snap["lease_fields"] = lease_fields
            snap["lease"] = interpret_lease(lease_fields, snap["polled_at"])
        self._record_load(snap, counters, rates)
        self._track(snap)
        self._track_lease(snap)
        self._recovery(snap)
        self._ingest(_data(alarms), "alarm")
        self._ingest(_data(events), "event")
        self.snapshot = snap

        return True, latency, None, (f"uptime {_dur(snap['uptime'])}" if snap.get("uptime")
                                     else "polled")

    def _record_load(self, snap, counters, rates):
        """Store one load sample. Throughput is averaged from the WAN byte counters since
        the last poll when possible (rates UniFi reports are only a few seconds' average)."""
        now = snap["polled_at"]
        rx_bps = tx_bps = None
        rx, tx = counters
        if rx is not None and tx is not None:
            prev = self._counters
            self._counters = (now, rx, tx)
            if prev:
                dt = now - prev[0]
                drx, dtx = rx - prev[1], tx - prev[2]
                # Skip gaps (the gateway was unreachable) and counter resets (reboots).
                if 5 <= dt <= 3 * self.cfg["interval_seconds"] + 30 and drx >= 0 and dtx >= 0:
                    rx_bps, tx_bps = drx * 8 / dt, dtx * 8 / dt
        if rx_bps is None and rates[0] is not None:
            rx_bps, tx_bps = rates[0] * 8, (rates[1] or 0) * 8
        snap["rx_bps"], snap["tx_bps"] = rx_bps, tx_bps
        if any(v is not None for v in (rx_bps, snap.get("cpu"), snap.get("mem"), snap.get("clients"))):
            self.db.add_load(now, rx_bps, tx_bps, snap.get("cpu"), snap.get("mem"),
                             snap.get("temp"), snap.get("clients"))

    async def _integration_stats(self, client):
        base = "/proxy/network/integration/v1"
        sites = await self._get(client, f"{base}/sites")
        site = next((x for x in _data(sites)
                     if self.site in (x.get("internalReference"), x.get("name"), x.get("id"))),
                    None)
        if not site:
            return
        devs = await self._get(client, f"{base}/sites/{site['id']}/devices")
        gw = next((d for d in _data(devs) if "gateway" in str(d.get("features", "")).lower()
                   or str(d.get("model", "")).upper().startswith(("UDR", "UDM", "UXG", "UCG"))),
                  None)
        if not gw:
            return
        stats = await self._get(client, f"{base}/sites/{site['id']}/devices/{gw['id']}/statistics/latest")
        if not stats:
            return
        uplink = stats.get("uplink") or {}
        self._integration = {
            "uptime": int(stats["uptimeSec"]) if stats.get("uptimeSec") else None,
            "cpu": _num(stats.get("cpuUtilizationPct")),
            "mem": _num(stats.get("memoryUtilizationPct")),
            "rx_bps": _num(uplink.get("rxRateBps")),
            "tx_bps": _num(uplink.get("txRateBps")),
        }

    def _track(self, snap):
        now = time.time()
        if snap.get("uptime"):
            boot = now - snap["uptime"]
            prev = self.db.get_kv("gw_boot")
            if prev and boot - prev > 120:
                self.db.add_event("unifi", "reboot",
                                  f"Gateway rebooted (detected via uptime reset; up {_dur(snap['uptime'])})",
                                  ts=boot, uid=f"reboot:{int(boot)}")
            if not prev or abs(boot - prev) > 120:
                self.db.set_kv("gw_boot", boot)
        if snap.get("wan_ip"):
            prev = self.db.get_kv("gw_wan_ip")
            if prev and prev != snap["wan_ip"]:
                self.db.add_event("unifi", "wan_ip_change",
                                  f"Gateway WAN IP changed {prev} -> {snap['wan_ip']}")
            self.db.set_kv("gw_wan_ip", snap["wan_ip"])
        port = snap.get("wan_port") or {}
        if "up" in port:
            # Stored as {"up": bool, "ts": last poll that saw it}; older versions stored a bare bool.
            prev = self.db.get_kv("gw_wan_up")
            prev_up, prev_ts = (prev.get("up"), prev.get("ts")) if isinstance(prev, dict) else (prev, None)
            if prev_up is not None and prev_up != port["up"]:
                # Polling only sees the change, not when it happened: it happened somewhere
                # between the last poll that saw the old state and this one. During an outage
                # the gateway is usually unreachable, so that window can be long.
                self.db.add_event("unifi", "wan_port",
                                  "Gateway reports WAN port " + ("UP" if port["up"] else "DOWN"),
                                  data={"up": port["up"], "since": prev_ts, "seen": now})
            self.db.set_kv("gw_wan_up", {"up": port["up"], "ts": now})

    def _track_lease(self, snap):
        """Log an event when the lease is first seen, renewed, or its length changes. These
        events are the lease history outages are compared against."""
        lease = snap.get("lease")
        if not lease or not (lease.get("obtained") or lease.get("expires")):
            return
        prev = self.db.get_kv("gw_lease") or {}
        data = {k: lease.get(k) for k in ("obtained", "expires", "lease_time", "sources")}
        anchor = lease.get("obtained") or lease.get("expires")
        if not prev:
            kind, msg = "dhcp_lease", "DHCP lease first seen"
        elif (lease.get("obtained") and prev.get("obtained")
              and lease["obtained"] - prev["obtained"] > 30) or (
                lease.get("expires") and prev.get("expires")
                and lease["expires"] - prev["expires"] > 60):
            kind, msg = "dhcp_lease", "DHCP lease renewed"
        elif lease.get("lease_time") != prev.get("lease_time") and lease.get("lease_time"):
            kind, msg = "dhcp_lease", f"DHCP lease time changed to {_dur(lease['lease_time'])}"
        else:
            self.db.set_kv("gw_lease", data)
            return
        if lease.get("lease_time"):
            msg += f" (lease {_dur(lease['lease_time'])})"
        self.db.add_event("unifi", kind, msg, data=data, ts=lease.get("obtained") or snap["polled_at"],
                          uid=f"lease:{int(anchor)}:{lease.get('lease_time')}")
        self.db.set_kv("gw_lease", data)

    def _recovery(self, snap):
        """The first poll after the gateway was unreachable: keep what its WAN looked like
        right after recovery, since nothing could be read during the outage."""
        now = snap["polled_at"]
        gap = max(3 * self.cfg["interval_seconds"], 90)
        if self._last_ok and now - self._last_ok > gap:
            data = {"unreachable_since": self._last_ok, "seen": now}
            for k in ("wan_ip", "isp_gateway", "wan_port", "wan_uptime", "uptime", "lease",
                      "lease_fields", "wan_status"):
                if snap.get(k) is not None:
                    data[k] = snap[k]
            self.db.add_event("unifi", "recovery",
                              f"Gateway reachable again after {_dur(now - self._last_ok)}; "
                              f"WAN IP {snap.get('wan_ip') or 'unknown'}",
                              data=data, ts=now, uid=f"recovery:{int(now)}")
        self._last_ok = now

    def _ingest(self, items, kind):
        for it in items:
            uid = it.get("_id")
            t = it.get("time") or it.get("datetime")
            if not uid or not t:
                continue
            ts = t / 1000 if isinstance(t, (int, float)) and t > 1e11 else t
            if not isinstance(ts, (int, float)):
                continue
            msg = it.get("msg") or it.get("key") or "UniFi " + kind
            key = it.get("key") or ""
            wan = bool(WAN_WORDS.search(key) or WAN_WORDS.search(msg))
            self.db.add_event("unifi", "wan_alert" if wan else kind, msg,
                              data={"key": key, "subsystem": it.get("subsystem")},
                              ts=ts, uid=f"unifi:{uid}")


def _data(body):
    if isinstance(body, dict):
        d = body.get("data")
        return d if isinstance(d, list) else []
    return body if isinstance(body, list) else []


def _lease_fields(obj, prefix, depth=0):
    """Scalar fields whose name looks lease-related, keyed by their path."""
    out = {}
    if not isinstance(obj, dict) or depth > 2:
        return out
    for k, v in obj.items():
        path = f"{prefix}.{k}"
        if isinstance(v, dict):
            out.update(_lease_fields(v, path, depth + 1))
        elif LEASE_NAME.search(str(k)) and isinstance(v, (int, float, str, bool)):
            out[path] = v
    return out


def _epoch(v, now):
    n = _num(v)
    if n is None:
        return None
    if n > 1e12:
        n /= 1000
    return n if abs(n - now) < 400 * 86400 else None


def interpret_lease(fields, now):
    """What the lease fields unambiguously say: obtained / expires (epoch seconds) and
    lease_time (seconds). Anything else stays raw. `sources` names the field behind each."""
    out, src = {}, {}
    for path, v in fields.items():
        name = path.rsplit(".", 1)[-1]
        n = _num(v)
        if n is None:
            continue
        ep = _epoch(v, now)
        if LEASE_EXPIRES.search(name):
            if ep:
                out.setdefault("expires", ep); src.setdefault("expires", path)
            elif LEASE_RELATIVE.search(name) and 0 <= n <= MAX_LEASE:
                out.setdefault("expires", now + n); src.setdefault("expires", path)
        elif LEASE_OBTAINED.search(name) and ep:
            out.setdefault("obtained", ep); src.setdefault("obtained", path)
        elif LEASE_DURATION.search(name) and not ep and 60 <= n <= MAX_LEASE:
            out.setdefault("lease_time", n); src.setdefault("lease_time", path)
    if out.get("obtained") and out.get("lease_time") and not out.get("expires"):
        out["expires"] = out["obtained"] + out["lease_time"]
    if out.get("expires") and out.get("lease_time") and not out.get("obtained"):
        out["obtained"] = out["expires"] - out["lease_time"]
    if not out:
        return None
    out["sources"] = src
    return out


def _num(v):
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _dur(sec):
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m"
