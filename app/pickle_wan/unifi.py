"""Polls his UniFi gateway through the tunnel.

Collects what the gateway itself knows: its uptime (to catch reboots), the WAN
port state and IP, UniFi's own WAN-monitor stats and drop counter, and its
alarm/event log. Endpoint shapes differ between UniFi Network versions, so every
piece is optional; whatever came back raw is viewable at /api/unifi/raw.
"""
import logging
import re
import time

import httpx

log = logging.getLogger("pickle.unifi")

GATEWAY_TYPES = {"udm", "ugw", "uxg", "udr"}
WAN_WORDS = re.compile(r"wan|internet|isp|uplink", re.I)


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
                    await self._integration_uptime(client)
        except httpx.HTTPError as e:
            return False, None, None, f"UniFi API: {type(e).__name__}: {e}"
        except ValueError as e:
            return False, None, None, f"UniFi API returned non-JSON: {e}"
        latency = (time.monotonic() - start) * 1000

        snap = {"polled_at": time.time()}
        for sub in _data(health):
            if sub.get("subsystem") == "wan":
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
                snap["wan_port"] = {k: wan1.get(k) for k in
                                    ("up", "ip", "gateway", "type", "speed", "full_duplex", "name")
                                    if k in wan1}
                snap["wan_ip"] = snap.get("wan_ip") or wan1.get("ip")
                gw = wan1.get("gateway") or wan1.get("gateway_ip")
                if gw:
                    snap["isp_gateway"] = gw
                break
        if "uptime" not in snap and self.snapshot.get("integration_uptime"):
            snap["uptime"] = self.snapshot["integration_uptime"]
        self._track(snap)
        self._ingest(_data(alarms), "alarm")
        self._ingest(_data(events), "event")
        self.snapshot = snap

        return True, latency, None, (f"uptime {_dur(snap['uptime'])}" if snap.get("uptime")
                                     else "polled")

    async def _integration_uptime(self, client):
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
        if stats and stats.get("uptimeSec"):
            self.snapshot["integration_uptime"] = int(stats["uptimeSec"])

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


def _dur(sec):
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return f"{d}d {h}h {m}m" if d else f"{h}h {m}m"
