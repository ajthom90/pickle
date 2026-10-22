"""Runs the checks on a schedule, records results, and tracks incidents."""
import asyncio
import logging
import random
import time

from . import probes
from .unifi import UniFi
from .wg import STALE_HANDSHAKE, Tunnel

log = logging.getLogger("pickle.monitor")

HOP_REDISCOVER = 3600
TRACE_COOLDOWN = 300


class Monitor:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.checks = list(cfg["checks"])
        self.state = {}       # check_id -> {"last": row, "streak": n, "streak_start": ts, "incident": id}
        self.wan_ip = None
        self.hops = {"external": None, "inside": None}
        self.hop_traces = {}
        self.last_trace = 0
        self.started = time.time()
        self.tunnel = None
        self.unifi = None

        wg = cfg["wireguard"]
        if wg["enabled"]:
            self.tunnel = Tunnel(wg)
        if cfg["unifi"]["enabled"]:
            self.checks.append({"id": "unifi_api", "name": "UniFi API (gateway status)",
                                "via": "vpn", "type": "unifi", "target": cfg["unifi"]["url"],
                                "role": "gateway_api",
                                "interval": cfg["unifi"]["interval_seconds"]})
        self.by_id = {c["id"]: c for c in self.checks}

        for row in db.q("SELECT id, check_id, start FROM incidents WHERE end IS NULL"):
            self.state.setdefault(row["check_id"], {})["incident"] = row["id"]
        saved = db.get_kv("hops")
        if saved:
            self.hops.update(saved)

    def event(self, source, kind, message, data=None):
        log.info("[%s] %s", kind, message)
        self.db.add_event(source, kind, message, data)

    async def start(self):
        if self.tunnel:
            await asyncio.to_thread(self.tunnel.bring_up)
            if self.tunnel.error:
                self.event("tunnel", "error", "WireGuard setup failed: " + self.tunnel.error)
            elif self.cfg["unifi"]["enabled"]:
                self.unifi = UniFi(self.cfg["unifi"], self.db, self.tunnel.source)
        tasks = [self._wan_resolver(), self._hop_discovery(), self._housekeeping()]
        if self.tunnel and self.tunnel.up:
            tasks.append(self.tunnel.watchdog(self.event))
        await self._resolve_wan()
        for c in self.checks:
            tasks.append(self._loop(c))
        await asyncio.gather(*tasks)

    # ---- targets -------------------------------------------------------------

    async def _resolve_wan(self):
        host = self.cfg["target"]["wan_host"]
        ip = await probes.resolve(host)
        if ip and ip != self.wan_ip:
            if self.wan_ip:
                self.event("resolver", "wan_ip_change",
                           f"{host} now resolves to {ip} (was {self.wan_ip})")
            self.wan_ip = ip

    async def _wan_resolver(self):
        while True:
            await asyncio.sleep(60)
            await self._resolve_wan()

    def resolve_target(self, target):
        if target == "{wan}":
            return self.wan_ip
        if target == "{isp_hop_external}":
            fixed = self.cfg["target"].get("isp_hop_external", "auto")
            return self.hops["external"] if fixed == "auto" else fixed
        if target == "{isp_hop_inside}":
            fixed = self.cfg["wireguard"].get("isp_hop_inside", "auto")
            if fixed != "auto":
                return fixed
            # UniFi knows its WAN next hop exactly; fall back to the traceroute's guess.
            port = (self.unifi.snapshot.get("wan_port") if self.unifi else None) or {}
            return port.get("gateway") or self.hops["inside"]
        return target

    async def _hop_discovery(self):
        while True:
            try:
                await self.discover_hops()
            except Exception:  # noqa: BLE001
                log.exception("hop discovery failed")
            missing = not self.hops["external"] or (self.tunnel and self.tunnel.up
                                                     and not self.hops["inside"])
            await asyncio.sleep(120 if missing else HOP_REDISCOVER)

    def effective_hops(self):
        return {"external": self.resolve_target("{isp_hop_external}"),
                "inside": self.resolve_target("{isp_hop_inside}")}

    async def discover_hops(self):
        """Find the ISP routers adjacent to his connection, from outside and inside."""
        if self.wan_ip:
            hops, raw = await probes.trace(self.wan_ip)
            self.hop_traces["external"] = {"ts": time.time(), "hops": hops}
            responding = [h for h in hops if h["host"] != "???"]
            if responding and responding[-1]["host"] == self.wan_ip:
                before = [h for h in responding if h["host"] != self.wan_ip]
                if before:
                    self._set_hop("external", before[-1]["host"])
            elif responding and not self.hops["external"]:
                # Trace never reached him (maybe he doesn't answer ping): best guess is the last hop.
                self._set_hop("external", responding[-1]["host"])
        if self.tunnel and self.tunnel.up:
            # Make sure the tunnel has handshaken, or the first probes vanish.
            for _ in range(10):
                if await asyncio.to_thread(self.tunnel.handshake_age) is not None:
                    break
                await probes.ping(self.cfg["wireguard"]["gateway_lan_ip"], self.tunnel.source)
            target = self.cfg["wireguard"]["internet_targets"][0]
            hops, raw = await probes.trace(target, source=self.tunnel.source)
            self.hop_traces["inside"] = {"ts": time.time(), "hops": hops}
            gw = self.cfg["wireguard"]["gateway_lan_ip"]
            # Hop 1 is his gateway; the first responder after it is the ISP.
            after = [h for h in hops if h["hop"] >= 2 and h["host"] not in ("???", gw)]
            if hops and after:
                self._set_hop("inside", after[0]["host"])

    def _set_hop(self, which, ip):
        if self.hops[which] != ip:
            if self.hops[which]:
                self.event("hops", "isp_hop_change",
                           f"ISP hop ({which}) changed {self.hops[which]} -> {ip}")
            self.hops[which] = ip
            self.db.set_kv("hops", self.hops)

    # ---- check loop ----------------------------------------------------------

    async def _loop(self, check):
        await asyncio.sleep(random.uniform(0, min(check["interval"], 10)))
        while True:
            began = time.monotonic()
            try:
                await self.run_check(check)
            except Exception:  # noqa: BLE001 - one bad check must not stop the others
                log.exception("check %s crashed", check["id"])
            await asyncio.sleep(max(1, check["interval"] - (time.monotonic() - began)))

    async def run_check(self, check):
        ts = time.time()
        vpn = check["via"] == "vpn"
        target = self.resolve_target(check.get("target"))
        if vpn and (not self.tunnel or not self.tunnel.up):
            return  # no tunnel configured or it failed to start; nothing meaningful to record
        if target is None:
            self._note_waiting(check)
            return
        source = self.tunnel.source if vpn else None
        t = check["type"]
        if t == "ping":
            res = await probes.ping(target, source)
        elif t == "tcp":
            res = await probes.tcp(target, check["port"], source)
        elif t == "dns":
            res = await probes.dns_query(target, check.get("query", "www.google.com"), source)
        elif t == "http":
            res = await probes.http(target, source)
        elif t == "tunnel":
            age = await asyncio.to_thread(self.tunnel.handshake_age)
            ok = age is not None and age < STALE_HANDSHAKE
            res = (ok, None, None,
                   "no handshake yet" if age is None else f"last handshake {int(age)}s ago")
        elif t == "unifi":
            if not self.unifi:
                return
            res = await self.unifi.poll()
        else:
            raise ValueError(f"unknown check type {t}")
        self.record(check, ts, target, *res)

    def _note_waiting(self, check):
        st = self.state.setdefault(check["id"], {})
        st["waiting"] = "waiting for target discovery"

    def record(self, check, ts, target, ok, latency, loss, detail):
        cid = check["id"]
        self.db.add_result(ts, cid, ok, latency, loss, target, detail)
        st = self.state.setdefault(cid, {})
        st.pop("waiting", None)
        st["last"] = {"ts": ts, "ok": ok, "latency_ms": latency, "loss": loss,
                      "target": target, "detail": detail}
        if ok:
            st["streak"] = 0
            if st.get("incident"):
                self.db.x("UPDATE incidents SET end = ? WHERE id = ?", (ts, st["incident"]))
                st["incident"] = None
            return
        if not st.get("streak"):
            st["streak_start"] = ts
        st["streak"] = st.get("streak", 0) + 1
        if st.get("incident"):
            self.db.x("UPDATE incidents SET fail_count = fail_count + 1 WHERE id = ?",
                      (st["incident"],))
        elif st["streak"] >= self.cfg["fail_threshold"]:
            cur = self.db.x("INSERT INTO incidents (check_id, start, fail_count) VALUES (?, ?, ?)",
                            (cid, st["streak_start"], st["streak"]))
            st["incident"] = cur.lastrowid
            if check["role"] == "wan":
                asyncio.get_running_loop().create_task(self.snapshot_traces())

    async def snapshot_traces(self):
        """When his WAN stops answering, capture where the path dies, from both sides."""
        if time.time() - self.last_trace < TRACE_COOLDOWN:
            return
        self.last_trace = time.time()
        if self.wan_ip:
            hops, raw = await probes.trace(self.wan_ip, cycles=5)
            self.db.add_event("pickle", "trace",
                              f"Traceroute to his WAN ({self.wan_ip}) during failure: "
                              + _summarize(hops), data={"hops": hops, "raw": raw})

    async def _housekeeping(self):
        while True:
            await asyncio.sleep(3600)
            self.db.purge(self.cfg["retention_days"])


def _summarize(hops):
    if not hops:
        return "no output"
    answering = [h for h in hops if h["host"] != "???" and h["loss"] < 100]
    if not answering:
        return "no hops answered"
    last = answering[-1]
    return f"last answering hop #{last['hop']} {last['host']} ({len(hops)} hops probed)"
