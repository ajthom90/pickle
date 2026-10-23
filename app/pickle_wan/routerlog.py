"""Optional router log collection over SSH, through the WireGuard tunnel.

Every few minutes, and right after his gateway is reachable again after an outage, pickle
logs in to the router and reads its DHCP/WAN log lines. Each line is stored once as an
event (source "router_log") at the log line's own time, and udhcpc / dhclient lines are
parsed into structured events (renewal sent, lease obtained with its lease time, ...).

Safety:
- Only the fixed commands in COMMANDS run; nothing is built from config or input.
- The router's host key is pinned on first connect (or taken from ssh.host_key) and passed
  to asyncssh as the only trusted key, so a changed key fails before any password is sent.
- Only the configured credentials are used: no default keys, SSH agent or ~/.ssh/config.
"""
import asyncio
import datetime
import hashlib
import json
import logging
import re
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import asyncssh

log = logging.getLogger("pickle.routerlog")

GREP = "grep -iE 'dhcp|udhcpc|wan'"
# UniFi OS keeps the WAN DHCP client's log in wan-diag-dhcp.log (also in daemon.log), link
# changes in messages / wan-diag-port.log, its WAN monitors in messages, and a reboot record.
UGREP = ("grep -aiE 'udhcpc|dhcp-client|wan-failover|wf-monitor|wf-interface|carrier|"
         "link is (up|down)|reset button|ui-probe-dhcpv6: (no advertise|received advertise)'")
LINKGREP = "grep -aiE 'carrier|link is (up|down)'"
# The only commands pickle ever runs on the router. All read-only, all constant strings.
# Rotated files are read oldest first, so concatenation never looks like a clock jump.
COMMANDS = {
    # router clock (epoch), UTC offset, zone name, uptime: to place syslog lines in time
    "clock": ("date +%s; date +%z; cat /etc/timezone 2>/dev/null || "
              "readlink /etc/localtime 2>/dev/null; echo; cat /proc/uptime"),
    # which log sources exist
    "probe": ("test -f /var/log/wan-diag-dhcp.log && echo unifi; "
              "test -f /var/log/messages && echo messages; "
              "command -v logread >/dev/null 2>&1 && echo logread; "
              "command -v journalctl >/dev/null 2>&1 && echo journalctl; true"),
    # UniFi OS. Each read also takes the tail of the .1 file, so lines written just before
    # a rotation aren't missed.
    "unifi_dhcp": ("{ tail -n 300 /var/log/wan-diag-dhcp.log.1; tail -n 3000 /var/log/wan-diag-dhcp.log; } "
                   "2>/dev/null"),
    "unifi_messages": (f"{{ tail -n 20000 /var/log/messages.1; cat /var/log/messages; }} 2>/dev/null "
                       f"| {UGREP} | tail -n 3000"),
    "unifi_daemon": (f"{{ tail -n 20000 /var/log/daemon.log.1; cat /var/log/daemon.log; }} 2>/dev/null "
                     f"| {UGREP} | tail -n 3000"),
    "unifi_port": (f"{{ tail -n 300 /var/log/wan-diag-port.log.1; tail -n 3000 /var/log/wan-diag-port.log; }} "
                   f"2>/dev/null | {LINKGREP}"),
    "unifi_reboots": "cat /var/log/reboot-time.log 2>/dev/null",
    # UniFi OS backfill: everything still on the router, oldest first.
    "unifi_dhcp_backfill": ("{ for n in 9 8 7 6 5 4 3 2; do zcat /var/log/wan-diag-dhcp.log.$n.gz; done; "
                            "cat /var/log/wan-diag-dhcp.log.1 /var/log/wan-diag-dhcp.log; } 2>/dev/null"),
    "unifi_messages_backfill": (f"{{ for n in 4 3 2; do zstdcat /var/log/messages.$n.zst; done; "
                                f"cat /var/log/messages.1 /var/log/messages; }} 2>/dev/null "
                                f"| {UGREP} | tail -n 30000"),
    "unifi_daemon_backfill": (f"{{ for n in 4 3 2; do zstdcat /var/log/daemon.log.$n.zst; done; "
                              f"cat /var/log/daemon.log.1 /var/log/daemon.log; }} 2>/dev/null "
                              f"| {UGREP} | tail -n 30000"),
    "unifi_port_backfill": (f"{{ for n in 4 3 2; do zcat /var/log/wan-diag-port.log.$n.gz; done; "
                            f"cat /var/log/wan-diag-port.log.1 /var/log/wan-diag-port.log; }} 2>/dev/null "
                            f"| {LINKGREP}"),
    # Other routers
    "messages": f"{GREP} /var/log/messages | tail -n 2000",
    "messages_backfill": f"{GREP} /var/log/messages | tail -n 20000",
    "logread": f"logread | {GREP} | tail -n 2000",
    "logread_backfill": f"logread | {GREP} | tail -n 20000",
    "journalctl": f"journalctl -o short-iso --no-pager -q -n 50000 | {GREP} | tail -n 2000",
    "journalctl_backfill": f"journalctl -o short-iso --no-pager -q -n 200000 | {GREP} | tail -n 20000",
}
SOURCES = ["messages", "logread", "journalctl"]
# UniFi OS reads, in order: the DHCP log first, so the WAN interface is known for the rest.
UNIFI_READS = ["unifi_dhcp", "unifi_port", "unifi_messages", "unifi_daemon"]
BACKFILL_FLAG = "router_log_backfilled_v2"   # v1 only read /var/log/messages

INTERVAL = 300
MIN_GAP = 30          # seconds between collections, however often it's kicked
STALE_HANDSHAKE = 180
CONNECT_TIMEOUT = 15

# ---- timestamps ------------------------------------------------------------------------

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
# 2026-10-22T22:52:23.123456-05:00 host rest   (rsyslog RFC3339, journalctl short-iso)
ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(\S+)\s+(.*)$")
# Oct  2 22:52:23 host rest   (traditional syslog: no year, local time)
TRAD = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+(.*)$")
# Thu Oct 22 22:52:23 2026 daemon.notice rest   (busybox logread: has the year, local time)
LOGREAD = re.compile(r"^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+"
                     r"(\d{4})\s+(\S+)\s+(.*)$")
PROG = re.compile(r"^([\w./@-]+)(?:\[\d+\])?:\s*(.*)$")


def router_tz(zone_name, offset):
    """The router's timezone: its zone name if known (handles DST), else its current offset."""
    if zone_name:
        name = zone_name.strip()
        if "zoneinfo/" in name:
            name = name.split("zoneinfo/", 1)[1]
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    m = re.match(r"^([+-])(\d\d):?(\d\d)$", (offset or "").strip())
    if m:
        delta = datetime.timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        return datetime.timezone(delta if m.group(1) == "+" else -delta)
    return datetime.timezone.utc


def parse_line(line, tz, router_now, fold=0):
    """(epoch, program, text) for one log line, or None if it can't be placed in time.
    Lines without a year get the year that puts them at or before the router's clock.
    fold=1 picks the second occurrence of a local time that happens twice (DST ending)."""
    m = ISO.match(line)
    if m:
        stamp = m.group(1).replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(stamp)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz, fold=fold)
        return _split(dt.timestamp(), m.group(3))
    m = LOGREAD.match(line)
    if m and m.group(1) in MONTHS:
        mon, day, hh, mm, ss, year, _, rest = m.groups()
        dt = datetime.datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                               tzinfo=tz, fold=fold)
        return _split(dt.timestamp(), rest)
    m = TRAD.match(line)
    if m and m.group(1) in MONTHS:
        mon, day, hh, mm, ss, _, rest = m.groups()
        year = datetime.datetime.fromtimestamp(router_now, tz).year
        for y in (year, year - 1):
            try:
                dt = datetime.datetime(y, MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                                       tzinfo=tz, fold=fold)
            except ValueError:      # Feb 29 in a non-leap year
                continue
            if dt.timestamp() <= router_now + 86400:
                return _split(dt.timestamp(), rest)
    return None


def _split(ts, rest):
    m = PROG.match(rest)
    return (ts, m.group(1), m.group(2)) if m else (ts, "", rest)


# ---- DHCP line parsing -----------------------------------------------------------------

# udhcpc (busybox, used by UniFi OS), matched on the text after "udhcpc: ".
UDHCPC = [
    ("dhcp_lease", re.compile(r"lease of (?P<ip>[\d.]+) obtained(?: from (?P<server>[\d.]+))?,?\s+"
                              r"lease time (?P<lease_time>\d+)", re.I)),
    ("dhcp_renew", re.compile(r"sending renew(?: to (?:server )?(?P<server>[\d.]+))?|performing dhcp renew", re.I)),
    ("dhcp_rebind", re.compile(r"sending rebind", re.I)),
    ("dhcp_select", re.compile(r"(?:sending|broadcasting) select for (?P<ip>[\d.]+)|sending request", re.I)),
    ("dhcp_discover", re.compile(r"(?:sending|broadcasting) discover", re.I)),
    ("dhcp_offer", re.compile(r"received offer of (?P<ip>[\d.]+)", re.I)),
    ("dhcp_nak", re.compile(r"received nak|\bnak\b", re.I)),
    ("dhcp_lost", re.compile(r"lease lost|no lease, failing", re.I)),
    ("dhcp_release", re.compile(r"sending release", re.I)),
    ("dhcp_client_start", re.compile(r"^started\b", re.I)),
    ("dhcp_client_stop", re.compile(r"received sigterm", re.I)),
]
# dhclient (ISC), only when the program is dhclient: other DHCP servers on the router (the
# LAN's dnsmasq) log the same DHCPREQUEST / DHCPACK words for their own clients.
DHCLIENT = [
    ("dhcp_ack", re.compile(r"DHCPACK(?: of (?P<ip>[\d.]+))?(?: from (?P<server>[\d.]+))?")),
    ("dhcp_ack", re.compile(r"bound to (?P<ip>[\d.]+) -- renewal in (?P<renewal_in>\d+)")),
    ("dhcp_nak", re.compile(r"DHCPNAK")),
    ("dhcp_discover", re.compile(r"DHCPDISCOVER")),
    ("dhcp_renew", re.compile(r"DHCPREQUEST")),
    ("dhcp_release", re.compile(r"DHCPRELEASE")),
]
IFACE_TAG = re.compile(r"\(interface:([\w.-]+)\)")
# Wired interfaces only; Wi-Fi radios (ra0, rai1, ...) and switch "Port N" lines stay plain.
LINK = re.compile(r"\b(?P<iface>(?:eth|wan|ppp|en)[\w.-]*): (?:Link is (?P<ud>Up|Down)|(?P<cg>Lost|Gained) carrier)")
MONITOR = re.compile(r"wan-failover-monitor-\w+: (?P<mon>\S+) \((?P<src>[^)]*?)->(?P<dst>[^)]*)\) has [\w-]+ update: "
                     r"(?P<target>\S+) is (?P<state>up|down)\b")
WAN_STATE = re.compile(r"wan-failover-interfaces: wf-interface-(?P<iface>[\w.-]+) \((?P<ip>[^)]*)\) is (?P<state>\w+)")
DHCPV6 = re.compile(r"ui-probe-dhcpv6: (?P<res>no Advertise received|received Advertise)", re.I)
RESET = re.compile(r"reset button is (?P<action>released|pressed)", re.I)
REBOOT_RECORD = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(Experience .+)$")

REQUESTS = {"dhcp_renew", "dhcp_rebind", "dhcp_select", "dhcp_discover"}
ANSWERS = {"dhcp_lease", "dhcp_ack", "dhcp_offer"}


def classify_line(ts, prog, text, wan_iface=None):
    """(kind, data) for a log line. WAN DHCP kinds only for lines that positively come from
    the router's WAN DHCP client (udhcpc, or dhclient), on the WAN interface if it's known."""
    data = {}
    tag = IFACE_TAG.search(text)
    if tag:
        data["iface"] = tag.group(1)
    body = text[len("udhcpc:"):].strip() if text.lower().startswith("udhcpc:") else None
    if body is None and prog == "udhcpc":
        body = text
    if body is not None:
        if wan_iface and data.get("iface") and data["iface"] != wan_iface:
            return "log", data
        for kind, rx in UDHCPC:
            m = rx.search(body)
            if m:
                return kind, _fields(kind, ts, m, data)
        return "log", data
    if prog == "dhclient":
        for kind, rx in DHCLIENT:
            m = rx.search(text)
            if m:
                return kind, _fields(kind, ts, m, data)
        return "log", data
    m = LINK.search(text)
    if m:
        data["iface"] = m.group("iface")
        up = (m.group("ud") or "").lower() == "up" or m.group("cg") == "Gained"
        return ("link_up" if up else "link_down"), data
    m = MONITOR.search(text)
    if m:
        iface = re.search(r"wf-monitor-([\w.]+?)-\d", m.group("mon"))
        data.update(target=m.group("target"), state=m.group("state"), monitor=m.group("mon"))
        if iface:
            data["iface"] = iface.group(1)
        return "wan_monitor", data
    m = WAN_STATE.search(text)
    if m:
        data.update(iface=m.group("iface"), state=m.group("state"))
        return "wan_state", data
    m = DHCPV6.search(text)
    if m:
        data["ok"] = m.group("res").lower().startswith("received")
        return "dhcpv6_probe", data
    m = RESET.search(text)
    if m:
        data["action"] = m.group("action").lower()
        return "reset_button", data
    return "log", data


def _fields(kind, ts, m, data):
    data.update({k: v for k, v in m.groupdict().items() if v is not None})
    for k in ("lease_time", "renewal_in"):
        if k in data:
            data[k] = int(data[k])
    if kind == "dhcp_lease":
        # same keys as the UniFi lease events, so lease timing can use either
        data["obtained"] = ts
        data["expires"] = ts + data["lease_time"]
    return data


def reclassify(db):
    """Re-derive kind/data for every stored router log line. Lines are stored once (dedup by
    hash), so without this, lines collected by an older version would keep their old kind."""
    wan_iface = db.get_kv("router_wan_iface")
    changed = 0
    for r in db.q("SELECT id, ts, kind, data FROM events WHERE source = 'router_log'"):
        old = json.loads(r["data"]) if r["data"] else {}
        if "prog" not in old or "text" not in old or old.get("record"):
            continue
        kind, data = classify_line(r["ts"], old["prog"], old["text"], wan_iface)
        data.update(prog=old["prog"], text=old["text"])
        if old.get("clock_suspect"):
            data["clock_suspect"] = True
        if kind != r["kind"] or data != old:
            db.x("UPDATE events SET kind = ?, data = ? WHERE id = ?", (kind, json.dumps(data), r["id"]))
            changed += 1
    return changed


# ---- collector ---------------------------------------------------------------------------

class RouterLog:
    def __init__(self, cfg, db, tunnel):
        self.cfg = cfg
        self.db = db
        self.tunnel = tunnel
        self.host = cfg["host"]
        self._kick = asyncio.Event()
        self._last_run = 0
        self.status = {"state": "starting", "detail": "", "last_ok": None, "last_attempt": None,
                       "source": None, "new_lines": 0, "fingerprint": None, "clock_skew": None,
                       "tz": None}
        pinned = self._pinned()
        if pinned:
            self.status["fingerprint"] = _fingerprint(pinned)

    def kick(self):
        """Collect soon (e.g. the gateway just became reachable again after an outage)."""
        self._kick.set()

    async def run(self):
        changed = await asyncio.to_thread(reclassify, self.db)
        if changed:
            log.info("re-classified %d stored router log line(s)", changed)
        await asyncio.sleep(10)
        while True:
            if time.time() - self._last_run >= MIN_GAP:
                try:
                    await self.collect()
                except Exception as e:  # noqa: BLE001 - never stop monitoring
                    log.exception("router log collection failed")
                    self._set("error", f"{type(e).__name__}: {e}")
            try:
                await asyncio.wait_for(self._kick.wait(), INTERVAL)
            except asyncio.TimeoutError:
                pass
            self._kick.clear()

    def _set(self, state, detail=""):
        self.status.update(state=state, detail=detail)

    def _pinned(self):
        return (self.cfg.get("host_key") or "").strip() or self.db.get_kv("ssh_host_key")

    def _tunnel_ready(self):
        if not self.tunnel or not self.tunnel.up or not self.tunnel.source:
            return False
        age = self.tunnel.handshake_age()
        return age is not None and age < STALE_HANDSHAKE

    def _options(self):
        """Connection options shared by the host-key fetch and the real login. Only the
        configured credentials: no default keys, agent, or ~/.ssh/config."""
        return {"port": self.cfg["port"], "local_addr": (self.tunnel.source, 0), "config": None}

    async def _pin(self):
        key = await asyncio.wait_for(asyncssh.get_server_host_key(self.host, **self._options()),
                                     CONNECT_TIMEOUT)
        if key is None:
            raise asyncssh.Error(0, "server sent no host key")
        pinned = key.export_public_key("openssh").decode().strip()
        self.db.set_kv("ssh_host_key", pinned)
        fp = _fingerprint(pinned)
        self.db.add_event("pickle", "ssh_host_key",
                          f"Pinned the router's SSH host key on first connect: {fp}")
        log.info("pinned router SSH host key %s", fp)
        return pinned

    async def collect(self):
        self.status["last_attempt"] = time.time()
        if not self._tunnel_ready():
            # Not counted toward MIN_GAP: the recovery kick that follows once the tunnel is
            # back must still get through.
            self._set("no_tunnel", "waiting for the WireGuard tunnel")
            return
        self._last_run = time.time()
        try:
            pinned = self._pinned() or await self._pin()
            self.status["fingerprint"] = _fingerprint(pinned)
            trusted = asyncssh.import_public_key(pinned)
            async with asyncssh.connect(
                    self.host, username=self.cfg["username"],
                    password=self.cfg["password"] or None,
                    client_keys=[self.cfg["key_file"]] if self.cfg["key_file"] else None,
                    agent_path=None, known_hosts=([trusted], [], []),
                    connect_timeout=CONNECT_TIMEOUT, **self._options()) as conn:
                await self._read(conn)
        except asyncssh.HostKeyNotVerifiable as e:
            self._set("host_key_mismatch",
                      f"The router's host key doesn't match the pinned key ({e.reason}). "
                      f"Not connecting. If the router was reset or replaced, set ssh.host_key "
                      f"to its new key.")
        except asyncssh.PermissionDenied:
            self._set("auth_failed", "The router rejected the username / password or key.")
        except (OSError, asyncio.TimeoutError, asyncssh.ConnectionLost) as e:
            self._set("unreachable", f"{type(e).__name__}: {e}")
        except asyncssh.Error as e:
            self._set("error", f"{type(e).__name__}: {e.reason}")

    async def _run(self, conn, name):
        # Log files can hold stray bytes (wan-diag-port.log does; so can lines next to a power
        # cut): decode with replacement and drop NUL padding rather than failing the read.
        r = await conn.run(COMMANDS[name], check=False, timeout=120, encoding="utf-8", errors="replace")
        return (r.stdout or "").replace("\x00", "")

    async def _read_one(self, conn, name, backfill_key, store, problems):
        """One log read, isolated: a failure is reported but doesn't stop the other reads.
        Each source has its own backfill flag, set only once its backfill succeeded."""
        backfill = backfill_key and not self.db.get_kv(backfill_key)
        cmd = name + ("_backfill" if backfill else "")
        try:
            out = await self._run(conn, cmd)
        except (asyncio.TimeoutError, asyncssh.Error, OSError) as e:
            problems.append(f"{name}: {type(e).__name__}")
            return 0
        new = await asyncio.to_thread(store, out.splitlines())
        if backfill:
            self.db.set_kv(backfill_key, time.time())
        return new

    async def _read(self, conn):
        clock = (await self._run(conn, "clock")).splitlines()
        router_now = float(clock[0]) if clock and clock[0].strip().isdigit() else time.time()
        offset = clock[1] if len(clock) > 1 else ""
        zone = clock[2] if len(clock) > 2 else ""
        uptime = clock[-1].split()[0] if clock and clock[-1].split() else None
        tz = router_tz(zone, offset)
        self.status.update(clock_skew=round(router_now - time.time(), 1), tz=str(tz))
        boot = router_now - float(uptime) if uptime and _isfloat(uptime) else None

        available = (await self._run(conn, "probe")).split()
        lines_store = lambda lines: self.store(lines, tz, router_now, boot)  # noqa: E731
        new, problems = 0, []
        if "unifi" in available:
            source = "UniFi OS logs"
            for name in UNIFI_READS:
                new += await self._read_one(conn, name, f"{BACKFILL_FLAG}:{name}", lines_store, problems)
            new += await self._read_one(conn, "unifi_reboots", None, self.store_reboot_records, problems)
        else:
            source = next((s for s in SOURCES if s in available), None)
            if not source:
                self._set("connected", "no /var/log/messages, logread or journalctl on the router")
                self.status["last_ok"] = time.time()
                return
            new = await self._read_one(conn, source, f"{BACKFILL_FLAG}:{source}", lines_store, problems)
        self.status.update(source=source, new_lines=new, last_ok=time.time())
        self._set("connected", f"{new} new line(s) from {source}"
                  + (f"; couldn't read {', '.join(problems)}" if problems else ""))

    def store_reboot_records(self, lines):
        """UniFi OS's reboot-time.log: when and how the router last restarted. Its time is when
        the entry was written after boot (a few minutes late), so it's information only, never
        used to place a reboot in an outage."""
        new = 0
        for line in lines:
            m = REBOOT_RECORD.match(line.strip())
            if not m:
                continue
            try:
                ts = datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            text = m.group(2)
            data = {"record": True, "text": text, "improper": "improper shutdown" in text,
                    "upgrade": "upgrade reboot" in text}
            uid = "rl:" + hashlib.sha1(line.strip().encode()).hexdigest()
            if self.db.add_event("router_log", "restart_record", "reboot-time.log: " + line.strip()[:480],
                                 data=data, ts=ts, uid=uid):
                new += 1
        return new

    def store(self, lines, tz, router_now, boot=None):
        """Store new lines as events. Dedup is by a hash of the whole line only, so rotated
        logs and lines with odd timestamps are never dropped as 'already seen'. Lines whose
        time can't be trusted (out of order, or ahead of the router's clock) are stored but
        flagged, and kept out of outage analysis."""
        new, latest = 0, None
        wan_iface = self.db.get_kv("router_wan_iface")
        for line in lines:
            line = line.replace("\x00", "").strip()
            if not line:
                continue
            parsed = parse_line(line, tz, router_now)
            if not parsed:
                continue
            ts, prog, text = parsed
            if latest is not None and ts < latest - 300:
                # When DST ends, an hour of local times happens twice; a line from the second
                # pass first parses an hour early. Try it as the second occurrence. (The same
                # local time logged once in each pass, with nothing between, can't be told
                # apart from the log alone; it's placed in the first pass, not flagged.)
                again = parse_line(line, tz, router_now, fold=1)
                if again and again[0] >= latest - 300:
                    ts, prog, text = again
            kind, data = classify_line(ts, prog, text, wan_iface)
            if kind.startswith("dhcp_") and data.get("iface") and data["iface"] != wan_iface:
                # The WAN DHCP client names its interface: that's the WAN for link events.
                wan_iface = data["iface"]
                self.db.set_kv("router_wan_iface", wan_iface)
            data.update(prog=prog, text=text[:500])
            # A clock reset (after a power cut, before NTP syncs) shows up as lines that jump
            # backwards in a file that's written in order, or as lines from the future.
            if (latest is not None and ts < latest - 300) or ts > router_now + 86400:
                data["clock_suspect"] = True
            else:
                latest = ts if latest is None else max(latest, ts)
            uid = "rl:" + hashlib.sha1(line.encode()).hexdigest()
            if self.db.add_event("router_log", kind, line[:500], data=data, ts=ts, uid=uid):
                new += 1
        return new


def _fingerprint(openssh_key):
    """Key type and SHA256 fingerprint, e.g. 'ssh-ed25519 SHA256:...'."""
    try:
        key = asyncssh.import_public_key(openssh_key)
        return f"{key.get_algorithm()} {key.get_fingerprint()}"
    except (asyncssh.KeyImportError, ValueError):
        return "unreadable pinned key"


def _isfloat(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
