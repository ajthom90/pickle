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
import logging
import re
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import asyncssh

log = logging.getLogger("pickle.routerlog")

GREP = "grep -iE 'dhcp|udhcpc|wan'"
# The only commands pickle ever runs on the router. All read-only, all constant strings.
COMMANDS = {
    # router clock (epoch), UTC offset, zone name, uptime: to place syslog lines in time
    "clock": ("date +%s; date +%z; cat /etc/timezone 2>/dev/null || "
              "readlink /etc/localtime 2>/dev/null; echo; cat /proc/uptime"),
    # which log sources exist
    "probe": ("test -f /var/log/messages && echo messages; "
              "command -v logread >/dev/null 2>&1 && echo logread; "
              "command -v journalctl >/dev/null 2>&1 && echo journalctl; true"),
    "messages": f"{GREP} /var/log/messages | tail -n 2000",
    "messages_backfill": f"{GREP} /var/log/messages | tail -n 20000",
    "logread": f"logread | {GREP} | tail -n 2000",
    "logread_backfill": f"logread | {GREP} | tail -n 20000",
    "journalctl": f"journalctl -o short-iso --no-pager -q -n 50000 | {GREP} | tail -n 2000",
    "journalctl_backfill": f"journalctl -o short-iso --no-pager -q -n 200000 | {GREP} | tail -n 20000",
}
SOURCES = ["messages", "logread", "journalctl"]

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

PATTERNS = [
    # udhcpc (busybox): "lease of 93.187.143.116 obtained from 93.187.140.1, lease time 86400"
    ("dhcp_lease", re.compile(r"lease of (?P<ip>[\d.]+) obtained(?: from (?P<server>[\d.]+))?,?\s+"
                              r"lease time (?P<lease_time>\d+)", re.I)),
    ("dhcp_renew", re.compile(r"sending renew(?: to (?P<server>[\d.]+))?|performing dhcp renew", re.I)),
    ("dhcp_rebind", re.compile(r"sending rebind", re.I)),
    ("dhcp_select", re.compile(r"sending select for (?P<ip>[\d.]+)", re.I)),
    ("dhcp_discover", re.compile(r"sending discover|DHCPDISCOVER", re.I)),
    ("dhcp_nak", re.compile(r"\bDHCPNAK\b|received.*\bNAK\b", re.I)),
    ("dhcp_lost", re.compile(r"lease lost|no lease, failing", re.I)),
    ("dhcp_release", re.compile(r"sending release|DHCPRELEASE", re.I)),
    # dhclient (ISC): "DHCPACK of X from Y", "bound to X -- renewal in N seconds"
    ("dhcp_ack", re.compile(r"DHCPACK(?: of (?P<ip>[\d.]+))?(?: from (?P<server>[\d.]+))?", re.I)),
    ("dhcp_ack", re.compile(r"bound to (?P<ip>[\d.]+) -- renewal in (?P<renewal_in>\d+)", re.I)),
    ("dhcp_renew", re.compile(r"DHCPREQUEST", re.I)),
]
REQUESTS = {"dhcp_renew", "dhcp_rebind", "dhcp_select", "dhcp_discover"}
ANSWERS = {"dhcp_lease", "dhcp_ack"}


def classify_line(ts, prog, text):
    """(kind, data) for a log line's text."""
    for kind, rx in PATTERNS:
        m = rx.search(text)
        if m:
            data = {k: v for k, v in m.groupdict().items() if v is not None}
            for k in ("lease_time", "renewal_in"):
                if k in data:
                    data[k] = int(data[k])
            if kind == "dhcp_lease":
                # same keys as the UniFi lease events, so lease timing can use either
                data["obtained"] = ts
                data["expires"] = ts + data["lease_time"]
            return kind, data
    return "log", {}


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
        r = await conn.run(COMMANDS[name], check=False, timeout=120)
        return r.stdout or ""

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
        source = next((s for s in SOURCES if s in available), None)
        if not source:
            self._set("connected", "no /var/log/messages, logread or journalctl on the router")
            self.status["last_ok"] = time.time()
            return
        backfill = not self.db.get_kv("router_log_backfilled")
        out = await self._run(conn, source + ("_backfill" if backfill else ""))
        new = self.store(out.splitlines(), tz, router_now, boot)
        if backfill:
            self.db.set_kv("router_log_backfilled", time.time())
        self.status.update(source=source, new_lines=new, last_ok=time.time())
        self._set("connected", f"{new} new line(s) from {source}")

    def store(self, lines, tz, router_now, boot=None):
        """Store new lines as events. Dedup is by a hash of the whole line only, so rotated
        logs and lines with odd timestamps are never dropped as 'already seen'. Lines whose
        time can't be trusted (out of order, or ahead of the router's clock) are stored but
        flagged, and kept out of outage analysis."""
        new, latest = 0, None
        for line in lines:
            line = line.rstrip()
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
            kind, data = classify_line(ts, prog, text)
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
