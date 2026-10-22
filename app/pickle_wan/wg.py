"""Brings up the WireGuard tunnel to his gateway without hijacking the container's routes.

wg-quick would install a default route through the tunnel, which would send the
"external" checks through his connection too and make them meaningless. Instead,
the tunnel gets its own routing table, and only traffic *sourced from the tunnel
address* uses it:

    ip route add default dev wg0 table 51820
    ip rule add from <tunnel address> lookup 51820

Probes that should go through his connection bind to the tunnel address.
"""
import asyncio
import logging
import os
import socket
import subprocess
import time

log = logging.getLogger("pickle.wg")

IFACE = "wg0"
TABLE = "51820"
STALE_HANDSHAKE = 180  # seconds

# Keys `wg setconf` understands; everything else is wg-quick-only.
WG_INTERFACE_KEYS = {"privatekey", "listenport", "fwmark"}
WG_PEER_KEYS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}


def parse(path):
    sections = []
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and line.endswith("]"):
                sections.append((line[1:-1].strip().lower(), []))
            elif "=" in line and sections:
                k, v = line.split("=", 1)
                sections[-1][1].append((k.strip(), v.strip()))
    return sections


class Tunnel:
    def __init__(self, cfg):
        self.path = cfg["config"]
        self.addresses = []
        self.peer_key = None
        self.endpoint_host = None
        self.endpoint_port = None
        self.endpoint_ip = None
        self.up = False
        self.userspace = False
        self.error = None

    @property
    def source(self):
        """IPv4 tunnel address probes bind to."""
        for a in self.addresses:
            if ":" not in a:
                return a
        return None

    def bring_up(self):
        try:
            self._bring_up()
            self.up = True
            self.error = None
        except Exception as e:  # noqa: BLE001 - surfaced in the UI instead of crashing
            self.error = str(e)
            log.error("WireGuard setup failed: %s", e)

    def _bring_up(self):
        sections = parse(self.path)
        iface = [kv for name, kv in sections if name == "interface"]
        peers = [kv for name, kv in sections if name == "peer"]
        if not iface or not peers:
            raise RuntimeError(f"{self.path} needs an [Interface] and a [Peer] section")

        mtu = "1420"
        lines = ["[Interface]"]
        for k, v in iface[0]:
            lk = k.lower()
            if lk == "address":
                self.addresses += [a.strip().split("/")[0] for a in v.split(",") if a.strip()]
            elif lk == "mtu":
                mtu = v
            elif lk in WG_INTERFACE_KEYS:
                lines.append(f"{k} = {v}")
        if not self.source:
            raise RuntimeError("[Interface] Address must include an IPv4 address")

        peer = peers[0]
        lines.append("[Peer]")
        has_keepalive = False
        for k, v in peer:
            lk = k.lower()
            if lk == "allowedips":
                # Our side must accept/send any destination through the tunnel; the
                # separate routing table keeps that from affecting other traffic.
                v = "0.0.0.0/0" + (", ::/0" if any(":" in a for a in self.addresses) else "")
            elif lk == "publickey":
                self.peer_key = v
            elif lk == "endpoint":
                # Set separately below, so an unresolvable DDNS name doesn't block startup.
                host, _, port = v.rpartition(":")
                self.endpoint_host, self.endpoint_port = host.strip("[]"), port
                continue
            elif lk == "persistentkeepalive":
                has_keepalive = True
            if lk in WG_PEER_KEYS:
                lines.append(f"{k} = {v}")
        if not has_keepalive:
            lines.append("PersistentKeepalive = 25")

        stripped = "/tmp/wg0.stripped.conf"
        with open(stripped, "w") as f:
            f.write("\n".join(lines) + "\n")

        _sh(["ip", "link", "del", IFACE], check=False)
        r = _sh(["ip", "link", "add", IFACE, "type", "wireguard"], check=False)
        if r.returncode != 0:
            # No kernel WireGuard on the Docker host: fall back to the userspace implementation.
            if not os.path.exists("/dev/net/tun"):
                raise RuntimeError("the Docker host has no kernel WireGuard support; pass "
                                   "/dev/net/tun to the container (see docker-compose.yml) to "
                                   "use the userspace fallback. ip said: " + r.stderr.strip())
            u = subprocess.run(["wireguard-go", IFACE], capture_output=True, text=True,
                               env=os.environ | {"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD": "1"})
            if u.returncode != 0:
                raise RuntimeError("wireguard-go failed: " + (u.stderr or u.stdout).strip())
            self.userspace = True
            log.info("kernel WireGuard unavailable; using wireguard-go")
        _sh(["wg", "setconf", IFACE, stripped])
        for a in self.addresses:
            _sh(["ip", "-6" if ":" in a else "-4", "address", "add",
                 a + ("/128" if ":" in a else "/32"), "dev", IFACE])
        _sh(["ip", "link", "set", "mtu", mtu, "up", "dev", IFACE])
        _sh(["ip", "-4", "route", "replace", "default", "dev", IFACE, "table", TABLE])
        _sh(["ip", "-4", "rule", "del", "priority", "100"], check=False)
        _sh(["ip", "-4", "rule", "add", "from", self.source, "lookup", TABLE, "priority", "100"])
        if self.endpoint_host:
            try:
                ip = socket.getaddrinfo(self.endpoint_host, None, family=socket.AF_INET)[0][4][0]
                self.set_endpoint(ip)
            except socket.gaierror as e:
                log.warning("can't resolve endpoint %s yet (%s); will retry", self.endpoint_host, e)
        log.info("WireGuard up: %s -> %s:%s", self.source, self.endpoint_host, self.endpoint_port)

    def set_endpoint(self, ip):
        _sh(["wg", "set", IFACE, "peer", self.peer_key, "endpoint", f"{ip}:{self.endpoint_port}"])
        self.endpoint_ip = ip

    def handshake_age(self):
        """Seconds since the last handshake, or None if never."""
        r = _sh(["wg", "show", IFACE, "latest-handshakes"], check=False)
        if r.returncode != 0:
            return None
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] != "0":
                return max(0.0, time.time() - int(parts[1]))
        return None

    def transfer(self):
        r = _sh(["wg", "show", IFACE, "transfer"], check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3:
                return int(parts[1]), int(parts[2])
        return None, None

    async def watchdog(self, on_event):
        """Re-resolve a DDNS endpoint when the tunnel goes stale (his WAN IP may have changed)."""
        while True:
            await asyncio.sleep(30)
            if not self.up or not self.endpoint_host:
                continue
            age = self.handshake_age()
            if age is not None and age < STALE_HANDSHAKE:
                continue
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    self.endpoint_host, None, family=socket.AF_INET)
            except socket.gaierror:
                continue
            ip = infos[0][4][0]
            if ip != self.endpoint_ip:
                previous = self.endpoint_ip
                try:
                    self.set_endpoint(ip)
                except RuntimeError as e:
                    log.warning("could not update endpoint: %s", e)
                    continue
                if previous:
                    on_event("tunnel", "endpoint_update",
                             f"Tunnel stale; {self.endpoint_host} now resolves to {ip} (was {previous})")


def _sh(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r
