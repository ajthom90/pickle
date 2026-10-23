"""Loads /config/config.yaml and builds the list of checks to run."""
import os
import re

import yaml
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .analysis import VERDICTS

CONFIG_PATH = os.environ.get("PICKLE_CONFIG", "/config/config.yaml")

# Roles drive the outage verdicts in analysis.py:
#   wan       - his WAN IP, probed from the internet
#   isp_hop   - ISP routers just upstream of his WAN (his WAN's default gateway, and the
#               last traceroute hop before him), probed from the internet
#   control   - well-known hosts probed from the monitor's own connection
#   tunnel    - WireGuard handshake freshness
#   gateway   - his gateway's LAN IP, through the tunnel
#   isp_hop_inside - his WAN's default gateway (the ISP's router), probed through the tunnel
#   internet  - internet hosts reached through his connection
#   dns       - name resolution through his connection
#   gateway_api - the UniFi API itself
ROLES = ["wan", "isp_hop", "control", "tunnel", "gateway", "isp_hop_inside",
         "internet", "dns", "gateway_api"]

DEFAULTS = {
    # Everything is stored and computed in UTC; this is only the timezone times are shown
    # in (dashboard, report). Empty = the container's TZ environment variable, else UTC.
    "display_timezone": "",
    "interval_seconds": 15,
    "fail_threshold": 2,
    "retention_days": 90,
    "target": {"wan_host": "", "tcp_ports": [], "isp_hop_external": "auto",
               "isp_gateway": "auto"},
    "control_targets": ["1.1.1.1", "8.8.8.8"],
    "wireguard": {
        "enabled": True,
        "config": "/config/wg0.conf",
        "gateway_lan_ip": "192.168.1.1",
        "internet_targets": ["1.1.1.1", "8.8.8.8"],
        "dns_servers": ["1.1.1.1"],
        "dns_query": "www.google.com",
        "gateway_dns": True,
        "http_url": "https://www.google.com/generate_204",
    },
    "unifi": {
        "enabled": False,
        "url": "https://192.168.1.1",
        "api_key": "",
        "username": "",
        "password": "",
        "site": "default",
        "verify_tls": False,
        "interval_seconds": 30,
        # His plan's speeds, to show load as a share of the line. 0 = use UniFi's last
        # speed test if there is one.
        "wan_down_mbps": 0,
        "wan_up_mbps": 0,
    },
    # Optional: read DHCP/WAN lines from the router's log over SSH, through the tunnel.
    "ssh": {
        "enabled": False,
        "host": "",              # default: wireguard.gateway_lan_ip
        "port": 22,
        "username": "root",
        "password": "",
        "key_file": "",          # e.g. /config/router_ed25519 (the config folder is mounted read-only)
        "host_key": "",          # pin a known key ("ssh-ed25519 AAAA..."); empty = pin on first connect
    },
    "ntfy": {
        "enabled": False,
        "server": "https://ntfy.sh",
        "topic": "",
        # Authentication, for servers that require it: an access token (tk_...), or a
        # username and password. The token wins if both are set.
        "token": "",
        "username": "",
        "password": "",
        "verify_tls": True,
        "min_duration_seconds": 60,
        "priority_down": "high",
        "priority_up": "default",
        "ignore_verdicts": [],
        "click_url": "",
        # Appended to the "outage started" message for whoever is on site. {isp_gateway} is
        # replaced with his WAN's default gateway. Set to "" to leave it out.
        "onsite_note": (
            "On site, before touching anything:\n"
            "1. Photograph the ONT (Network Status light, ETH1 lights).\n"
            "2. If you can, SSH to the router and run `ping {isp_gateway}` and `ip neigh` "
            "(note whether {isp_gateway} shows FAILED or INCOMPLETE), and `ip -s link show "
            "{wan_iface}` twice, 10 s apart (note whether RX packets keep rising).\n"
            "3. Then re-plug only the router's WAN cable and note the time."),
    },
    "checks": None,
    "extra_checks": [],
}

# Secrets can come from the environment instead of config.yaml.
ENV_FALLBACKS = [
    ("UNIFI_API_KEY", "unifi", "api_key"),
    ("NTFY_TOKEN", "ntfy", "token"),
    ("SSH_PASSWORD", "ssh", "password"),
    ("NTFY_USERNAME", "ntfy", "username"),
    ("NTFY_PASSWORD", "ntfy", "password"),
]

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand(value):
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path=CONFIG_PATH):
    raw = {}
    if os.path.exists(path):
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    cfg = _merge(DEFAULTS, _expand(raw))
    for var, section, key in ENV_FALLBACKS:
        if os.environ.get(var) and not cfg[section][key]:
            cfg[section][key] = os.environ[var]
    if not cfg["target"]["wan_host"]:
        raise SystemExit("config: target.wan_host is required (his WAN IP or DDNS name)")
    sh = cfg["ssh"]
    if sh["enabled"]:
        if not cfg["wireguard"]["enabled"]:
            raise SystemExit("config: ssh needs wireguard enabled (the router is reached through the tunnel)")
        if not (sh["password"] or sh["key_file"]):
            raise SystemExit("config: ssh.enabled needs ssh.password (or SSH_PASSWORD) or ssh.key_file")
        if sh["key_file"] and not os.path.exists(sh["key_file"]):
            raise SystemExit(f"config: ssh.key_file {sh['key_file']} doesn't exist")
        sh["host"] = sh["host"] or cfg["wireguard"]["gateway_lan_ip"]
        sh["port"] = int(sh["port"])
    n = cfg["ntfy"]
    if n["enabled"]:
        if not n["topic"]:
            raise SystemExit("config: ntfy.topic is required when ntfy is enabled")
        if not n["server"].startswith(("http://", "https://")):
            raise SystemExit("config: ntfy.server must start with http:// or https://")
        if n["onsite_note"] is None:
            n["onsite_note"] = ""
        if not isinstance(n["onsite_note"], str):
            raise SystemExit("config: ntfy.onsite_note must be text (or \"\" to leave it out)")
        unknown = set(n["ignore_verdicts"] or []) - set(VERDICTS)
        if unknown:
            raise SystemExit(f"config: ntfy.ignore_verdicts has unknown verdicts {sorted(unknown)}")
    tzname = (cfg.get("display_timezone") or os.environ.get("TZ") or "UTC").strip().lstrip(":")
    try:
        ZoneInfo(tzname)
    except (ZoneInfoNotFoundError, ValueError):
        raise SystemExit(f"config: display_timezone / TZ {tzname!r} isn't a known timezone "
                         f"(use a name like America/Chicago)")
    cfg["display_timezone"] = tzname
    cfg["checks"] = build_checks(cfg)
    return cfg


def build_checks(cfg):
    if cfg.get("checks"):
        checks = list(cfg["checks"])
    else:
        checks = default_checks(cfg)
    checks += cfg.get("extra_checks") or []
    seen = set()
    for c in checks:
        c.setdefault("via", "external")
        c.setdefault("role", "internet" if c["via"] == "vpn" else "control")
        c.setdefault("interval", cfg["interval_seconds"])
        c.setdefault("name", c["id"])
        if c["id"] in seen:
            raise SystemExit(f"config: duplicate check id {c['id']}")
        if c["role"] not in ROLES:
            raise SystemExit(f"config: check {c['id']} has unknown role {c['role']}")
        seen.add(c["id"])
    return checks


def default_checks(cfg):
    t = cfg["target"]
    checks = [
        {"id": "ext_wan_ping", "name": "His WAN IP (ping)", "via": "external",
         "type": "ping", "target": "{wan}", "role": "wan"},
        {"id": "ext_isp_gateway_ping", "name": "ISP gateway (his WAN's default gateway)",
         "via": "external", "type": "ping", "target": "{isp_gateway}", "role": "isp_hop"},
        {"id": "ext_isp_hop_ping", "name": "ISP router before him (traceroute hop)",
         "via": "external", "type": "ping", "target": "{isp_hop_external}", "role": "isp_hop"},
    ]
    for port in t.get("tcp_ports") or []:
        checks.append({"id": f"ext_wan_tcp_{port}", "name": f"His WAN IP (TCP {port})",
                       "via": "external", "type": "tcp", "target": "{wan}", "port": int(port),
                       "role": "wan"})
    for host in cfg["control_targets"]:
        checks.append({"id": f"ext_control_{_slug(host)}", "name": f"Control: {host} from monitor",
                       "via": "external", "type": "ping", "target": host, "role": "control"})

    wg = cfg["wireguard"]
    if wg["enabled"]:
        checks += [
            {"id": "vpn_tunnel", "name": "WireGuard tunnel handshake", "via": "vpn",
             "type": "tunnel", "target": "wg0", "role": "tunnel"},
            {"id": "vpn_gateway_ping", "name": "His gateway LAN IP (ping)", "via": "vpn",
             "type": "ping", "target": wg["gateway_lan_ip"], "role": "gateway"},
            {"id": "vpn_isp_gateway_ping", "name": "ISP gateway (his WAN's default gateway)",
             "via": "vpn", "type": "ping", "target": "{isp_gateway}", "role": "isp_hop_inside"},
        ]
        for host in wg["internet_targets"]:
            checks.append({"id": f"vpn_inet_{_slug(host)}", "name": f"{host} via his connection (ping)",
                           "via": "vpn", "type": "ping", "target": host, "role": "internet"})
        if wg.get("http_url"):
            checks.append({"id": "vpn_http", "name": "HTTPS fetch via his connection", "via": "vpn",
                           "type": "http", "target": wg["http_url"], "role": "internet"})
        for server in wg["dns_servers"]:
            checks.append({"id": f"vpn_dns_{_slug(server)}", "name": f"DNS via {server} through his connection",
                           "via": "vpn", "type": "dns", "target": server, "query": wg["dns_query"],
                           "role": "dns"})
        if wg.get("gateway_dns"):
            checks.append({"id": "vpn_dns_gateway", "name": "DNS via his gateway", "via": "vpn",
                           "type": "dns", "target": wg["gateway_lan_ip"],
                           "query": wg["dns_query"], "role": "dns"})
    return checks


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
