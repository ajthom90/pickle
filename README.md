# pickle

Pickle is a WAN monitoring system that runs in a Docker container. It's built to settle one
argument: when a UniFi network says "internet down", **is it the ISP or the router?**

It runs somewhere *outside* the network being watched (your own Docker server) and looks at
the connection from three sides at once:

| Path | What it checks | What it proves |
|---|---|---|
| **From the internet** | Pings his WAN IP, and the ISP's own router just upstream of it | Whether his connection is reachable, and whether the ISP's network next to him is |
| **Control** | Pings well-known hosts from the monitor's own connection | That a failure wasn't on *your* side |
| **Through his router** (WireGuard) | Pings, DNS, and HTTPS to the internet *from his connection*; his gateway's LAN IP; the ISP's first hop from inside | Partial failures (loss, DNS, routing) while the line is up |
| **His gateway** (UniFi API, via the tunnel) | Uptime, WAN port state, WAN IP, UniFi's own WAN monitor and drop counter, alarm/event log | Whether the router rebooted or its WAN port dropped, and whether UniFi's alerts matched reality |

Every result is stored with a timestamp. Failures are grouped into **outages**, and each outage
gets a verdict based on which layers failed together:

| What happened | Verdict |
|---|---|
| Control hosts failed too | **Inconclusive.** The monitor's own internet was down |
| Gateway uptime reset during the window | **Router.** It rebooted |
| His WAN *and* the ISP's upstream router both unreachable | **ISP network** |
| His WAN unreachable, ISP's upstream router fine, no reboot | **Last mile / WAN link**: fiber, ONT, or ISP session (DHCP/PPPoE). A UniFi "WAN port DOWN" event points at the ONT |
| WAN reachable from outside, but his router couldn't reach the internet | **ISP upstream routing** |
| Only VPN checks failed | **VPN tunnel only.** Not an internet outage |
| Only DNS failed | **DNS only** |

It also lists every UniFi WAN alert next to whether the external checks saw his WAN go down at
that moment. UniFi's WAN monitor raises false alarms when its ping targets rate-limit or drop
ICMP, so an uncorroborated alert is worth knowing about.

> **Limitation:** when his internet is down, the WireGuard tunnel is down too. Hard outages are
> diagnosed from the outside checks plus what the gateway reports once it's reachable again
> (uptime, WAN port events, alarms). The tunnel checks catch the partial failures in between.

## Setup

### 1. On his UniFi gateway

1. **Let the WAN answer pings.** Without this, his WAN can't be distinguished from "down".
   On recent UniFi Network versions, ICMP to the gateway from the internet may be blocked by
   default; allow ICMP echo-request on the External/WAN zone to the Gateway.
2. **WireGuard client.** Settings → VPN → VPN Server (WireGuard) → add a client, download its
   config, and save it as `config/wg0.conf`. (See `config/wg0.conf.example`.) Pickle only routes
   its own probes through the tunnel, never your Docker host's traffic, and it overrides
   `AllowedIPs`, `DNS` and `Table` on its side to make that work.
3. **UniFi API key.** UniFi Network → Settings → Control Plane → Integrations → create an API key.
   A local (non-SSO) admin username/password also works (`unifi.username` / `unifi.password`).

### 2. On your Docker server

```sh
git clone <this repo> pickle && cd pickle
cp config/config.example.yaml config/config.yaml   # set target.wan_host, gateway_lan_ip
cp ~/Downloads/<client>.conf config/wg0.conf
echo "UNIFI_API_KEY=xxxxxxxx" > .env
docker compose up -d --build
```

Open `http://<docker-server>:8080`. Set `PICKLE_USERNAME` / `PICKLE_PASSWORD` in
`docker-compose.yml` if the port is reachable by anyone but you.

`target.wan_host` can be a DDNS hostname. Pickle re-resolves it every minute, logs IP
changes, and re-points the tunnel when it goes stale.

**Requirements:** the container needs `NET_ADMIN` (already in the compose file) to create
its own `wg0` and routing rules inside its network namespace. Your host's routing is not
touched. If the host kernel has no WireGuard module (some NAS boxes), uncomment the
`/dev/net/tun` device in `docker-compose.yml` and it falls back to `wireguard-go`.

## Finding the ISP's routers

The ISP router "just upstream of his WAN" is found by traceroute. From outside, it's the last
hop before his WAN IP. From inside, UniFi reports the WAN next hop directly, with a traceroute
as fallback. Traceroutes rerun hourly, and again whenever his WAN starts failing (the
"during failure" trace in the event log shows where the path died). If the ISP filters
traceroutes, set `target.isp_hop_external` / `wireguard.isp_hop_inside` by hand.

## Exports

Every export takes the range selected in the UI (or `?hours=`, or `?since=&until=` as Unix
timestamps):

- `/export/results.csv`, `/export/results.json`: every check result (timestamp, check, path,
  target, success/failure, latency, packet loss, detail). Add `&check=<id>` for one check.
- `/export/outages.csv`: outage windows with verdict and evidence
- `/export/events.csv`: reboots, IP changes, UniFi alarms, failure traceroutes
- `/report`: a printable summary to send the ISP (print → save as PDF)

`/api/unifi/raw` shows exactly what the UniFi API returned, which helps if a field shows up
empty on his firmware version.

## Configuration

See `config/config.example.yaml`. Everything except `target.wan_host` has a default. Defaults:
checks every 15 s, an incident after 2 consecutive failures, 90 days of retention.
Extra checks (`ping`, `tcp`, `dns`, `http`, over `external` or `vpn`) can be added under
`extra_checks`.
