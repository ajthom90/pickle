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

### 2. Run it

The image is published to GHCR as `ghcr.io/ajthom90/pickle` (amd64 and arm64) by
`.github/workflows/docker.yml` on every push to `main`. Pushing a `v1.2.3` tag also
publishes `1.2.3` and `1.2` tags. If the repository is private, the package is too.
Either make the package public (GitHub → your profile → Packages → pickle → Package
settings) or `docker login ghcr.io` on the host with a token that has `read:packages`.

**TrueNAS SCALE:** use [`deploy/truenas-compose.yaml`](deploy/truenas-compose.yaml):
Apps → Discover Apps → ⋮ → *Install via YAML*. Create the config and data folders
first, and put `config.yaml` and `wg0.conf` in the config folder.

**Any other Docker host:**

```sh
git clone <this repo> pickle && cd pickle
cp config/config.example.yaml config/config.yaml   # set target.wan_host, gateway_lan_ip
cp ~/Downloads/<client>.conf config/wg0.conf
echo "UNIFI_API_KEY=xxxxxxxx" > .env
docker compose up -d --build
```

Open `http://<docker-server>:8080`. Set `PICKLE_USERNAME` / `PICKLE_PASSWORD` if the port
is reachable by anyone but you.

`target.wan_host` can be a DDNS hostname. Pickle re-resolves it every minute, logs IP
changes, and re-points the tunnel when it goes stale.

**Two connections, one container:** checks marked *external* use the host's normal
internet connection. Checks marked *vpn* bind to the tunnel address, and a routing rule
inside the container sends only that traffic through `wg0`. The container needs
`NET_ADMIN` for this, but it all happens in the container's own network namespace, so
the host's routing is untouched. If the host kernel has no WireGuard module (some NAS
boxes), pass `/dev/net/tun` into the container and it falls back to `wireguard-go`.

## Finding the ISP's router

UniFi doesn't show it prominently, but his gateway has a default gateway of its own: the
ISP's router his connection terminates on (for fiber usually a BNG, or the OLT's routed
interface). Pickle finds it in this order:

1. **The UniFi API**: the gateway's WAN next hop (`wan1.gateway` on the device).
2. **A traceroute through the tunnel**: the first hop after his router.
3. **`target.isp_gateway`** in the config, which overrides both.

It's remembered across restarts, a change is logged as an event, and it's pinged
**from the internet and through the tunnel**. That's the key comparison:

- His WAN dark, ISP gateway answering from outside → the ISP's router is fine and his
  connection to it isn't (fiber, ONT, session) — or his router, if it rebooted.
- His WAN dark *and* ISP gateway dark from outside → the ISP's network.

If the gateway address is private (CGNAT, `100.64.0.0/10`, or RFC 1918), it can only be
pinged from inside. The outside check then says so instead of reporting failures. In that
case the external comparison falls back to the **last hop before him** on a traceroute
from the monitor, which is tracked separately (`target.isp_hop_external`).

Checks that were already failing in the hour before an outage (an ISP router that never
answers ping, say) are left out of that outage's verdict.

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
