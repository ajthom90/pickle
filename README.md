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
| His WAN unreachable, ISP's gateway answering, no reboot, his WAN link stayed up (or only dropped late, i.e. someone reconnecting), and service came back when the link was reconnected or the DHCP lease renewed | **ISP session / DHCP**: the line and ONT work, but the ISP stopped serving his router's existing session until a fresh DHCP exchange |
| His WAN unreachable, ISP's upstream router fine, no reboot, otherwise | **Last mile / WAN link**: the fiber, the ONT, or a port actually dropping. A UniFi "WAN port DOWN" at the start points at the ONT |
| WAN reachable from outside, but his router couldn't reach the internet | **ISP upstream routing** |
| Only VPN checks failed | **VPN tunnel only.** Not an internet outage |
| Only DNS failed | **DNS only** |

It also lists every UniFi WAN alert next to whether the external checks saw his WAN go down at
that moment. UniFi's WAN monitor raises false alarms when its ping targets rate-limit or drop
ICMP, so an uncorroborated alert is worth knowing about.

> **Limitation:** when his internet is down, the WireGuard tunnel is down too. Hard outages are
> diagnosed from the outside checks plus what the gateway reports once it's reachable again
> (uptime, WAN port events, alarms). The tunnel checks catch the partial failures in between.

A reboot only counts toward an outage if the gateway's boot time (now minus its uptime,
accurate to about a minute) falls inside the outage, give or take 60 s. A reboot after his
internet already came back belongs to whatever happened next, not to that outage.

### Outage notes

Any outage can carry a note from the dashboard (**Add note** under its explanation), e.g.
"Ed moved router to wall power ~10:59 PM". Notes show in the Outages panel, the outages CSV
and `/report`. Tick **Human action** when someone on site caused the reboot or WAN port
changes in that window. Those events then stay listed but don't decide the verdict, and the
explanation says they were set aside.

### DHCP lease and recovery evidence

Each outage also shows where it fell relative to his router's **DHCP lease**: how long after
the lease was obtained, and whether a renewal (T/2), rebind (7T/8) or expiry was due during or
just before it. If it lines up with a renewal, the explanation says so. UniFi doesn't document
lease fields and they vary by firmware, so pickle collects every lease-looking field it finds
(shown raw on the dashboard and at `/api/unifi/raw`). It only interprets epoch timestamps
and plausible durations. When nothing is exposed, outages say "lease timing unknown". Lease
renewals are logged as events.

The first UniFi poll after the gateway becomes reachable again is saved as a **recovery
snapshot**, attached to the outage: WAN IP, gateway, WAN port, lease details, and WAN uptime
if reported. It's the closest pickle can get to the router's state during the outage, since
the tunnel was down.

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
# paste your UniFi API key into UNIFI_API_KEY in docker-compose.yml
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

## Load vs. outages

Every UniFi poll also records his gateway's load: WAN throughput (averaged from the
gateway's byte counters since the previous poll), CPU, memory, temperature and connected
clients. The dashboard charts them with outages shaded, and each outage shows the peak
load in the 10 minutes before it started.

To tell whether load is *linked* to outages, pickle ranks each outage's pre-outage peak
against every 10-minute stretch on record. If load doesn't matter, about 10% of outages
land in the busiest 10% by chance. The table reports how many actually did, with a
binomial test, once there's a day of history and at least 3 outages. What a link would
mean:

- **CPU or memory high before outages:** the router is struggling. Router fault.
- **Throughput near the line's speed:** the line is saturated. Latency and loss spike,
  which can trip UniFi's WAN monitor even though nothing actually dropped. Compare with
  the external checks.
- **Linked to throughput, but well below line speed and CPU normal:** outages come at
  busy times without his line or router being stretched. That points at congestion in
  the ISP's network at peak hours, which is the ISP's problem, not his router's.
- **No link:** load isn't a factor; the outage verdicts stand on their own.

Set `unifi.wan_down_mbps` / `wan_up_mbps` to his plan's speeds to show load as a share of
the line; otherwise UniFi's last speed test is used, if there is one.

## Exports

Every export takes the range selected in the UI (or `?hours=`, or `?since=&until=` as Unix
timestamps):

- `/export/results.csv`, `/export/results.json`: every check result (timestamp, check, path,
  target, success/failure, latency, packet loss, detail). Add `&check=<id>` for one check.
- `/export/outages.csv`: outage windows with verdict and evidence, DHCP lease timing, and
  the gateway's WAN state right after recovery
- `/export/load.csv`: gateway load samples (throughput, CPU, memory, temperature, clients)
- `/export/events.csv`: reboots, IP changes, UniFi alarms, failure traceroutes
- `/report`: a printable summary to send the ISP (print → save as PDF)

`/api/unifi/raw` shows exactly what the UniFi API returned, which helps if a field shows up
empty on his firmware version.

## Notifications (ntfy)

Pickle can push outage alerts through [ntfy](https://ntfy.sh), either ntfy.sh or a
self-hosted server. Turn it on in the `ntfy:` section of `config.yaml`. Each outage
sends two messages:

- **Started**, once it has lasted `min_duration_seconds` (default 60), naming the
  failing checks and an early verdict.
- **Resolved**, a minute after it ends (so a flapping line doesn't send a pair per flap),
  with the duration and the final verdict and explanation.

The started message ends with an on-site checklist for whoever is at the house:
photograph the ONT, ping the ISP gateway and check `ip neigh` on the router (a FAILED or
INCOMPLETE entry for the gateway means the ISP side stopped answering), then re-plug only
the router's WAN cable and note the time. Change it with `onsite_note` (`{isp_gateway}` is
filled in), or set `onsite_note: ""` to leave it out.

Shorter outages send nothing. What's been sent is stored in the database, so a restart
doesn't repeat it. `ignore_verdicts` skips outages you don't care about, e.g.
`[tunnel, monitor]` for VPN-only blips and ones caused by your own connection.

**Servers that require login:** set `token` to an access token (`ntfy token add <user>`
on the server), or `username` and `password`. The token is used if both are set. To keep
secrets out of `config.yaml`, use the `NTFY_TOKEN`, `NTFY_USERNAME` and `NTFY_PASSWORD`
environment variables instead. The user needs write access to the topic.

To check the setup, use **Send test notification** on the dashboard (next to *Re-run
path discovery*), or `curl -X POST http://<docker-server>:8080/api/ntfy/test`. A failure
shows the server's answer, e.g. `HTTP 401` for bad credentials or `HTTP 403` when the user
can't write to the topic.

## Router log over SSH (optional)

With `ssh.enabled`, pickle logs in to his router through the WireGuard tunnel every 5
minutes, and right after the gateway is reachable again after an outage, and reads its
DHCP/WAN log lines: `grep -iE "dhcp|udhcpc|wan" /var/log/messages`, or `logread` /
`journalctl` if that file doesn't exist. Each line is stored once, at the log line's own
time. Lines without a year or timezone are placed using the router's clock and timezone,
read in the same session, so DST changes are handled. The first collection reads further
back (up to 20,000 matching lines), so older outages can get router evidence too if the
router still has those lines.

udhcpc lines (renew sent, lease obtained with its lease time, discover, NAK, lease lost)
and common dhclient lines become structured events. Lease lines feed the lease timing
above. Each outage then lists the router's lines from 10 minutes before it to its end,
and calls out:

- **Renewal sent, no reply until the outage ended**: points at the ISP's DHCP server. It
  only says this when the log demonstrably covers the outage: there are lines after it,
  and no reboot inside it. Otherwise it says the reply can't be confirmed.
- **Renewal answered, then traffic stopped**: the router held a valid lease, so it points
  at the router or the ISP's session, not the DHCP exchange.
- **No DHCP activity during the outage**: the router still considered its lease valid.

Lines from a reset clock (after a power cut, before NTP syncs) show up out of order. They
are stored but flagged, and kept out of outage analysis. The dashboard's gateway panel shows
the SSH status (connected, auth failed, host key mismatch, unreachable), the router's clock
offset from the monitor, and the pinned host key fingerprint.

**Setup.** Turn on SSH for the console in UniFi (Settings → Control Plane → Console → SSH)
and set a password. Then set `ssh.enabled: true` and either `SSH_PASSWORD` in the compose
file or `ssh.key_file` pointing at a private key in the config folder, which is mounted
read-only.

**Host key.** On first connect pickle pins the router's SSH host key and shows its
fingerprint. Compare it with the router's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
on the router). If the key ever changes, pickle refuses to connect *before* sending the
password, and shows "host key mismatch". If the router was reset or replaced, put its new
key in `ssh.host_key`.

**Security tradeoff.** This gives the monitor root credentials for his router. Pickle only
ever runs a fixed list of read-only commands (`COMMANDS` in `routerlog.py`); nothing is
built from config or input. It uses only the configured password or key (no SSH agent,
default keys or `~/.ssh/config`), and connects only through the tunnel. But anyone who
gets into the monitor container, or can read its config folder or environment, gets root
on his router. If that's a concern:

- Use a key rather than a password, and keep the config folder readable only by the app.
- Leave it off and collect the log by hand when needed.
- Turn it off again once the ISP case is settled.

## Configuration

See `config/config.example.yaml`. Everything except `target.wan_host` has a default. Defaults:
checks every 15 s, an incident after 2 consecutive failures, 90 days of retention.
Extra checks (`ping`, `tcp`, `dns`, `http`, over `external` or `vpn`) can be added under
`extra_checks`.
