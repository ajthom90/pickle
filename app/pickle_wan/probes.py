"""Individual probe implementations.

Every probe takes an optional `source` IP. When set, sockets are bound to that
address, and the policy-routing rule created by wg.py sends the traffic through
the WireGuard tunnel. Unbound probes use the container's normal connection.

Each probe returns (ok, latency_ms, loss, detail).
"""
import asyncio
import re
import socket
import time

import dns.asyncquery
import dns.exception
import dns.message
import dns.rdatatype
import httpx

PING_COUNT = 3


async def run(cmd, timeout):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        return None, f"{cmd[0]} is not installed"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return None, "timed out"
    return proc.returncode, out.decode(errors="replace")


_SENT = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_RTT = re.compile(r"= [\d.]+/([\d.]+)/")


async def ping(target, source=None):
    cmd = ["ping", "-n", "-c", str(PING_COUNT), "-i", "0.2", "-W", "2"]
    if source:
        cmd += ["-I", source]
    cmd.append(target)
    code, out = await run(cmd, 10)
    if code is None:
        return False, None, 1.0, out
    m = _SENT.search(out)
    if not m:
        return False, None, 1.0, out.strip().splitlines()[-1] if out.strip() else "ping failed"
    sent, recv = int(m.group(1)), int(m.group(2))
    loss = 1 - recv / sent if sent else 1.0
    rtt = _RTT.search(out)
    latency = float(rtt.group(1)) if rtt else None
    return recv > 0, latency, loss, f"{recv}/{sent} replies"


async def tcp(target, port, source=None, timeout=5):
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, local_addr=(source, 0) if source else None),
            timeout)
    except asyncio.TimeoutError:
        return False, None, None, f"TCP {port}: timed out"
    except OSError as e:
        return False, None, None, f"TCP {port}: {e.strerror or e}"
    latency = (time.monotonic() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True, latency, None, f"TCP {port} open"


async def dns_query(server, query, source=None, timeout=4):
    msg = dns.message.make_query(query, dns.rdatatype.A)
    start = time.monotonic()
    try:
        resp = await dns.asyncquery.udp(msg, server, timeout=timeout, source=source)
    except dns.exception.Timeout:
        return False, None, None, f"{query}: timed out"
    except Exception as e:  # noqa: BLE001 - any resolver failure is a failed check
        return False, None, None, f"{query}: {type(e).__name__}: {e}"
    latency = (time.monotonic() - start) * 1000
    answers = [r.to_text() for rr in resp.answer for r in rr if rr.rdtype == dns.rdatatype.A]
    if not answers:
        return False, latency, None, f"{query}: no A records (rcode {resp.rcode()})"
    return True, latency, None, f"{query} -> {answers[0]}"


async def http(url, source=None, timeout=8):
    transport = httpx.AsyncHTTPTransport(local_address=source) if source else None
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(transport=transport, timeout=timeout,
                                     follow_redirects=False) as client:
            r = await client.get(url)
    except httpx.HTTPError as e:
        return False, None, None, f"{type(e).__name__}: {e}"
    latency = (time.monotonic() - start) * 1000
    ok = r.status_code < 400
    return ok, latency, None, f"HTTP {r.status_code}"


async def resolve(host):
    """Resolve a hostname via the monitor's own connection. Returns an IP or None."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_DGRAM)
    except socket.gaierror:
        return None
    return infos[0][4][0] if infos else None


_EXCEEDED = re.compile(r"^From (\S+) .*(?:Time to live exceeded|TTL exceeded)", re.M)
_REPLY = re.compile(r"bytes from ([^:\s]+).*time=([\d.]+)", re.M)


async def _trace_hop(target, ttl, source, cycles):
    cmd = ["ping", "-n", "-c", str(cycles), "-i", "0.2", "-W", "1", "-t", str(ttl)]
    if source:
        cmd += ["-I", source]
    cmd.append(target)
    _, out = await run(cmd, 10)
    out = out or ""
    exceeded = _EXCEEDED.findall(out)
    replies = _REPLY.findall(out)
    answers = len(exceeded) + len(replies)
    host = (replies[0][0] if replies else exceeded[0]) if answers else "???"
    avg = sum(float(t) for _, t in replies) / len(replies) if replies else None
    return {"hop": ttl, "host": host, "loss": round(100 * (1 - min(answers, cycles) / cycles), 1),
            "avg_ms": round(avg, 2) if avg is not None else None, "reached": bool(replies)}


async def trace(target, source=None, cycles=3, max_hops=20):
    """Traceroute built from TTL-limited pings (works through the tunnel, where mtr doesn't).

    Returns ([{hop, host, loss, avg_ms, reached}], text).
    """
    hops = await asyncio.gather(*(_trace_hop(target, ttl, source, cycles)
                                  for ttl in range(1, max_hops + 1)))
    for i, h in enumerate(hops):
        if h["reached"]:
            hops = hops[:i + 1]
            break
    else:
        while len(hops) > 1 and hops[-1]["host"] == "???" and hops[-2]["host"] == "???":
            hops.pop()
    text = "\n".join(f"{h['hop']:>2}  {h['host']:<16} {h['loss']:>5}% loss"
                     + (f"  {h['avg_ms']} ms" if h["avg_ms"] is not None else "") for h in hops)
    return list(hops), text
