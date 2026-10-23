"""Gateway load (from UniFi) and whether it lines up with outages.

The question is "do outages start when the connection is busy?". For each outage, take
the peak of each metric in the minutes before it started, and rank that against the peak
of every other window of the same length on record. If load doesn't matter, those ranks
are spread evenly, so about 10% of outages land in the busiest 10% of windows by chance.
Many more than that, and load is linked.
"""
import bisect
import math
import time
from collections import deque

LEAD = 600          # seconds before an outage whose load counts as "before" it
TOP = 0.9           # "busy" = in the busiest 10% of windows
MIN_OUTAGES = 3
MIN_HISTORY = 86400  # need a day of samples before ranking means anything
# Outages that say nothing about his connection's load.
SKIP_VERDICTS = {"monitor", "tunnel"}

METRICS = [
    ("rx_bps", "Download"),
    ("tx_bps", "Upload"),
    ("cpu", "Gateway CPU"),
    ("mem", "Gateway memory"),
    ("temp", "Gateway temperature"),
    ("clients", "Connected clients"),
]


def series(db, since, until, buckets):
    """Bucketed averages and peaks for the charts."""
    width = (until - since) / buckets
    rows = db.q("SELECT CAST((ts - ?) / ? AS INTEGER) b, "
                "AVG(rx_bps) rx, MAX(rx_bps) rx_max, AVG(tx_bps) tx, MAX(tx_bps) tx_max, "
                "AVG(cpu) cpu, MAX(cpu) cpu_max, AVG(mem) mem, AVG(temp) temp, "
                "MAX(clients) clients FROM load WHERE ts >= ? AND ts < ? GROUP BY b",
                (since, width, since, until))
    out = [None] * buckets
    for r in rows:
        if 0 <= r["b"] < buckets:
            out[r["b"]] = {k: r[k] for k in r.keys() if k != "b"}
    return {"since": since, "until": until, "width": width, "buckets": out}


def capacity(cfg, snapshot):
    """His line's speed in bits/s: from config, else UniFi's last speed test."""
    snap = snapshot or {}
    down = cfg.get("wan_down_mbps") or snap.get("speedtest_down_mbps")
    up = cfg.get("wan_up_mbps") or snap.get("speedtest_up_mbps")
    return {"rx_bps": float(down) * 1e6 if down else None,
            "tx_bps": float(up) * 1e6 if up else None,
            "source": "config" if cfg.get("wan_down_mbps") else ("speedtest" if down else None)}


def _samples(db, until):
    return db.q("SELECT ts, rx_bps, tx_bps, cpu, mem, temp, clients FROM load "
                "WHERE ts <= ? ORDER BY ts", (until,))


def _window_peaks(rows, key):
    """Peak of `key` over the LEAD seconds ending at each sample: the baseline to rank against."""
    peaks, window = [], deque()
    for r in rows:
        v = r[key]
        if v is None:
            continue
        while window and window[0][0] < r["ts"] - LEAD:
            window.popleft()
        while window and window[-1][1] <= v:
            window.pop()
        window.append((r["ts"], v))
        peaks.append(window[0][1])
    return sorted(peaks)


def _peak_before(rows_ts, rows, key, start):
    lo = bisect.bisect_left(rows_ts, start - LEAD)
    hi = bisect.bisect_left(rows_ts, start)
    vals = [rows[i][key] for i in range(lo, hi) if rows[i][key] is not None]
    return max(vals) if vals else None


def before(db, outages_list, cap=None):
    """Annotate outages with the peak load in the LEAD seconds before each one started."""
    if not outages_list:
        return outages_list
    first = min(o["start"] for o in outages_list) - LEAD
    last = max(o["start"] for o in outages_list)
    rows = db.q("SELECT ts, rx_bps, tx_bps, cpu, mem, temp, clients FROM load "
                "WHERE ts >= ? AND ts < ? ORDER BY ts", (first, last))
    ts = [r["ts"] for r in rows]
    for o in outages_list:
        lb = {key: _peak_before(ts, rows, key, o["start"]) for key, _ in METRICS}
        if cap:
            for key in ("rx_bps", "tx_bps"):
                if lb.get(key) is not None and cap.get(key):
                    lb[key + "_util"] = lb[key] / cap[key]
        o["load_before"] = lb if any(v is not None for v in lb.values()) else None
    return outages_list


def correlate(db, outages_list, now=None):
    """Per metric: how many outages began in the busiest 10% of times, against chance."""
    now = now or time.time()
    rows = _samples(db, now)
    if not rows:
        return {"enough_history": False, "history_hours": 0, "metrics": [], "outages": 0}
    history = rows[-1]["ts"] - rows[0]["ts"]
    ts = [r["ts"] for r in rows]
    eligible = [o for o in outages_list if o["verdict"] not in SKIP_VERDICTS]
    result = {"enough_history": history >= MIN_HISTORY, "history_hours": round(history / 3600, 1),
              "outages": len(eligible), "metrics": []}
    for key, label in METRICS:
        peaks = _window_peaks(rows, key)
        if not peaks:
            continue
        ranks = []
        for o in eligible:
            v = _peak_before(ts, rows, key, o["start"])
            if v is not None:
                ranks.append(bisect.bisect_left(peaks, v) / len(peaks))
        n = len(ranks)
        k = sum(1 for r in ranks if r >= TOP)
        p = _binom_tail(n, k, 1 - TOP) if n else None
        code, text = _verdict(n, k, p, ranks, result["enough_history"])
        result["metrics"].append({
            "key": key, "label": label, "outages": n, "busy": k,
            "expected": round(n * (1 - TOP), 1),
            "median_rank": round(sorted(ranks)[n // 2], 3) if n else None,
            "p_value": round(p, 4) if p is not None else None,
            "verdict": code, "explanation": text,
        })
    return result


def _verdict(n, k, p, ranks, enough_history):
    if not enough_history:
        return "pending", "Needs at least a day of load history."
    if n < MIN_OUTAGES:
        return "pending", f"Needs at least {MIN_OUTAGES} outages with load data ({n} so far)."
    if p is not None and p < 0.05 and k > n * (1 - TOP):
        return "linked", (f"{k} of {n} outages began in the busiest 10% of times; about "
                          f"{n * (1 - TOP):.1f} would by chance.")
    median = sorted(ranks)[n // 2]
    if k == 0 or median < 0.6:
        return "none", (f"Outages began at ordinary load (typically busier than "
                        f"{median * 100:.0f}% of the time).")
    return "unclear", f"{k} of {n} outages began at peak load; not enough to call it a pattern."


def _binom_tail(n, k, p):
    """P(X >= k) for X ~ Binomial(n, p)."""
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k, n + 1))
