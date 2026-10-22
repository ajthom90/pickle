"""Turns raw check results into outages with a verdict on where the fault was."""
import time

# Incidents on checks with these roles start an outage window.
TRIGGER_ROLES = {"wan", "internet", "dns"}
MERGE_GAP = 60      # seconds; incidents closer than this are one outage
EVENT_PAD = 300     # seconds; reboots/IP changes this close to a window count toward it
ALERT_PAD = 90      # seconds; same for UniFi alarms and events
FAILING = 0.5       # a role "failed" in a window if >= this share of its results failed
BASELINE = 3600     # seconds before a window used to spot checks that were already broken

VERDICTS = {
    "isp": "ISP network",
    "last_mile": "Last mile / WAN link",
    "upstream": "ISP upstream routing",
    "router": "Router",
    "dns": "DNS only",
    "tunnel": "VPN tunnel only",
    "monitor": "Inconclusive (monitor side)",
    "unknown": "Unclassified",
}


def outages(db, checks_by_id, since, until):
    rows = db.q("SELECT check_id, start, end FROM incidents "
                "WHERE start <= ? AND (end IS NULL OR end >= ?) ORDER BY start",
                (until, since))
    windows = []
    for r in rows:
        check = checks_by_id.get(r["check_id"])
        if not check or check["role"] not in TRIGGER_ROLES:
            continue
        end = r["end"]
        if windows and (windows[-1]["end"] is None
                        or r["start"] <= windows[-1]["end"] + MERGE_GAP):
            w = windows[-1]
            w["end"] = None if (w["end"] is None or end is None) else max(w["end"], end)
            w["checks"].add(r["check_id"])
        else:
            windows.append({"start": r["start"], "end": end, "checks": {r["check_id"]}})
    return [classify(db, checks_by_id, w) for w in windows]


# Roles where *every* check must fail to count (one public host being down shouldn't make
# the monitor's connection, or his whole internet, look down). For the rest, the
# worst-failing check speaks for the role: e.g. either ISP router going dark is evidence.
ALL_MUST_FAIL = {"control", "internet"}


def role_stats(db, checks_by_id, start, end):
    rows = db.q("SELECT check_id, COUNT(*) n, SUM(ok = 0) bad FROM results "
                "WHERE ts >= ? AND ts <= ? GROUP BY check_id", (start, end))
    # A check that was already mostly failing beforehand (e.g. a router that never answers
    # ping) says nothing about this window, so leave it out.
    baseline = {r["check_id"]: (r["bad"] or 0) / r["n"] for r in db.q(
        "SELECT check_id, COUNT(*) n, SUM(ok = 0) bad FROM results "
        "WHERE ts >= ? AND ts < ? GROUP BY check_id", (start - BASELINE, start)) if r["n"]}
    rates = {}
    for r in rows:
        check = checks_by_id.get(r["check_id"])
        if check and r["n"] and baseline.get(r["check_id"], 0) < FAILING:
            rates.setdefault(check["role"], []).append((r["bad"] or 0) / r["n"])
    return {role: (min(v) if role in ALL_MUST_FAIL else max(v)) for role, v in rates.items()}


def classify(db, checks_by_id, w):
    start, end = w["start"], w["end"] if w["end"] is not None else time.time()
    fail = role_stats(db, checks_by_id, start, end)
    events = [e for e in db.q("SELECT ts, kind, message FROM events WHERE source = 'unifi' "
                              "AND ts >= ? AND ts <= ? ORDER BY ts",
                              (start - EVENT_PAD, end + EVENT_PAD))
              # Reboots and IP changes are detected late, so they get a wide margin; alerts don't.
              if e["kind"] in ("reboot", "wan_ip_change", "wan_port")
              or start - ALERT_PAD <= e["ts"] <= end + ALERT_PAD]
    reboots = [e for e in events if e["kind"] == "reboot"]
    wan_ip_changed = any(e["kind"] == "wan_ip_change" for e in events)
    port_down = any(e["kind"] == "wan_port" and "DOWN" in e["message"] for e in events)

    def failed(role):
        return fail.get(role) is not None and fail[role] >= FAILING

    def ok(role):
        return fail.get(role) is not None and fail[role] < FAILING

    if failed("control"):
        code, why = "monitor", ("The monitor's own internet connection was failing too, "
                                "so this window proves nothing either way.")
    elif reboots:
        code, why = "router", ("The gateway rebooted during this window (uptime reset). "
                               "That points at the router, its power, or a firmware update.")
    elif failed("wan") and failed("isp_hop"):
        code, why = "isp", ("His WAN IP and the ISP's own router just upstream of it (his WAN's "
                            "default gateway or the last hop before him) were both unreachable "
                            "from the internet. The fault is inside the ISP network, before "
                            "traffic ever reaches his router.")
    elif failed("wan"):
        code = "last_mile"
        why = ("His WAN IP stopped answering while the ISP's upstream router stayed reachable"
               if ok("isp_hop") else "His WAN IP stopped answering")
        if "gateway_api" in fail:
            why += "; UniFi shows the gateway did not reboot. That isolates the fiber, ONT, or the "
            why += "ISP session (DHCP/PPPoE) between the ISP and his router's WAN port."
        else:
            why += ". The fault is between the ISP and his router's WAN port (fiber, ONT, ISP "
            why += "session), or the router itself; without UniFi data a reboot can't be ruled out."
        if port_down:
            why += " UniFi logged the WAN port going DOWN: the ONT dropped the link, which is ISP equipment."
        if wan_ip_changed:
            why += " His WAN IP changed afterward, consistent with the ISP resetting the session."
    elif failed("internet") and ok("gateway") and not failed("tunnel"):
        code, why = "upstream", ("His router was reachable from outside and over the VPN, but "
                                 "couldn't reach internet hosts. Traffic was leaving his router "
                                 "and dying in the ISP's network.")
    elif failed("internet") or failed("gateway"):
        code, why = "tunnel", ("Only checks through the VPN failed; his WAN stayed reachable from "
                               "the internet. Likely the tunnel, not his internet.")
    elif failed("dns"):
        code, why = "dns", ("Connectivity was fine but name resolution failed. Compare the public "
                            "resolver and gateway DNS checks to see which.")
    else:
        code, why = "unknown", "Brief or partial failure; no layer failed for most of the window."

    return {
        "start": w["start"], "end": w["end"],
        "duration": (end - start),
        "ongoing": w["end"] is None,
        "checks": sorted(w["checks"]),
        "verdict": code, "verdict_label": VERDICTS[code], "explanation": why,
        "role_failure": {k: round(v, 3) for k, v in fail.items()},
        "unifi_events": [dict(e) for e in events],
    }


def unifi_alerts(db, checks_by_id, since, until):
    """UniFi WAN alerts, each marked by whether external checks saw a failure at that time."""
    wan_checks = [c["id"] for c in checks_by_id.values() if c["role"] == "wan"]
    out = []
    for e in db.q("SELECT ts, message, data FROM events WHERE source = 'unifi' "
                  "AND kind = 'wan_alert' AND ts >= ? AND ts <= ? ORDER BY ts DESC",
                  (since, until)):
        corroborated = None
        if wan_checks:
            marks = ",".join("?" * len(wan_checks))
            r = db.q(f"SELECT COUNT(*) n, SUM(ok = 0) bad FROM results WHERE check_id IN ({marks}) "
                     "AND ts >= ? AND ts <= ?", (*wan_checks, e["ts"] - 120, e["ts"] + 120))[0]
            if r["n"]:
                corroborated = bool(r["bad"])
        out.append({"ts": e["ts"], "message": e["message"], "corroborated": corroborated})
    return out
