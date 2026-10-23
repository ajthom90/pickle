"""Turns raw check results into outages with a verdict on where the fault was."""
import json
import time

# Incidents on checks with these roles start an outage window.
TRIGGER_ROLES = {"wan", "internet", "dns"}
MERGE_GAP = 60      # seconds; incidents closer than this are one outage
EVENT_PAD = 300     # seconds; reboots/IP changes this close to a window count toward it
ALERT_PAD = 90      # seconds; same for UniFi alarms and events
FAILING = 0.5       # a role "failed" in a window if >= this share of its results failed
BASELINE = 3600     # seconds before a window used to spot checks that were already broken
PORT_LEAD = 90      # seconds; a WAN port drop seen within this of the start is "at the start"
RECOVER_PAD = 120   # seconds; an outage ending this close to the port coming back ended with it
UNIFI_POLL = 60     # fallback detection window for WAN port events from before it was recorded
LEASE_LEAD = 300    # seconds; a lease renewal/expiry this soon before an outage counts
RECOVERY_PAD = 900  # seconds after an outage to look for the gateway's recovery snapshot

VERDICTS = {
    "isp": "ISP network",
    "last_mile": "Last mile / WAN link",
    "isp_session": "ISP session / DHCP",
    "upstream": "ISP upstream routing",
    "router": "Router",
    "dns": "DNS only",
    "tunnel": "VPN tunnel only",
    "monitor": "Inconclusive (monitor side)",
    "unknown": "Unclassified",
}


# Verdicts about his WAN itself, where lease timing is worth mentioning.
WAN_VERDICTS = {"isp", "last_mile", "isp_session", "upstream"}


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
    ongoing = w["end"] is None
    fail = role_stats(db, checks_by_id, start, end)
    events = [e for e in db.q("SELECT ts, kind, message, data FROM events WHERE source = 'unifi' "
                              "AND ts >= ? AND ts <= ? ORDER BY ts",
                              (start - EVENT_PAD, end + EVENT_PAD))
              # Reboots and IP changes are detected late, so they get a wide margin; alerts don't.
              if e["kind"] in ("reboot", "wan_ip_change", "wan_port")
              or (e["kind"] not in ("recovery", "dhcp_lease")
                  and start - ALERT_PAD <= e["ts"] <= end + ALERT_PAD)]
    events = [dict(e) | {"data": json.loads(e["data"]) if e["data"] else None} for e in events]
    reboots = [e for e in events if e["kind"] == "reboot"]
    wan_ip_changed = any(e["kind"] == "wan_ip_change" for e in events)
    port = port_story(events, start, end, ongoing)
    lease = lease_context(db, start, end, ongoing)
    recovery = recovery_snapshot(db, start, end)

    def failed(role):
        return fail.get(role) is not None and fail[role] >= FAILING

    def ok(role):
        return fail.get(role) is not None and fail[role] < FAILING

    have_unifi = "gateway_api" in fail
    stayed_up = have_unifi and not port["downs"]
    ended_by_renewal = not ongoing and (lease.get("renewed_at_end") or any(
        abs(d["at"] - end) <= RECOVER_PAD for d in lease.get("due", [])))

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
    elif (failed("wan") and ok("isp_hop") and (stayed_up or port["late"])
          and (port["ended_by_reconnect"] or ended_by_renewal)):
        code, why = "isp_session", isp_session_text(port, stayed_up, ended_by_renewal,
                                                    wan_ip_changed)
    elif failed("wan"):
        code = "last_mile"
        why = ("His WAN IP stopped answering while the ISP's upstream router stayed reachable"
               if ok("isp_hop") else "His WAN IP stopped answering")
        if have_unifi:
            why += ("; UniFi shows the gateway did not reboot. That isolates the link between "
                    "the ISP's gateway and his router: the fiber, the ONT, or a WAN port.")
        else:
            why += (". The fault is between the ISP and his router's WAN port (fiber, ONT, ISP "
                    "session), or the router itself; without UniFi data a reboot can't be ruled out.")
        note = wan_port_note(port, start, wan_ip_changed)
        if note:
            why += " " + note
        elif stayed_up and not ongoing:
            why += (" UniFi saw no WAN port change and nothing marked the end (no reconnect or "
                    "lease renewal), so this can't separate the ISP dropping his session from a "
                    "port that stopped passing traffic.")
        elif wan_ip_changed:
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

    if code in WAN_VERDICTS and lease.get("due"):
        why += " " + lease["note"]

    return {
        "start": w["start"], "end": w["end"],
        "duration": (end - start),
        "ongoing": ongoing,
        "checks": sorted(w["checks"]),
        "verdict": code, "verdict_label": VERDICTS[code], "explanation": why,
        "role_failure": {k: round(v, 3) for k, v in fail.items()},
        "unifi_events": events,
        "lease": lease,
        "recovery": recovery,
    }


def isp_session_text(port, stayed_up, ended_by_renewal, wan_ip_changed):
    why = ("His WAN IP stopped answering while the ISP's gateway kept answering from the "
           "internet, and his router didn't reboot. ")
    if stayed_up:
        why += "UniFi saw no WAN port change, so the link to the ONT stayed up. "
    else:
        why += (f"His router's WAN link stayed up until about {port['late_minutes']} min in, "
                f"when the port went DOWN: someone reconnecting, after traffic had already "
                f"stopped. ")
    if port["ended_by_reconnect"]:
        why += ("Service came back as soon as the link was reconnected, which makes his router "
                "request a fresh DHCP lease: the fiber and ONT were working, but the ISP had "
                "stopped serving his router's existing session.")
    else:
        why += ("Service came back when his router renewed its DHCP lease, so the ISP side "
                "started answering again on a fresh DHCP exchange.")
    if wan_ip_changed:
        why += " His WAN IP changed, so the ISP had ended his session outright."
    else:
        why += (" His WAN IP didn't change, which is normal: the ISP's DHCP server hands the "
                "same address back to the same router.")
        why += (" A router WAN port that had stopped passing traffic would look the same from "
                "outside; on site, `ip neigh` on the router showing the ISP gateway FAILED or "
                "INCOMPLETE while the link is up tells them apart.")
    return why


def _into(ts, start):
    """'3 min' into the outage, for explanations (server-side text has no reliable timezone)."""
    m = max(0, round((ts - start) / 60))
    return "the start" if m == 0 else f"{m} min in"


def _relative(ts, start):
    m = round((ts - start) / 60)
    if m < 0:
        return f"{-m} min before the outage began"
    return "as the outage began" if m == 0 else f"{m} min into the outage"


def _port_window(e):
    """When a WAN port change could have happened: between the last poll that saw the old
    state and the poll that saw the new one."""
    d = e.get("data") or {}
    return (d.get("since") or e["ts"] - UNIFI_POLL), (d.get("seen") or e["ts"])


def port_story(events, start, end, ongoing):
    """What UniFi saw his WAN port do around an outage. Only a drop at the start of the
    outage means the ONT dropped the link; a drop well into it came after traffic had
    already stopped, which is what someone unplugging or power-cycling equipment looks like."""
    downs = [e for e in events if e["kind"] == "wan_port" and "DOWN" in e["message"]]
    story = {"downs": downs, "at_start": False, "ambiguous": False, "late": False,
             "ended_by_reconnect": False, "late_minutes": None, "window": None}
    if not downs:
        return story
    lo, hi = _port_window(downs[0])
    story["window"] = (lo, hi)
    if hi <= start + PORT_LEAD:
        story["at_start"] = True
    elif lo < start + PORT_LEAD:
        story["ambiguous"] = True
    else:
        story["late"] = True
        story["late_minutes"] = round((lo - start) / 60)
        ups = [e for e in events if e["kind"] == "wan_port" and "UP" in e["message"]
               and _port_window(e)[0] >= lo]
        if ups and not ongoing:
            up_lo, up_hi = _port_window(ups[0])
            story["ended_by_reconnect"] = up_lo - RECOVER_PAD <= end <= up_hi + RECOVER_PAD
    return story


def wan_port_note(port, start, wan_ip_changed):
    """Explain a WAN port DOWN for the Last mile verdict."""
    if not port["downs"]:
        return None
    ip_note = (" His WAN IP changed afterward, consistent with the ISP resetting the session."
               if wan_ip_changed else "")
    lo, hi = port["window"]
    if port["at_start"]:
        return ("UniFi logged the WAN port going DOWN as the outage began: the ONT dropped the "
                "link, which is ISP equipment." + ip_note)
    if port["ambiguous"]:
        return (f"UniFi logged the WAN port going DOWN, but pickle couldn't reach the gateway "
                f"between {_into(lo, start)} and {_into(hi, start)}, so it can't tell whether "
                f"the port dropped when the outage began (the ONT dropping the link) or later "
                f"(someone unplugging or power-cycling equipment)." + ip_note)
    note = (f"The WAN port went DOWN about {port['late_minutes']} min into the outage, after "
            f"traffic had already stopped, so it wasn't the cause; that's what someone unplugging "
            f"or power-cycling the router or ONT looks like.")
    if port["ended_by_reconnect"]:
        note += (" The outage ended when the link came back up, so reconnecting cleared it: "
                 "the line itself was working by then.")
        if wan_ip_changed:
            note += " His WAN IP changed when it reconnected, so the ISP had dropped his session."
        else:
            note += (" His WAN IP didn't change, which is normal after a fresh DHCP exchange, so "
                     "it doesn't say which side had stopped.")
    else:
        note += ip_note
    return note


def _lease_rows(db, until):
    rows = db.q("SELECT ts, data FROM events WHERE source = 'unifi' AND kind = 'dhcp_lease' "
                "AND ts <= ? ORDER BY ts", (until,))
    out = []
    for r in rows:
        d = json.loads(r["data"]) if r["data"] else {}
        if d.get("obtained") or d.get("expires"):
            out.append(d | {"ts": r["ts"]})
    return out


def lease_context(db, start, end, ongoing):
    """Where an outage fell relative to his router's DHCP lease, if UniFi exposes it."""
    rows = _lease_rows(db, end + RECOVER_PAD + UNIFI_POLL)
    if not rows:
        return {"known": False, "note": "Lease timing unknown: UniFi didn't report DHCP lease "
                                        "details for this period."}
    before = [r for r in rows if (r.get("obtained") or r["ts"]) <= start]
    after = [r for r in rows if r.get("obtained") and start < r["obtained"]]
    ctx = {"known": True, "due": [], "renewed_at_end": False}
    parts = []
    if before:
        b = before[-1]
        obtained, T, expires = b.get("obtained"), b.get("lease_time"), b.get("expires")
        ctx.update(obtained=obtained, lease_time=T, expires=expires)
        if obtained:
            ctx["since_obtained"] = start - obtained
            parts.append(f"The outage began {_dur(start - obtained)} after his router last "
                         f"obtained its DHCP lease" + (f" (lease time {_dur(T)})" if T else "") + ".")
        marks = ([("renewal (T/2)", obtained + T / 2), ("rebind (7T/8)", obtained + T * 0.875),
                  ("expiry", obtained + T)] if obtained and T else
                 [("expiry", expires)] if expires else [])
        for what, at in marks:
            if start - LEASE_LEAD <= at <= end:
                ctx["due"].append({"what": what, "at": at})
                parts.append(f"A DHCP {what} was due {_relative(at, start)}.")
    else:
        parts.append("The lease was first seen after this outage began, so its timing before "
                     "the outage is unknown.")
    if after and not ongoing and abs(after[0]["obtained"] - end) <= RECOVER_PAD + UNIFI_POLL:
        ctx["renewed_at_end"] = True
        parts.append("His router renewed its lease as the outage ended.")
    if ctx["due"]:
        parts.append("The outage lines up with the lease renewal.")
    ctx["note"] = " ".join(parts)
    return ctx


def recovery_snapshot(db, start, end):
    """His gateway's WAN state from the first poll after it became reachable again."""
    rows = db.q("SELECT ts, message, data FROM events WHERE source = 'unifi' AND kind = 'recovery' "
                "AND ts >= ? AND ts <= ? ORDER BY ts", (start, end + RECOVERY_PAD))
    for r in rows:
        d = json.loads(r["data"]) if r["data"] else {}
        if d.get("unreachable_since", r["ts"]) <= end + RECOVER_PAD:
            return d | {"ts": r["ts"], "message": r["message"]}
    return None


def _dur(sec):
    sec = int(abs(sec))
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m" if m else f"{s}s"


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
