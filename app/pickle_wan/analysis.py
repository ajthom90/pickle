"""Turns raw check results into outages with a verdict on where the fault was."""
import json
import re
import time

# Incidents on checks with these roles start an outage window.
TRIGGER_ROLES = {"wan", "internet", "dns"}
MERGE_GAP = 60      # seconds; incidents closer than this are one outage
EVENT_PAD = 300     # seconds; IP changes and port events this close to a window count toward it
REBOOT_PAD = 60     # seconds; boot time (now - uptime) is accurate to about a minute
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
              # A reboot event's time is the boot time, so it counts only if the gateway booted
              # during the outage. IP and port changes are detected late (by polling), so they
              # get a wide margin; alerts carry UniFi's own timestamps.
              if (e["kind"] == "reboot" and start - REBOOT_PAD <= e["ts"] <= end + REBOOT_PAD)
              or e["kind"] in ("wan_ip_change", "wan_port")
              or (e["kind"] not in ("reboot", "recovery", "dhcp_lease")
                  and start - ALERT_PAD <= e["ts"] <= end + ALERT_PAD)]
    events = [dict(e) | {"data": json.loads(e["data"]) if e["data"] else None} for e in events]
    wan_ip_changed = any(e["kind"] == "wan_ip_change" for e in events)
    user_note = outage_note(db, start, end)
    human = bool(user_note and user_note["human_action"])
    # Someone on site (moving power, re-plugging cables) explains reboots and port changes, so
    # with the human-action flag they don't decide the verdict; the port state is then unknown.
    rebooted = any(e["kind"] == "reboot" for e in events)
    # WAN port changes: the router's own log gives the exact second. Use it instead of UniFi's
    # polled events when that log covers the outage (and the WAN interface is known); otherwise
    # use both, so a partial router log can't erase the only record of a drop.
    router_ports = router_link_events(db, start, end)
    unifi_ports = [e for e in events if e["kind"] == "wan_port"]
    router_cov = bool(db.get_kv("router_wan_iface")) and router_log_covers(db, start, end, ongoing, rebooted)
    if router_cov:
        port_events = router_ports
    else:
        port_events = sorted(unifi_ports + router_ports, key=lambda e: e["ts"])
    others = [e for e in events if e["kind"] != "wan_port"]
    relevant_ports = _relevant_port_events(port_events, start, end)
    set_aside = [e for e in others if human and e["kind"] == "reboot"]
    set_aside += [e for e in relevant_ports if human]
    for e in set_aside:
        e["human_action"] = True
    reboots = [e for e in events if e["kind"] == "reboot" and not human]
    port = port_story([e for e in others + port_events if e not in set_aside], start, end, ongoing)
    port["unknown"] = bool(set_aside)
    port["source"] = "router_log" if port_events is router_ports and router_ports else "unifi"
    lease = lease_context(db, start, end, ongoing)
    recovery = recovery_snapshot(db, start, end)
    router_log = router_log_context(db, start, end, ongoing, rebooted=rebooted)

    def failed(role):
        return fail.get(role) is not None and fail[role] >= FAILING

    def ok(role):
        return fail.get(role) is not None and fail[role] < FAILING

    have_unifi = "gateway_api" in fail
    # The link is known to have stayed up if UniFi was polled or the router's log covers it.
    stayed_up = (have_unifi or router_cov) and not port["downs"] and not port["unknown"]
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
        if set_aside:
            why += ". The fault is between the ISP's gateway and his router: the fiber, the ONT, "
            why += "a WAN port, or his router."
        elif have_unifi:
            why += ("; UniFi shows the gateway did not reboot. That isolates the link between "
                    "the ISP's gateway and his router: the fiber, the ONT, or a WAN port.")
        else:
            why += (". The fault is between the ISP and his router's WAN port (fiber, ONT, ISP "
                    "session), or the router itself; without UniFi data a reboot can't be ruled out.")
        note = wan_port_note(port, start, wan_ip_changed)
        if note:
            why += " " + note
        elif stayed_up and not ongoing:
            why += (f" {_who(port)} no WAN port change and nothing marked the end (no reconnect or "
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
    if code in WAN_VERDICTS and router_log and router_log.get("finding") in CALLOUTS:
        why += " " + router_log["note"]
    if set_aside:
        kinds = sorted({"the gateway reboot" if e["kind"] == "reboot" else "the WAN port changes"
                        for e in set_aside})
        verb = "was" if kinds == ["the gateway reboot"] else "were"
        why += (f" Marked as human action, so {' and '.join(kinds)} in this window {verb} left "
                f"out of the verdict.")

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
        "router_log": router_log,
        "note": user_note,
    }


def isp_session_text(port, stayed_up, ended_by_renewal, wan_ip_changed):
    why = ("His WAN IP stopped answering while the ISP's gateway kept answering from the "
           "internet, and his router didn't reboot. ")
    if stayed_up:
        why += f"{_who(port)} no WAN port change, so the link to the ONT stayed up. "
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
    downs = [e for e in _relevant_port_events(events, start, end) if "DOWN" in e["message"]]
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


def _relevant_port_events(events, start, end):
    """WAN port events that belong to this outage. A DOWN/UP cycle that was over before the
    outage began, or a change that began after it ended, isn't part of it (the wide event
    margin can pull in a neighbouring outage's reconnect)."""
    ports = [e for e in events if e["kind"] == "wan_port"]
    out = []
    for i, e in enumerate(ports):
        lo, hi = _port_window(e)
        if lo > end:
            continue
        if "DOWN" in e["message"]:
            nxt = next((u for u in ports[i + 1:] if "UP" in u["message"]), None)
            if nxt and _port_window(nxt)[1] < start:
                continue
        elif hi < start:
            continue
        out.append(e)
    return out


def _who(port):
    return "His router's log shows" if port.get("source") == "router_log" else "UniFi saw"


def _logged(port):
    return "His router logged" if port.get("source") == "router_log" else "UniFi logged"


def wan_port_note(port, start, wan_ip_changed):
    """Explain a WAN port DOWN for the Last mile verdict."""
    if not port["downs"]:
        return None
    ip_note = (" His WAN IP changed afterward, consistent with the ISP resetting the session."
               if wan_ip_changed else "")
    lo, hi = port["window"]
    if port["at_start"]:
        return (f"{_logged(port)} the WAN port going DOWN as the outage began: the ONT dropped the "
                "link, which is ISP equipment." + ip_note)
    if port["ambiguous"]:
        return (f"{_logged(port)} the WAN port going DOWN, but pickle couldn't reach the gateway "
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
    # Lease history from UniFi and from the router's own log (udhcpc "lease ... obtained").
    rows = db.q("SELECT ts, data FROM events WHERE source IN ('unifi', 'router_log') "
                "AND kind = 'dhcp_lease' AND ts <= ? ORDER BY ts", (until,))
    out = []
    for r in rows:
        d = json.loads(r["data"]) if r["data"] else {}
        if d.get("clock_suspect"):
            continue
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


def outage_note(db, start, end):
    """The note(s) someone attached to this outage. Matched by window rather than exact start,
    because an ongoing outage's start can move earlier as more checks cross the threshold."""
    rows = db.q("SELECT id, start, note, human_action, updated FROM outage_notes "
                "WHERE start >= ? AND start <= ? ORDER BY start", (start - MERGE_GAP, end))
    if not rows:
        return None
    return {"ids": [r["id"] for r in rows],
            "text": " / ".join(r["note"] for r in rows if r["note"]),
            "human_action": any(r["human_action"] for r in rows),
            "updated": max(r["updated"] for r in rows)}


ROUTER_LEAD = 600   # seconds of router log shown before an outage
# Router log findings worth adding to the verdict's explanation (others are shown, not argued).
CALLOUTS = {"no_reply", "no_reply_logged", "answered_then_stopped", "quiet", "midlease"}
ROUTER_REQUESTS = {"dhcp_renew", "dhcp_rebind", "dhcp_select", "dhcp_discover"}
ROUTER_ANSWERS = {"dhcp_lease", "dhcp_ack", "dhcp_offer"}
ANSWER_WAIT = 10    # seconds; a DHCP request answered within this was answered
FRESH_PAD = 60      # seconds; a request this soon after a link reset / client restart is "fresh"
WORD = {"dhcp_renew": "renewal", "dhcp_rebind": "rebind", "dhcp_select": "request",
        "dhcp_discover": "discover"}


def _router_rows(db, lo, hi):
    return [dict(r) | {"data": json.loads(r["data"]) if r["data"] else {}} for r in db.q(
        "SELECT id, ts, kind, message, data FROM events WHERE source = 'router_log' "
        "AND ts >= ? AND ts <= ? ORDER BY ts, id", (lo, hi))]


def router_log_covers(db, start, end, ongoing=False, rebooted=False):
    """Whether the router log can prove an absence for this window: it reaches back before
    the outage, has lines after it, and no reboot (which can wipe or reset it) inside."""
    if ongoing or rebooted:
        return False
    def trusted(rows_):
        return any(not json.loads(a["data"] or "{}").get("clock_suspect") for a in rows_)
    after = db.q("SELECT data FROM events WHERE source = 'router_log' AND kind != 'restart_record' "
                 "AND ts > ? ORDER BY ts LIMIT 20", (end,))
    before = db.q("SELECT data FROM events WHERE source = 'router_log' AND kind != 'restart_record' "
                  "AND ts <= ? ORDER BY ts DESC LIMIT 20", (start,))
    return trusted(after) and trusted(before)


def router_link_events(db, start, end):
    """WAN link down/up from the router's own log, shaped like UniFi's polled wan_port events
    but exact (the change happened at the logged second, not somewhere between two polls)."""
    wan = db.get_kv("router_wan_iface")
    if not wan:
        return []
    out = []
    for r in _router_rows(db, start - EVENT_PAD, end + EVENT_PAD):
        if r["kind"] in ("link_down", "link_up") and r["data"].get("iface") == wan \
                and not r["data"].get("clock_suspect"):
            state = "DOWN" if r["kind"] == "link_down" else "UP"
            out.append({"ts": r["ts"], "kind": "wan_port",
                        "message": f"Router log: WAN link {state} ({wan})",
                        "data": {"up": state == "UP", "since": r["ts"], "seen": r["ts"],
                                 "source": "router_log"}})
    return out


def router_log_context(db, start, end, ongoing, rebooted=False):
    """The router's own DHCP/WAN log lines around an outage (collected over SSH), and what
    they say about the DHCP exchange. None if no router log has ever been collected."""
    if not db.q("SELECT 1 FROM events WHERE source = 'router_log' LIMIT 1"):
        return None
    wan = db.get_kv("router_wan_iface")
    rows = _router_rows(db, start - ROUTER_LEAD, end + UNIFI_POLL)
    lines = [r for r in rows if not r["data"].get("clock_suspect")]

    def shown(r):
        # other interfaces' link lines and Wi-Fi carrier noise aren't about his WAN
        if r["kind"] in ("link_up", "link_down"):
            return r["data"].get("iface") == wan
        if r["kind"] == "log" and re.search(r"carrier|Link is", r["message"]):
            return False
        return True
    covered = router_log_covers(db, start, end, ongoing, rebooted)
    ctx = {"lines": [{"ts": r["ts"], "kind": r["kind"], "message": r["message"]}
                     for r in lines if shown(r)],
           "suspect_lines": len(rows) - len(lines), "covered": covered,
           "finding": None, "note": "", "facts": []}

    # Requests and answers in log order (several can share a second).
    dhcp = [r for r in lines if r["kind"] in ROUTER_REQUESTS | ROUTER_ANSWERS]
    def answer_after(i):
        return next((a for a in dhcp[i + 1:] if a["kind"] in ROUTER_ANSWERS), None)
    def unanswered(lo, hi):
        """First request sent in [lo, hi) that wasn't answered promptly, and whose answer (if
        any) only came as the outage was ending."""
        for i, r in enumerate(dhcp):
            if r["kind"] in ROUTER_REQUESTS and lo <= r["ts"] < hi and r["ts"] <= end:
                nxt = answer_after(i)
                if nxt is None or (nxt["ts"] - r["ts"] > ANSWER_WAIT and nxt["ts"] >= end - RECOVER_PAD):
                    return r, nxt
        return None

    # Only a request sent while traffic still flowed says something about the DHCP server:
    # once the line is dead, nothing gets a reply, whatever the cause.
    early = unanswered(start - ROUTER_LEAD, start)
    during = unanswered(start, end + 1)
    midlease = None if (early or during or ongoing) else _midlease(db, lines, dhcp, start, end, wan)
    before = [a for a in dhcp if a["kind"] in ROUTER_ANSWERS and start - ROUTER_LEAD <= a["ts"] < start]
    if early:
        r, nxt = early
        sent = (f"His router sent a DHCP {WORD[r['kind']]} {_relative(r['ts'], start)}, while "
                f"traffic was still flowing")
        if nxt or covered:
            ctx["finding"] = "no_reply"
            ctx["note"] = (sent + ", and got no reply until the outage ended"
                           + (f" (answered {_relative(nxt['ts'], start)})" if nxt else "")
                           + ". That points at the ISP's DHCP server.")
        else:
            ctx["finding"] = "no_reply_logged"
            ctx["note"] = (sent + "; no reply was logged before the outage ended, but the router "
                           "log doesn't clearly cover the whole outage (no later lines yet, or "
                           "a reboot), so a missing reply can't be confirmed.")
    elif midlease:
        ctx["finding"], ctx["note"] = "midlease", midlease
    elif during:
        r, nxt = during
        ctx["finding"] = "unanswered_during"
        ctx["note"] = (f"His router's DHCP {WORD[r['kind']]} {_relative(r['ts'], start)} went "
                       f"unanswered, which is expected during an outage whatever the cause"
                       + ("; service returned when the reply arrived." if nxt else "."))
    elif before:
        a = before[-1]
        ctx["finding"] = "answered_then_stopped"
        ctx["note"] = (f"His router's DHCP lease was renewed {_relative(a['ts'], start)}, so it "
                       f"held a valid lease when traffic stopped. That points at his router or "
                       f"the ISP's session, not the DHCP exchange.")
    elif covered and not any(start <= r["ts"] <= end for r in dhcp):
        ctx["finding"] = "quiet"
        ctx["note"] = ("The router logged no DHCP activity during the outage: it still "
                       "considered its lease valid.")
    elif not covered and not ongoing:
        ctx["note"] = ("The router log doesn't cover this outage yet (no lines after it, or the "
                       "router rebooted).")

    ctx["facts"] = _router_facts(lines, start, end)
    if ctx["facts"]:
        ctx["note"] = (ctx["note"] + " " if ctx["note"] else "") + " ".join(ctx["facts"])
    return ctx


def _midlease(db, lines, dhcp, start, end, wan):
    """Oct 22's pattern, stated as facts: a valid lease, no DHCP requests during the outage
    until the link was reset (or the client restarted), then a fresh exchange answered at once
    as service returned."""
    # The lease in force when the outage began can be from well before the lines shown.
    last = None
    for r in db.q("SELECT ts, data FROM events WHERE source = 'router_log' AND kind = 'dhcp_lease' "
                  "AND ts < ? ORDER BY ts DESC LIMIT 5", (start,)):
        d = json.loads(r["data"] or "{}")
        if not d.get("clock_suspect"):
            last = {"ts": r["ts"], "data": d}
            break
    if not last or not last["data"].get("lease_time"):
        return None
    T = last["data"]["lease_time"]
    if last["ts"] + T <= start:
        return None
    first_req = next((r for r in dhcp if r["kind"] in ROUTER_REQUESTS and r["ts"] >= start), None)
    if not first_req or first_req["ts"] > end + RECOVER_PAD:
        return None
    resets = [r for r in lines if (r["kind"] in ("link_up", "dhcp_client_start")
                                   and r["data"].get("iface") in (None, wan))
              and first_req["ts"] - FRESH_PAD <= r["ts"] <= first_req["ts"]]
    i = dhcp.index(first_req)
    ans = next((a for a in dhcp[i + 1:] if a["kind"] in ROUTER_ANSWERS), None)
    if not resets or not ans or ans["ts"] - first_req["ts"] > ANSWER_WAIT \
            or abs(ans["ts"] - end) > RECOVER_PAD:
        return None
    new_lease = next((a for a in dhcp[i + 1:] if a["kind"] == "dhcp_lease"), None)
    same_ip = new_lease and new_lease["data"].get("ip") == last["data"].get("ip")
    how = "the link was reset" if any(r["kind"] == "link_up" for r in resets) else "the DHCP client restarted"
    secs = max(1, round(ans["ts"] - first_req["ts"]))
    return (f"His router's DHCP lease was valid: renewed {_dur(start - last['ts'])} before the "
            f"outage, with {_dur(last['ts'] + T - start)} left. It made no DHCP requests during "
            f"the outage until {how} {_relative(resets[0]['ts'], start)}; the fresh request was "
            f"answered within {secs} s" + (" with the same IP" if same_ip else "")
            + ", and service returned.")


def _router_facts(lines, start, end):
    """Other things the router itself logged during the outage, as plain facts."""
    facts = []
    v6 = [r for r in lines if r["kind"] == "dhcpv6_probe" and start - 60 <= r["ts"] <= end]
    if v6 and not v6[0]["data"].get("ok"):
        facts.append(f"His router's DHCPv6 probe {_relative(v6[0]['ts'], start)} got no answer, "
                     f"so IPv6 had stopped too.")
    downs = {}
    for r in lines:
        if r["kind"] == "wan_monitor" and r["data"].get("state") == "down" \
                and start - 60 <= r["ts"] <= end:
            downs.setdefault(r["data"].get("target"), r["ts"])
    if downs:
        parts = [f"{t} {_relative(ts, start)}" for t, ts in sorted(downs.items(), key=lambda x: x[1])]
        facts.append("His router's own WAN monitors marked these down: " + ", ".join(parts) + ".")
    return facts


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
