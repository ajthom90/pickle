"""Push notifications for outages through ntfy (https://ntfy.sh or a self-hosted server).

An outage gets one "started" message once it has lasted min_duration_seconds, and a
"resolved" message once it has been over for analysis.MERGE_GAP seconds (so a flapping
connection doesn't produce a pair of messages per flap). The resolved message carries the
final verdict. What's been sent is kept in the database, so a restart doesn't repeat it.
"""
import asyncio
import logging
import time

import httpx

from . import analysis

log = logging.getLogger("pickle.notify")

PRIORITIES = {"min": 1, "low": 2, "default": 3, "high": 4, "max": 5, "urgent": 5}
LOOKBACK = 86400      # seconds of history scanned for outages each pass
KEEP_SENT = 7 * 86400  # how long a sent-record is remembered
POLL = 15


def _priority(value):
    if isinstance(value, int):
        return min(max(value, 1), 5)
    return PRIORITIES.get(str(value).strip().lower(), 3)


def _duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


class Ntfy:
    def __init__(self, cfg, wan_host):
        self.cfg = cfg
        self.wan_host = wan_host
        server = cfg["server"].rstrip("/")
        auth = None
        headers = {}
        if cfg.get("token"):
            headers["Authorization"] = f"Bearer {cfg['token']}"
        elif cfg.get("username"):
            auth = (cfg["username"], cfg.get("password") or "")
        self._client_args = {"base_url": server, "headers": headers, "auth": auth,
                             "verify": cfg["verify_tls"], "timeout": 10}

    async def send(self, title, message, priority="default", tags=None):
        """Publish one message. Returns (ok, detail); never raises."""
        body = {"topic": self.cfg["topic"], "title": title, "message": message,
                "priority": _priority(priority)}
        if tags:
            body["tags"] = list(tags)
        if self.cfg.get("click_url"):
            body["click"] = self.cfg["click_url"]
        try:
            # JSON publishing (POST to the server root) keeps titles UTF-8 safe.
            async with httpx.AsyncClient(**self._client_args) as client:
                r = await client.post("/", json=body)
        except httpx.HTTPError as e:
            log.warning("ntfy publish failed: %s", e)
            return False, str(e)
        if r.status_code >= 400:
            hint = {401: " (check token / username / password)",
                    403: " (this user can't write to that topic)"}.get(r.status_code, "")
            detail = f"HTTP {r.status_code}{hint}: {r.text.strip()[:200]}"
            log.warning("ntfy publish failed: %s", detail)
            return False, detail
        return True, "sent"

    def onsite_note(self, monitor):
        note = (self.cfg.get("onsite_note") or "").strip()
        if not note:
            return ""
        gw = monitor.resolve_target("{isp_gateway}") or "the ISP gateway"
        return "\n\n" + note.replace("{isp_gateway}", gw)

    # ---- outage notifications -----------------------------------------------

    async def run(self, monitor):
        """Watch for outages and publish start/resolve messages. Runs forever."""
        db = monitor.db
        sent = db.get_kv("ntfy_sent") or {}
        while True:
            try:
                changed = await self._pass(monitor, sent)
                if changed:
                    cutoff = time.time() - KEEP_SENT
                    for k in [k for k, v in sent.items() if v.get("ts", 0) < cutoff]:
                        del sent[k]
                    db.set_kv("ntfy_sent", sent)
            except Exception:  # noqa: BLE001 - notifications must never stop monitoring
                log.exception("ntfy notifier pass failed")
            await asyncio.sleep(POLL)

    async def _pass(self, monitor, sent):
        now = time.time()
        min_dur = self.cfg["min_duration_seconds"]
        skip = set(self.cfg.get("ignore_verdicts") or [])
        changed = False
        for o in analysis.outages(monitor.db, monitor.by_id, now - LOOKBACK, now):
            key = str(round(o["start"], 3))
            rec = sent.get(key, {})
            if rec.get("resolved"):
                continue
            # Outages that were already over before pickle started are history, not news.
            if not o["ongoing"] and o["end"] < monitor.started and not rec:
                continue
            names = ", ".join(monitor.by_id[c]["name"] for c in o["checks"] if c in monitor.by_id)

            if o["ongoing"]:
                if not rec.get("started") and o["duration"] >= min_dur:
                    if o["verdict"] in skip:
                        continue
                    ok, _ = await self.send(
                        f"Outage at {self.wan_host}",
                        f"Failing: {names}\n"
                        f"Down {_duration(o['duration'])} so far. "
                        f"Early read: {o['verdict_label']} (final verdict comes when it ends)."
                        + self.onsite_note(monitor),
                        self.cfg["priority_down"], ["rotating_light"])
                    if ok:
                        sent[key] = {"started": True, "ts": now}
                        changed = True
                continue

            # Over, but wait out the merge gap: if it comes back, it's the same outage.
            if now - o["end"] < analysis.MERGE_GAP:
                continue
            if not rec.get("started") and (o["duration"] < min_dur or o["verdict"] in skip):
                sent[key] = {"resolved": True, "ts": now}  # too short to bother anyone
                changed = True
                continue
            ok, _ = await self.send(
                f"Resolved: {o['verdict_label']} ({self.wan_host})",
                f"Down {_duration(o['duration'])}. Failing: {names}\n\n{o['explanation']}",
                self.cfg["priority_up"], ["white_check_mark"])
            if ok:
                sent[key] = {"started": rec.get("started", False), "resolved": True, "ts": now}
                changed = True
        return changed
