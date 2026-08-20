#!/usr/bin/env python3
"""Watch the camera portal. Four independent things, four different failures.

WHY NOT ONE "IS IT UP" CHECK
  This stack has four pieces and each fails in a way the others hide:

    camera   -> mediamtx    RTSP pull. Dies if the camera reboots to a new
                            address or the credentials change.
    mediamtx -> disk        Recording. Can silently stop while the live view
                            keeps working perfectly.
    portal   -> mediamtx    The login layer. Can serve a page with no video.
    tunnel   -> internet    cloudflared. Everything can be healthy locally
                            while nobody outside can reach it.

  A single check that returns "ok" would be answering a question nobody asked.
  The recording one matters most: it is the only failure with no symptom. The
  portal looks fine, the stream plays, and the archive quietly stops - which
  is discovered weeks later when someone needs the footage.

DISK
  Retention is enforced by mediamtx, but only for the stream it manages. If
  the disk fills for any other reason, recording stops. Warn on headroom, not
  after the write fails.

Follows the rules the rest of this project earned: a probe failure is not a
condition, corroborate before asserting, cooldown so a persistent fault is a
steady note rather than a loop.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta

BASE = os.path.expanduser("~/network-agent")
LOGS = os.path.join(BASE, "logs")
NOTICES = os.path.join(LOGS, "notices.jsonl")
PROPOSALS = os.path.join(LOGS, "proposals.jsonl")
STATE = os.path.join(LOGS, "camera_monitor_state.json")

PORTAL = "http://127.0.0.1:8081"
RECORDINGS = os.path.expanduser("~/camera-recordings")
PUBLIC_URL = "https://cam.example.com/login"

# A 1h segment is still being written for up to an hour, so the newest file
# can legitimately be ~60 min old before a new one appears. Alert past that
# plus slack, not at the first quiet minute.
RECORDING_STALE_MIN = 75
DISK_WARN_PCT = 85
CONSECUTIVE_BAD = 2
COOLDOWN = timedelta(hours=6)


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(s):
    try:
        os.makedirs(LOGS, exist_ok=True)
        json.dump(s, open(STATE, "w"), indent=2)
    except OSError:
        pass


def append(path, rec):
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def notice(eid, title, msg, kind="info"):
    append(NOTICES, {"timestamp": datetime.now().isoformat(timespec="seconds"),
                     "kind": kind, "event_id": eid, "title": title,
                     "message": msg, "source": "camera_monitor"})


def propose(key, detail, action, severity=2):
    pid = f"C{datetime.now():%m%d%H%M%S}-{key}"
    append(PROPOSALS, {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anomaly_type": f"camera_{key}", "component": "camera",
        "severity": severity, "details": detail,
        "recommended_action": action, "playbook_id": "PB-CAM-001",
        "source": "camera_monitor", "status": "pending"})
    return pid


def http(url, timeout=10):
    """Returns (status, body) or (None, reason). Reason is not a fault."""
    try:
        import requests
        r = requests.get(url, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return None, type(e).__name__


def check_portal():
    code, body = http(f"{PORTAL}/api/health")
    if code is None:
        return {"ok": False, "observed": False, "why": f"portal unreachable ({body})"}
    if code != 200:
        return {"ok": False, "observed": True, "why": f"portal returned {code}"}
    try:
        d = json.loads(body)
    except Exception:
        return {"ok": False, "observed": False, "why": "portal health not JSON"}
    if d.get("mediamtx") != "ok":
        return {"ok": False, "observed": True,
                "why": f"portal cannot reach mediamtx: {d.get('mediamtx')}"}
    if not d.get("streams", {}).get("sd"):
        return {"ok": False, "observed": True,
                "why": "the recorded stream (sd) is not ready - the camera "
                       "pull has failed"}
    return {"ok": True, "observed": True, "why": "portal and mediamtx healthy"}


def check_recording():
    """The failure with no symptom. Live view keeps working; the archive stops."""
    newest, newest_mtime = None, 0
    for root, _, files in os.walk(RECORDINGS):
        for fn in files:
            p = os.path.join(root, fn)
            try:
                m = os.path.getmtime(p)
            except OSError:
                continue
            if m > newest_mtime:
                newest, newest_mtime = p, m
    if not newest:
        return {"ok": False, "observed": True, "why": "no recording files at all"}
    age_min = (time.time() - newest_mtime) / 60
    if age_min > RECORDING_STALE_MIN:
        return {"ok": False, "observed": True,
                "why": f"newest recording is {int(age_min)} min old "
                       f"(expected under {RECORDING_STALE_MIN})"}
    return {"ok": True, "observed": True,
            "why": f"newest recording {int(age_min)} min old"}


def check_disk():
    try:
        t, u, f = shutil.disk_usage(RECORDINGS)
    except OSError as e:
        return {"ok": False, "observed": False, "why": f"cannot stat: {e}"}
    pct = 100.0 * u / t
    size = sum(os.path.getsize(os.path.join(r, fn))
               for r, _, fs in os.walk(RECORDINGS) for fn in fs
               if os.path.exists(os.path.join(r, fn)))
    gb = size / 1e9
    if pct > DISK_WARN_PCT:
        return {"ok": False, "observed": True,
                "why": f"disk {pct:.0f}% full; recordings hold {gb:.0f} GB"}
    return {"ok": True, "observed": True,
            "why": f"disk {pct:.0f}% used, recordings {gb:.0f} GB, "
                   f"{f/1e9:.0f} GB free"}


def check_tunnel():
    """Local daemon state AND the public URL. The daemon can be 'active' while
    the hostname resolves nowhere - reporting one without the other is how a
    thing looks healthy while nobody can reach it."""
    r = subprocess.run(["systemctl", "is-active", "cloudflared"],
                       capture_output=True, text=True)
    if r.stdout.strip() != "active":
        return {"ok": False, "observed": True,
                "why": f"cloudflared is {r.stdout.strip() or 'not running'}"}
    code, body = http(PUBLIC_URL, timeout=15)
    if code is None:
        # Could not look. Not the same as looked and found broken - this box
        # may simply have no internet at this moment.
        return {"ok": False, "observed": False,
                "why": f"could not reach {PUBLIC_URL} ({body})"}
    if code != 200:
        return {"ok": False, "observed": True,
                "why": f"{PUBLIC_URL} returned {code}"}
    return {"ok": True, "observed": True, "why": "tunnel up, public URL serving"}


CHECKS = {
    "portal":    (check_portal,    "Portal or camera pull is down",
                  "Check: systemctl status camera-portal, docker logs mediamtx"),
    "recording": (check_recording, "Recording has stopped",
                  "Check docker logs mediamtx for recorder errors, and disk space"),
    "disk":      (check_disk,      "Disk is filling",
                  "Reduce RETENTION_DAYS in setup_mediamtx.py and re-run, or free space"),
    "tunnel":    (check_tunnel,    "Public access is down",
                  "Check: systemctl status cloudflared, journalctl -u cloudflared"),
}


def main():
    quiet = "--quiet" in sys.argv
    st = load_state()
    now = datetime.now()
    results = {}

    for key, (fn, title, action) in CHECKS.items():
        r = fn()
        results[key] = r
        s = st.setdefault(key, {"bad": 0, "last_alert": None})

        if not r["observed"]:
            # Failure to observe is not a condition. Record it; do not raise.
            notice(f"camera_{key}_blind", f"camera monitor could not check {key}",
                   r["why"])
            if not quiet:
                print(f"  {key:10} CANNOT OBSERVE - {r['why']}")
            continue

        if r["ok"]:
            if s["bad"]:
                notice(f"camera_{key}_recovered", f"{key} recovered",
                       r["why"], kind="recover")
                if not quiet:
                    print(f"  {key:10} recovered after {s['bad']} bad round(s)")
            s["bad"] = 0
            if not quiet:
                print(f"  {key:10} ok - {r['why']}")
            continue

        s["bad"] += 1
        if not quiet:
            print(f"  {key:10} FAIL ({s['bad']}) - {r['why']}")
        if s["bad"] < CONSECUTIVE_BAD:
            continue
        last = s.get("last_alert")
        if last and now - datetime.fromisoformat(last) < COOLDOWN:
            continue
        propose(key, f"{title}. {r['why']}. Seen on {s['bad']} consecutive "
                     f"checks.", action)
        s["last_alert"] = now.isoformat(timespec="seconds")
        if not quiet:
            print(f"             -> proposal raised")

    save_state(st)
    if "--json" in sys.argv:
        print(json.dumps({"checked_at": now.isoformat(timespec="seconds"),
                          "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
