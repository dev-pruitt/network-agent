#!/usr/bin/env python3
"""recorder_watchdog.py -- keep the 24/7 recording alive.

On 2026-08-12 the mediamtx republisher ffmpeg wedged: the sd stream went
not-ready and recording silently wrote nothing for ~8 hours. Detection existed
but nothing RECOVERED it. This does: if the newest recording has not grown for
STALE_SEC, or the sd path is not ready, restart mediamtx (which reliably re-runs
the republisher), wait, re-check, and alert once through the proposal queue --
"recovered" if the restart fixed it, "needs hands" if not (camera unreachable).
Cooldown stops restart loops. Runs from cron every 5 minutes.
"""
import json, os, subprocess, time, urllib.request
from datetime import datetime

REC_DIR = os.path.expanduser("~/camera-recordings/sd")
PROPOSALS = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
STATE = os.path.expanduser("~/network-agent/logs/recorder_watchdog_state.json")
MTX_API = "http://127.0.0.1:9997"
STALE_SEC = 300
COOLDOWN = 900
WAIT_AFTER = 20

def newest_recording_age():
    try:
        days = sorted(d for d in os.listdir(REC_DIR) if os.path.isdir(os.path.join(REC_DIR, d)))
    except OSError:
        return None
    newest = None
    for d in reversed(days[-2:]):
        p = os.path.join(REC_DIR, d)
        for n in os.listdir(p):
            if n.endswith(".mp4"):
                m = os.path.getmtime(os.path.join(p, n))
                if newest is None or m > newest:
                    newest = m
        if newest is not None:
            break
    return None if newest is None else time.time() - newest

def sd_ready():
    try:
        with urllib.request.urlopen(MTX_API + "/v3/paths/get/sd", timeout=5) as r:
            return bool(json.load(r).get("ready"))
    except Exception:
        return None

def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}

def save_state(st):
    tmp = STATE + ".tmp"; json.dump(st, open(tmp, "w")); os.replace(tmp, STATE)

def alert(sev, atype, details, action):
    row = {"proposal_id": "W" + datetime.now().strftime("%m%d%H%M%S") + "-" + atype,
           "timestamp": datetime.now().isoformat(), "anomaly_type": atype,
           "component": "camera", "severity": sev, "details": details,
           "recommended_action": action, "status": "pending", "source": "recorder_watchdog"}
    with open(PROPOSALS, "a") as f:
        f.write(json.dumps(row) + "\n")

def restart_mediamtx():
    subprocess.run(["docker", "restart", "mediamtx"], timeout=60, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    age = newest_recording_age(); ready = sd_ready()
    stalled = (age is None) or (age > STALE_SEC) or (ready is False)
    st = load_state(); now = time.time()
    stamp = datetime.now().strftime("%H:%M:%S")
    if not stalled:
        st["last_status"] = "ok"; st["last_check"] = now; save_state(st)
        print("[%s] ok (age=%ss ready=%s)" % (stamp, None if age is None else round(age), ready))
        return
    if now - st.get("last_restart", 0) < COOLDOWN:
        st["last_status"] = "stalled_cooldown"; save_state(st)
        print("[%s] stalled but in cooldown" % stamp); return
    print("[%s] RECORDING STALLED (age=%s ready=%s) -> restart mediamtx" % (
          stamp, None if age is None else round(age), ready))
    restart_mediamtx(); st["last_restart"] = now; time.sleep(WAIT_AFTER)
    age2 = newest_recording_age(); ready2 = sd_ready()
    if (ready2 is True) or (age2 is not None and age2 < STALE_SEC):
        st["last_status"] = "recovered"
        alert(2, "recorder_recovered",
              "Recording had stalled; auto-restarted mediamtx and it recovered.",
              "None needed - handled. Investigate the camera if this recurs.")
        print("recovered")
    else:
        st["last_status"] = "restart_failed"
        alert(1, "recorder_stalled",
              "Recording stalled and a mediamtx restart did NOT recover it. Camera may be unreachable.",
              "Check camera power/network, then: docker logs mediamtx")
        print("still stalled - alerted level 1")
    save_state(st)

if __name__ == "__main__":
    main()
