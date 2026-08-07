#!/usr/bin/env python3
"""WAN-link flap detector.

Reads the ALREADY-persisted router syslog on the agent PC (no extra router
load) and raises a Level-3 "check the cable" proposal when the physical WAN
link (eth1.1) loses carrier repeatedly in a short window.

This is the failure mode that on 2026-07-30 masqueraded as a reboot loop: the
LINK, not the router, was flapping, and every flap forced a firewall reload =
a brief total outage. The agent had no signal for it, so it mislabeled the
symptom. This closes that gap and tells the operator to do the one thing that
actually fixes it - check the cable.

Usage:
  wan_flap_monitor.py            # normal: may queue a proposal (agent posts it)
  wan_flap_monitor.py --dry-run  # detect and print only; never writes/queues
Env:
  WAN_FLAP_SYSLOG=/path          # override syslog source (used for testing)
"""
import os, re, json, sys, time
from datetime import datetime, timedelta

BASE      = os.path.expanduser("~/network-agent")
SYSLOG    = os.environ.get("WAN_FLAP_SYSLOG") or os.path.join(BASE, "logs/router_syslog.log")
PROPOSALS = os.path.join(BASE, "logs/proposals.jsonl")
STATE     = os.path.join(BASE, "logs/.wan_flap_state")

WINDOW_MIN     = 15        # look back this many minutes of ROUTER log time
FLAP_THRESHOLD = 4         # >= this many WAN carrier-down events = flapping
COOLDOWN_SEC   = 3600      # re-alert at most once/hour while it persists
TAIL_BYTES     = 500_000   # only scan the freshest slice of the log

TS_RE   = re.compile(r"^([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2} \d{4})")
DOWN_RE = re.compile(r"eth1\.1'? link is down", re.I)


def parse_ts(s):
    try:
        return datetime.strptime(s, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def scan():
    """Return (down_count_in_window, last_down_ts, log_now).

    The window is anchored to the newest timestamp IN THE LOG, not the agent's
    wall clock, so it is immune to clock skew between router and agent.
    """
    if not os.path.exists(SYSLOG):
        return 0, None, None
    with open(SYSLOG, "rb") as f:
        try:
            f.seek(-TAIL_BYTES, os.SEEK_END)
        except OSError:
            f.seek(0)
        chunk = f.read().decode("utf-8", "replace")

    downs, log_now = [], None
    for line in chunk.splitlines():
        m = TS_RE.match(line)
        if not m:
            continue
        ts = parse_ts(m.group(1))
        if ts is None:
            continue
        if log_now is None or ts > log_now:
            log_now = ts
        if DOWN_RE.search(line):
            downs.append(ts)
    if log_now is None:
        return 0, None, None
    cutoff = log_now - timedelta(minutes=WINDOW_MIN)
    recent = [t for t in downs if t >= cutoff]
    return len(recent), (max(recent) if recent else None), log_now


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(s):
    try:
        json.dump(s, open(STATE, "w"))
    except OSError:
        pass


def build_proposal(count, last, log_now):
    pid = "PWANFLAP" + datetime.now().strftime("%m%d%H%M%S")
    when = last.strftime("%Y-%m-%d %H:%M:%S") if last else "?"
    return {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(),
        "anomaly_type": "wan_link_flapping",
        "component": "wan1 (eth1.1)",
        "severity": 3,
        "details": ("Physical WAN link flapped %d times in ~%d min "
                    "(carrier down/up on eth1.1; most recent %s router-time). "
                    "Router uptime is stable, so this is NOT a reboot - it is a "
                    "hardware/link fault. Each flap forces a firewall reload and "
                    "a brief total outage." % (count, WINDOW_MIN, when)),
        "recommended_action": ("Reseat the WAN Ethernet cable at BOTH ends "
                    "(router WAN port and modem/ONT). If it persists: swap the "
                    "cable for a known-good one, then power-cycle the modem/ONT. "
                    "Physical fault - cannot be fixed remotely."),
        "status": "pending",
    }


def main():
    dry = "--dry-run" in sys.argv
    count, last, log_now = scan()
    flapping = count >= FLAP_THRESHOLD
    print("[scan] window=%dmin downs=%d threshold=%d log_now=%s -> %s"
          % (WINDOW_MIN, count, FLAP_THRESHOLD,
             log_now.strftime("%H:%M:%S") if log_now else "?",
             "FLAPPING" if flapping else "ok"))

    if dry:
        if flapping:
            print("[dry-run] WOULD queue this proposal:")
            print(json.dumps(build_proposal(count, last, log_now), indent=2))
        else:
            print("[dry-run] no proposal (below threshold)")
        return

    state = load_state()
    recently = (time.time() - state.get("last_alert_epoch", 0)) < COOLDOWN_SEC
    if flapping and not recently:
        p = build_proposal(count, last, log_now)
        with open(PROPOSALS, "a") as f:
            f.write(json.dumps(p) + "\n")
        state["last_alert_epoch"] = time.time()
        state["last_alert_pid"] = p["proposal_id"]
        save_state(state)
        print("[ALERT] queued proposal %s (%d downs)" % (p["proposal_id"], count))
    elif flapping:
        print("[hold] flapping but within %ds cooldown" % COOLDOWN_SEC)
    else:
        if state.get("last_alert_epoch"):
            state["last_alert_epoch"] = 0
            save_state(state)
        print("[ok] WAN stable in window")


if __name__ == "__main__":
    main()
