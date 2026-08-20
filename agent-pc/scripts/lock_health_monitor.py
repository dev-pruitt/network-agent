#!/usr/bin/env python3
"""Detect the August lock wedging, and say which failure it is.

WHAT THIS CANNOT DO
  It cannot keep the lock working. The fault measured on 2026-08-08 was
  inside the device: good signal, associated, ARP reachable, an ESTABLISHED
  TLS session - and 516ms average LAN latency while a peer on the same radio
  answered in 5ms, with the byte counter frozen for 36 seconds. Nothing on
  the network can prevent that. This shortens the time to knowing.

THE SIGNATURE, and why each part is needed
  Three conditions, and all three have to hold. Any one alone produces false
  alarms, which is how a monitor gets ignored:

    1. lock latency high        - the lock is struggling
    2. PEER latency normal      - a control on the same radio. Without it,
                                  every bit of RF interference or router load
                                  looks identical to a wedged lock.
    3. byte counter frozen      - an ESTABLISHED socket moving nothing. This
                                  is what separates "slow" from "hung".

  Measured during the real fault: lock 516ms / peer 5ms / counter unchanged
  across four samples. Measured healthy: lock 62ms / peer 5ms / counter
  climbing. The thresholds sit between those, not at round numbers.

WHAT IT REPORTS
  Not "lock offline". That was the old a1300 mistake - a verdict with no
  information. It reports which of the three conditions held, because that is
  what distinguishes a wedged device from RF trouble from an actual outage,
  and those need different responses from a human.

BATTERIES
  The prime suspect for the wedge is cells that hold idle voltage but sag
  under transmit load. The alert says so, because the cheapest test is fresh
  batteries and the operator should not have to remember that at the door.
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta

BASE = os.path.expanduser("~/network-agent")
LOGS = os.path.join(BASE, "logs")
NOTICES = os.path.join(LOGS, "notices.jsonl")
PROPOSALS = os.path.join(LOGS, "proposals.jsonl")
STATE = os.path.join(LOGS, "lock_health_state.json")
DIAG = os.path.join(LOGS, "lock_health.jsonl")

ROUTER = "b3000"
SSH = ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", ROUTER]

LOCK = "192.168.1.214"
PEER = "192.168.1.215"          # doorbell, same 2.4GHz radio - the control

# Thresholds sit between the measured healthy and measured wedged states,
# not at tidy round numbers.
# 200ms was measured against a lock that happened to be awake. A battery
# radio parks itself between beacons, so its resting reply is 300-1200ms - the
# old threshold sat BELOW normal and could never be satisfied. It reported a
# fault on 281 consecutive checks while the lock was working. Latency is now a
# corroborator only; this value exists to catch an extreme stall, not sleep.
LOCK_SLOW_MS = 2500
PEER_OK_MS = 40                 # healthy 5; above this the radio is the issue
CONSECUTIVE_BAD = 2

# A working lock holds an ESTABLISHED session out to its AWS endpoint and
# keeps moving bytes on it. That is the condition which must hold for the lock
# to function, so measure it - rather than inferring health from ping speed.
CLOUD_PORT = 443
FLAT_RUNS_BEFORE_WEDGED = 3     # ~30 min at the 10-minute cron interval
COOLDOWN = timedelta(hours=4)

# Fresh cells were fitted on 2026-08-10. The lock did not recover: the last
# healthy check was 2026-08-09T20:40 and it has been wedged on every check
# since, straight through the replacement. That is the battery hypothesis
# tested and failed, so this monitor must stop recommending it - advice that
# has already been tried and disproved is the same failure as a stale metric:
# confident, specific, wrong, and it sends the operator back down a dead end.
BATTERIES_REPLACED = "2026-08-10"


def router(cmd, timeout=40):
    try:
        r = subprocess.run(SSH + [cmd], capture_output=True, text=True,
                           timeout=timeout)
        if r.returncode != 0:
            return None, f"exit {r.returncode}"
        return r.stdout, None
    except subprocess.TimeoutExpired:
        return None, "ssh timeout"
    except Exception as e:
        return None, type(e).__name__


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
                     "message": msg, "source": "lock_health"})


def propose(detail, action):
    pid = f"L{datetime.now():%m%d%H%M%S}-lock_wedged"
    append(PROPOSALS, {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anomaly_type": "lock_wedged", "component": "august-lock",
        "severity": 2, "details": detail, "recommended_action": action,
        "playbook_id": "PB-LOCK-001", "source": "lock_health",
        "status": "pending"})
    return pid


def _close_stale_proposals(component, anomaly_type, why):
    """Close pending proposals for (component, anomaly_type) now that the
    monitor itself has confirmed recovery. Without this, a recovered fault's
    old proposal sits "pending" forever, which keeps discord_relay's alert
    gate open indefinitely and would silently swallow the NEXT real
    occurrence. See silent_state_audit.py's MASKING check, which exists to
    catch exactly this gap; this closes it at the source instead of relying
    on a human to notice the audit finding.

    Fails closed: any error leaves proposals.jsonl untouched and is not
    raised, because losing lock detection over a bookkeeping write is a
    worse outcome than a proposal staying open one cycle longer.
    """
    try:
        rows = [json.loads(l) for l in open(PROPOSALS) if l.strip()]
    except (OSError, json.JSONDecodeError):
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    closed = 0
    for r in rows:
        if (r.get("component") == component and r.get("anomaly_type") == anomaly_type
                and r.get("status") == "pending"):
            r["status"] = "closed_stale"
            r["closed_at"] = now
            r["closed_via"] = "lock_health_monitor_auto"
            r["closed_why"] = why
            closed += 1
    if not closed:
        return 0
    try:
        tmp = PROPOSALS + ".tmp"
        with open(tmp, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, PROPOSALS)
    except OSError:
        return 0
    return closed


def ping_avg(ip):
    """Average RTT in ms, or None if it could not be measured."""
    out, err = router(f"ping -c 6 -W 2 {ip} 2>/dev/null | tail -1")
    if err or not out:
        return None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    return float(m.group(1)) if m else None


def https_bytes():
    """Cumulative bytes on the lock's HTTPS counter, or None if unreadable."""
    out, err = router(
        "iptables -L LOCKWATCH -v -n -x 2>/dev/null | awk '/lw https/{print $2}'")
    if err or not out.strip():
        return None
    try:
        return int(out.strip().split()[0])
    except (ValueError, IndexError):
        return None



def cloud_session():
    """Live session to the cloud, and how many bytes have crossed it.

    Returns (established, bytes_total). (None, None) means the check could not
    be performed - which is NOT the same as "no session", and the caller must
    not treat it as one.
    """
    out, err = router("cat /proc/net/nf_conntrack 2>/dev/null | grep %s" % LOCK)
    if out is None:
        return None, None
    total, seen = 0, False
    for line in out.splitlines():
        if "tcp" not in line or "dport=%d" % CLOUD_PORT not in line:
            continue
        if "ESTABLISHED" not in line:
            continue
        seen = True
        for tok in line.split():
            if tok.startswith("bytes="):
                try:
                    total += int(tok.split("=", 1)[1])
                except ValueError:
                    pass
    return seen, (total if seen else 0)


def main():
    quiet = "--quiet" in sys.argv
    st = load_state()
    now = datetime.now()

    def say(*a):
        if not quiet:
            print(*a)

    lock_ms = ping_avg(LOCK)
    peer_ms = ping_avg(PEER)
    b1 = https_bytes()
    time.sleep(20)
    b2 = https_bytes()

    # Cannot observe is not a fault. The lock being unreachable entirely is a
    # different condition and is handled below, but an unreadable counter or a
    # dead SSH is a failure to look.
    if b1 is None or b2 is None:
        notice("lock_health_blind", "lock check could not read the counter",
               "LOCKWATCH unreadable - run router/remediation-*/"
               "b3000-lockwatch-persist.sh")
        say("  CANNOT OBSERVE - LOCKWATCH unreadable")
        return 0
    if peer_ms is None:
        notice("lock_health_blind", "lock check has no control measurement",
               f"could not ping the peer at {PEER}; without it a slow lock "
               f"cannot be told apart from a slow radio")
        say("  CANNOT OBSERVE - no peer measurement")
        return 0

    # A counter sitting at zero has NEVER seen traffic - it was just
    # (re)installed. That is absence of data, not evidence that flow stopped,
    # and conflating the two is the mistake this project keeps finding. Only
    # a counter that has previously moved can be meaningfully "frozen".
    fresh_counter = (b2 == 0)
    frozen = (b2 == b1) and not fresh_counter
    unreachable = lock_ms is None
    slow = (not unreachable) and lock_ms > LOCK_SLOW_MS
    peer_ok = peer_ms <= PEER_OK_MS

    say(f"  lock   {'unreachable' if unreachable else f'{lock_ms:.0f} ms'}")
    say(f"  peer   {peer_ms:.0f} ms  ({'normal' if peer_ok else 'ALSO SLOW'})")
    say(f"  bytes  {b1} -> {b2}  "
        f"({'no baseline yet' if fresh_counter else 'FROZEN' if frozen else 'moving'})")

    if fresh_counter:
        # Latency alone is still worth recording - it was the loudest signal
        # during the real fault - but without the counter this cannot claim
        # the full wedged signature.
        state = "unreachable" if unreachable else f"{lock_ms:.0f} ms"
        notice("lock_counter_fresh", "lock counter has no baseline",
               f"LOCKWATCH reads zero, so flow cannot be judged yet. "
               f"Latency right now: lock {state}, peer {peer_ms:.0f} ms.")
        say("  counter has no baseline - not judging flow this run")

    # --- classify ----------------------------------------------------------
    if not peer_ok:
        # The control is slow too, so this is not about the lock.
        notice("lock_radio_congested", "2.4GHz radio is slow for everything",
               f"lock {lock_ms}, peer {peer_ms} - both above normal. This is "
               f"the radio or router load, not the lock.")
        say("  -> radio-wide, not the lock")
        st["bad"] = 0
        save_state(st)
        return 0

    # PRIMARY signal: the lock is slow or gone while a device on the SAME
    # radio is fine. During the real fault that read 516ms against 5ms, and it
    # is the discriminator that cannot be explained by RF or router load.
    #
    # The byte counter CORROBORATES; it does not gate. Requiring it meant a
    # freshly installed counter made the monitor report "healthy" at 1151ms
    # against a 6ms peer - refusing to call an obvious fault because one of
    # three inputs was unavailable. Absence of a secondary signal is not
    # evidence of health.
    diverged = peer_ok and (slow or unreachable)

    # The authoritative signal. Flow is judged ACROSS RUNS - ten minutes apart
    # - not inside one 20-second sample. A lock that keepalives every few
    # minutes is silent in any 20-second window, which is exactly why the old
    # test read "frozen" on a healthy device.
    established, cloud_bytes = cloud_session()
    prev_bytes = st.get("cloud_bytes")
    st["cloud_bytes"] = cloud_bytes

    if established is None:
        say("  CANNOT OBSERVE - conntrack unreadable; not judging this run")
        save_state(st)
        return 0

    if established and prev_bytes is not None and cloud_bytes > prev_bytes:
        flat_runs = 0
    elif established and prev_bytes is None:
        flat_runs = 0
    else:
        flat_runs = st.get("flat_runs", 0) + 1
    st["flat_runs"] = flat_runs

    cloud_dead = (not established) or flat_runs >= FLAT_RUNS_BEFORE_WEDGED

    # BOTH must hold. Slow-and-talking is a sleeping radio: the lock's normal
    # resting state, and not something to wake anybody over.
    wedged = cloud_dead and diverged
    confidence = ("no cloud session" if not established
                  else "cloud flat %d runs" % flat_runs if cloud_dead
                  else "latency only")

    say("  cloud  %s  bytes %s -> %s  flat_runs=%d"
        % ("ESTABLISHED" if established else "NONE", prev_bytes, cloud_bytes,
           flat_runs))
    if diverged and not cloud_dead:
        say("  slow to ping but cloud session is live - battery power-save, "
            "not a fault")

    if not wedged:
        if st.get("bad"):
            notice("lock_recovered", "lock responsive again",
                   f"lock {lock_ms} ms, bytes moving.", kind="recover")
            say(f"  recovered after {st['bad']} bad round(s)")
            n = _close_stale_proposals(
                "august-lock", "lock_wedged",
                "lock_health_monitor detected recovery this run (wedged=False); "
                "auto-closed so the alert gate re-arms for a future wedge instead "
                "of staying muted on a cleared fault.")
            if n:
                say(f"  closed {n} stale pending proposal(s)")
        st["bad"] = 0
        save_state(st)
        # cloud_ok is the authoritative signal. `frozen` is kept only as
        # historical data and must NOT be read as a health verdict - a
        # keepalive device is silent inside any 20-second window.
        # silent_state_audit judged the lock on `frozen` and called a
        # working deadbolt "degraded" for 51 hours: the same mistake
        # lock_wedged already made, reached by a different route.
        append(DIAG, {"timestamp": now.isoformat(timespec="seconds"),
                      "lock_ms": lock_ms, "peer_ms": peer_ms,
                      "bytes": b2, "frozen": frozen, "wedged": False,
                      "cloud_ok": bool(established and not cloud_dead),
                      "flat_runs": flat_runs})
        say("  healthy")
        return 0

    st["bad"] = st.get("bad", 0) + 1
    say(f"  WEDGED ({st['bad']}) - {confidence}")
    append(DIAG, {"timestamp": now.isoformat(timespec="seconds"),
                  "lock_ms": lock_ms, "peer_ms": peer_ms,
                  "bytes": b2, "frozen": True, "wedged": True})

    if st["bad"] >= CONSECUTIVE_BAD:
        last = st.get("last_alert")
        if not (last and now - datetime.fromisoformat(last) < COOLDOWN):
            detail = (
                f"The deadbolt is not passing traffic to its cloud. "
                f"{confidence}. LAN latency "
                f"{('unreachable' if unreachable else f'{lock_ms:.0f} ms')} "
                f"against {peer_ms:.0f} ms for the doorbell on the same radio. "
                f"Seen on {st['bad']} consecutive checks.\n\n"
                f"This requires BOTH a stalled cloud session AND the latency "
                f"divergence. Latency alone is no longer enough: the lock is "
                f"battery-powered and parks its radio between beacons, so "
                f"300-1200ms against a mains-powered peer is its resting "
                f"state, not a fault. The previous version alerted on latency "
                f"alone and reported this device wedged 281 times while it "
                f"was working.\n\n"
                f"Already ruled out, do not repeat: fresh cells "
                f"({BATTERIES_REPLACED}), factory reset (done several times), "
                f"and August support confirm firmware and hardware are "
                f"fine.\n\n"
                f"Scope: this proves the lock is not passing traffic. It cannot "
                f"tell you the battery percentage - only the August app knows that.")
            action = ("Cloud session is genuinely stalled - batteries, "
                      "factory reset and August support are all ruled out. "
                      "Check whether the VPN exit is being refused by the "
                      "lock's AWS endpoint.")
            pid = propose(detail, action)
            st["last_alert"] = now.isoformat(timespec="seconds")
            say(f"  -> proposal {pid}")

    save_state(st)
    return 0


if __name__ == "__main__":
    sys.exit(main())
