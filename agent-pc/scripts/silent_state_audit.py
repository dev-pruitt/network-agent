#!/usr/bin/env python3
"""Surface SILENT state - the failure mode that never announces itself.

  MASKING   A condition is muted in the relay gate, but its source monitor now
            reads HEALTHY. The mute stands on a fault that already cleared, so
            the NEXT occurrence of that fault is swallowed too. (The camera:
            recovered on its own, but a stuck 'pending' proposal keeps the
            fingerprint standing, so a fresh outage stays quiet until the 7-day
            heartbeat.)

  DEGRADED  A monitor is in an abnormal state that sits BELOW its own page
            threshold, so it never alerts. (The August lock: 'frozen' and ~1s
            response for days, but the cloud bytes trickle so it never trips the
            full 'wedged' bar - real degradation, zero notifications.)

Default mode is READ-ONLY. With --emit it appends ONE gated proposal per silent
finding so the existing relay + quiet_gate pipeline pages it exactly once, then
stays quiet. Idempotent. Fail LOUD: an unreadable state file is reported as
CANNOT VERIFY, never assumed healthy; --emit never fires on an UNVERIFIED item.
"""
import json, os, sys, time
from collections import defaultdict
from datetime import datetime

BASE = os.path.expanduser("~/network-agent")
LOGS = os.path.join(BASE, "logs")
RECORDINGS = os.path.expanduser("~/camera-recordings")
RECORDING_STALE_MIN = 75

PROPOSALS = os.path.join(LOGS, "proposals.jsonl")
GATE = os.path.join(LOGS, "alert_gate_state.json")

# anomaly_type -> (state file, key-path to its "bad" counter). bad==0 means the
# monitor currently sees no fault. Anything not listed is left UNVERIFIED.
MONITOR_BAD = {
    "camera_portal":    ("camera_monitor_state.json", ["portal", "bad"]),
    "camera_recording": ("camera_monitor_state.json", ["recording", "bad"]),
    "lock_wedged":      ("lock_health_state.json", ["bad"]),
    "dns_escape_doh":   ("dns_escape_state.json", ["doh", "bad"]),
}
# Human-actionable or inherently transient; not a "silent mute".
HUMAN_OR_TRANSIENT = {"resident_signup"}


def _load_json(path):
    with open(path) as f:
        return json.load(f)


def _dig(d, keys):
    for k in keys:
        d = d[k]
    return d


def _age_hours(ts):
    try:
        return round((datetime.now() - datetime.fromisoformat(ts[:26])).total_seconds() / 3600, 1)
    except Exception:
        return None


def _newest_recording_age_min():
    newest = 0
    try:
        for root, _, files in os.walk(RECORDINGS):
            for fn in files:
                try:
                    m = os.path.getmtime(os.path.join(root, fn))
                except OSError:
                    continue
                if m > newest:
                    newest = m
    except OSError:
        return None
    if not newest:
        return None
    return (time.time() - newest) / 60.0


def source_health(typ):
    """True=healthy, False=still bad, None=cannot verify."""
    spec = MONITOR_BAD.get(typ)
    if not spec:
        return None, "no monitor mapping"
    fname, keys = spec
    try:
        st = _load_json(os.path.join(LOGS, fname))
        bad = _dig(st, keys)
    except (OSError, ValueError, KeyError, TypeError) as e:
        return None, "CANNOT VERIFY (%s: %s)" % (fname, e)
    healthy = (int(bad) == 0)
    if typ == "camera_recording":
        age = _newest_recording_age_min()
        if age is None:
            return None, "CANNOT VERIFY (no recordings readable)"
        rec_ok = age < RECORDING_STALE_MIN
        if rec_ok != healthy:
            return None, "CONFLICT (bad=%s but newest recording %d min old)" % (bad, int(age))
        return healthy, "bad=%s, newest recording %d min old" % (bad, int(age))
    return healthy, "bad=%s" % bad


def collect():
    """Return findings as structured dicts, plus UNVERIFIED/STALE notes."""
    out = {"MASKING": [], "DEGRADED": [], "STALE": [], "UNVERIFIED": []}
    try:
        gate = _load_json(GATE)
    except (OSError, ValueError):
        gate = {}

    try:
        pend = [json.loads(l) for l in open(PROPOSALS) if l.strip()]
    except OSError as e:
        out["UNVERIFIED"].append("proposals.jsonl: CANNOT VERIFY (%s)" % e)
        return out, gate
    pend = [p for p in pend if p.get("status") == "pending"]

    for p in pend:
        typ = p.get("anomaly_type", "?")
        comp = p.get("component", "?")
        if typ in HUMAN_OR_TRANSIENT or typ in ("silent_mute", "silent_degrade"):
            continue
        age = _age_hours(p.get("timestamp", ""))
        key = "%s|%s" % (comp, typ)
        muted = key in gate
        supp = gate.get(key, {}).get("alert_suppressed", 0)
        healthy, why = source_health(typ)
        rec = {"type": typ, "comp": comp, "age": age, "why": why,
               "supp": supp, "since": gate.get(key, {}).get("alert_first_at", "?")}
        if healthy is None:
            rec["muted"] = muted
            out["UNVERIFIED"].append(rec)
        elif healthy and muted:
            out["MASKING"].append(rec)
        elif healthy and not muted:
            out["STALE"].append(rec)

    try:
        rows = [json.loads(l) for l in open(os.path.join(LOGS, "lock_health.jsonl")) if l.strip()][-12:]
        if rows:
            wedged = sum(1 for r in rows if r.get("wedged"))
            frozen = sum(1 for r in rows if r.get("frozen"))
            lock_ms = sorted(r.get("lock_ms") for r in rows if r.get("lock_ms") is not None)
            peer_ms = sorted(r.get("peer_ms") for r in rows if r.get("peer_ms") is not None)
            if not lock_ms or not peer_ms:
                # lock_health_monitor writes lock_ms/peer_ms: null when the
                # counter was unreadable or the peer was unpingable. That is
                # not evidence of DEGRADED or of healthy - it is a blind
                # sample, so say so rather than crash or silently drop it.
                out["UNVERIFIED"].append(
                    "lock_health.jsonl: %d/%d recent checks missing lock_ms/peer_ms "
                    "(unreadable counter or no peer control) - cannot compute a median"
                    % (len(rows) - min(len(lock_ms), len(peer_ms)), len(rows)))
            else:
                med_lock = lock_ms[len(lock_ms) // 2]
                med_peer = peer_ms[len(peer_ms) // 2]
                # `frozen` is the 20-second byte-counter test. A deadbolt that
                # keepalives every few minutes is silent inside any 20-second
                # window, so frozen is TRUE on a perfectly healthy lock - which
                # is why lock_wedged stopped using it. Judging degradation on it
                # here reproduced the same false positive by another route and
                # reported a working lock as silently degrading for 51 hours.
                #
                # cloud_ok is the real signal: does the lock still hold an
                # ESTABLISHED session to its cloud, judged across runs. Absent
                # from older rows, so absence means "cannot tell" and must not
                # be read as a fault.
                cloud_seen = [r for r in rows if "cloud_ok" in r]
                cloud_bad = sum(1 for r in cloud_seen if not r.get("cloud_ok"))
                if (cloud_seen and wedged == 0
                        and cloud_bad >= len(cloud_seen) / 2):
                    out["DEGRADED"].append({
                        "comp": "august-lock", "frozen": frozen, "n": len(rows),
                        "med_lock": med_lock, "med_peer": med_peer})
    except (OSError, ValueError) as e:
        out["UNVERIFIED"].append("lock_health.jsonl: CANNOT VERIFY (%s)" % e)
    return out, gate


def _fmt(rec):
    if "med_lock" in rec:
        return ("august-lock cloud session stalled in %d/%d recent checks, never "
                "wedged -> no page. median lock %.0fms vs peer %.0fms." %
                (rec["frozen"], rec["n"], rec["med_lock"], rec["med_peer"]))
    base = "%s/%s (pending %sh; %s)" % (rec["type"], rec["comp"], rec["age"], rec["why"])
    if rec.get("supp"):
        base += " muted x%d since %s" % (rec["supp"], rec["since"])
    return base


def report(out):
    total = sum(len(v) for v in out.values())
    print("SILENT-STATE AUDIT  %s" % datetime.now().isoformat(timespec="seconds"))
    if total == 0:
        print("  all clear - nothing muted-but-healthy, nothing degraded-but-silent.")
        return
    order = [("MASKING", "MASKING (a real fault will be swallowed)"),
             ("DEGRADED", "DEGRADED-SILENT (abnormal, below its own page bar)"),
             ("STALE", "STALE PENDING (source healthy, not gate-muted)"),
             ("UNVERIFIED", "UNVERIFIED (could not confirm - treat as blind spot)")]
    for k, title in order:
        if out[k]:
            print(" %s:" % title)
            for rec in out[k]:
                print("   - " + (rec if isinstance(rec, str) else _fmt(rec)))


def emit(out):
    """Append one gated proposal per MASKING/DEGRADED finding. Idempotent."""
    try:
        existing = [json.loads(l) for l in open(PROPOSALS) if l.strip()]
    except OSError as e:
        print("EMIT ABORT: cannot read proposals (%s)" % e)
        return
    open_keys = {(p.get("component"), p.get("anomaly_type"))
                 for p in existing if p.get("status") == "pending"}

    new = []
    now = datetime.now()
    ts = now.strftime("%m%d%H%M%S")

    # MASKING: group by underlying component so one subsystem = one page. Both
    # camera_portal and camera_recording live under component "camera"; they must
    # collapse to a single proposal, or they share a gate key and flip-flop.
    by_comp = defaultdict(set)
    for rec in out["MASKING"]:
        by_comp[rec["comp"]].add(rec["type"])
    for comp, types in sorted(by_comp.items()):
        if (comp, "silent_mute") in open_keys:
            continue
        open_keys.add((comp, "silent_mute"))
        tstr = ", ".join(sorted(types))
        new.append({
            "proposal_id": "SM%s-%s" % (ts, comp),
            "timestamp": now.isoformat(), "anomaly_type": "silent_mute",
            "component": comp, "severity": 2,
            "details": ("SILENT MUTE: %s (%s) is muted in the alert gate but its monitor now "
                        "reads healthy. The mute stands on a cleared fault, so the next real "
                        "failure is swallowed until it clears." % (comp, tstr)),
            "recommended_action": ("Resolve the stale pending %s proposal(s) and clear the gate "
                                   "entry to re-arm alerting." % comp),
            "playbook_id": "PB-SILENT-001", "source": "silent_state_audit", "status": "pending"})

    for rec in out["DEGRADED"]:
        comp = rec["comp"]
        if (comp, "silent_degrade") in open_keys:
            continue
        open_keys.add((comp, "silent_degrade"))
        new.append({
            "proposal_id": "SD%s-%s" % (ts, comp),
            "timestamp": now.isoformat(), "anomaly_type": "silent_degrade",
            "component": comp, "severity": 2,
            "details": ("SILENT DEGRADE: %s is abnormal but below its own page threshold, so it "
                        "never alerts. Frozen/slow but not fully wedged." % comp),
            "recommended_action": "Check %s directly; it is degraded under the auto-page bar." % comp,
            "playbook_id": "PB-SILENT-001", "source": "silent_state_audit", "status": "pending"})

    if not new:
        print("EMIT: nothing new (all silent findings already have an open proposal).")
        return
    with open(PROPOSALS, "a") as f:
        for p in new:
            f.write(json.dumps(p) + "\n")
    for p in new:
        print("EMIT: %s %s/%s" % (p["proposal_id"], p["anomaly_type"], p["component"]))


def main():
    out, _gate = collect()
    report(out)
    if "--emit" in sys.argv:
        emit(out)


if __name__ == "__main__":
    main()
