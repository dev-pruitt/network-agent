#!/usr/bin/env python3
"""Drain router alerts into the agent's proposal pipeline.

FLOW
----
  router monitor -> phone-alert -> /tmp/alert-spool.jsonl   (router, no secrets)
       -> [this script, over existing SSH] -> proposals.jsonl
       -> discord_relay.py -> Discord embed with approve/deny

WHY NOT PUSH FROM THE ROUTER
----------------------------
The agent deliberately runs with no inbound ports. Pulling keeps the trust
direction unchanged (agent -> router, same as all other telemetry), adds no
listener, and keeps the Discord credential off the router entirely. The router
currently stores an iCloud app password; after this, it stores nothing.

WHAT THIS ADDS OVER PLAIN FORWARDING
------------------------------------
A raw alert says "HomePod APNs session lost". A proposal says what it means,
what to do, how risky the fix is, and offers an approve/deny. Each known alert
maps to a playbook with a severity, so router events land in the same
escalation model as everything else rather than in a parallel notification
channel.
"""
import json
import os
import subprocess
import time

BASE      = os.path.expanduser("~/network-agent")
PROPOSALS = os.path.join(BASE, "logs/proposals.jsonl")
NOTICES   = os.path.join(BASE, "logs/notices.jsonl")
SEEN      = os.path.join(BASE, "logs/.router_alerts_seen")
SPOOL     = "/tmp/alert-spool.jsonl"

# event_id prefix -> (severity, playbook, recommended action)
#   1 = agent may act autonomously
#   2 = needs your approval in Discord
#   3 = manual/physical intervention; posted without reactions
PLAYBOOKS = {
    "ipv6leak":   (3, "PB-V6-001",
                   "VPN posture may be compromised. Verify no global IPv6 sits on a "
                   "raw WAN and no v6 default route bypasses the tunnel. Do not "
                   "auto-remediate - confirm manually first."),
    "wan-":       (2, "PB-WAN-002",
                   "Check the cable and upstream modem. kmwan has likely failed over, "
                   "so internet still works but redundancy is lost."),
    "wg":         (2, "PB-WG-001",
                   "Tunnel down. The watchdog restarts and rotates automatically; "
                   "approve only if it has not recovered on its own."),
    "a1300":      (3, "PB-EXT-001",
                   "Laundry-room extender unreachable. Check its power, placement, "
                   "and 2.4GHz signal back to the router. Physical check required."),
    "homepod":    (3, "PB-HP-001",
                   "HomePod lost its Apple push session. Siri will be unresponsive. "
                   "Restart the affected HomePod from the Home app."),
    "guest":      (2, "PB-GST-001",
                   "Guest network event. Review the device and confirm it should have "
                   "access."),
    "carrier":    (2, "PB-WAN-003",
                   "Carrier/uplink event. Verify upstream connectivity."),
}
DEFAULT = (2, "PB-GEN-001", "Review the router alert and decide whether action is needed.")


def classify(event_id, title):
    key = f"{event_id} {title}".lower()
    for prefix, spec in PLAYBOOKS.items():
        if prefix in key:
            return spec
    return DEFAULT


def load_seen():
    try:
        with open(SEEN) as f:
            return set(json.load(f))
    except (OSError, json.JSONDecodeError):
        return set()


def save_seen(seen):
    # Bound the file; keep the most recent 500 fingerprints.
    trimmed = sorted(seen)[-500:]
    tmp = SEEN + ".tmp"
    with open(tmp, "w") as f:
        json.dump(trimmed, f)
    os.replace(tmp, SEEN)


def fetch_spool():
    """Read and truncate the router spool atomically-ish.

    Move-then-read so alerts arriving mid-drain are not lost: the monitor
    appends to a fresh spool while we consume the rotated copy.
    """
    cmd = ("if [ -s /tmp/alert-spool.jsonl ]; then "
           "mv /tmp/alert-spool.jsonl /tmp/alert-spool.draining; "
           "cat /tmp/alert-spool.draining; "
           "rm -f /tmp/alert-spool.draining; fi")
    try:
        r = subprocess.run(["ssh", "b3000", cmd],
                           capture_output=True, text=True, timeout=25)
        if r.returncode != 0:
            print(f"[WARN] router unreachable: {r.stderr.strip()[:120]}")
            return []
        return [l for l in r.stdout.splitlines() if l.strip()]
    except Exception as e:
        print(f"[WARN] spool fetch failed: {e}")
        return []


def resolve_recovered(event_id, when):
    """Close pending proposals that this recovery answers.

    An alert becomes a pending proposal; the matching recover used to become a
    notice and nothing else, so the proposal stayed pending forever. Measured
    once: nine 'a1300down' recoveries while the original alarm stayed lit and
    the operator kept rebooting a working device.

    Matching is exact - anomaly_type == f"router_{event_id}". Substring
    matching would let one event close a different alarm, and closing the
    wrong alarm is worse than closing none.
    """
    want = f"router_{event_id}"
    try:
        rows = [json.loads(l) for l in open(PROPOSALS) if l.strip()]
    except (OSError, json.JSONDecodeError):
        return 0
    n = 0
    for r in rows:
        if r.get("status") != "pending" or r.get("anomaly_type") != want:
            continue
        # A recovery cannot answer a question raised after it.
        if r.get("timestamp", "") > when:
            continue
        r["status"] = "resolved"
        r["decided_at"] = when
        r["resolution_note"] = (f"router reported {event_id} recovered at "
                                f"{when}; closed automatically")
        n += 1
    if n:
        tmp = PROPOSALS + ".tmp"
        with open(tmp, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, PROPOSALS)
    return n


def main():
    lines = fetch_spool()
    if not lines:
        print("[INFO] no new router alerts")
        return

    seen = load_seen()
    added = 0
    notices = 0

    with open(PROPOSALS, "a") as out:
        for line in lines:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            sev_name = ev.get("severity", "alert")
            eid      = ev.get("event_id", "unknown")
            title    = ev.get("title", "Router alert")
            msg      = ev.get("message", "")

            # Informational events are NOT proposals. The router already makes
            # this distinction in /usr/bin/discord-alert:
            #     alert) -> a real condition, de-duplicated
            #     send)  -> spool_event info "manual" ...
            # Previously only "recover" was excluded, so every routine success
            # ("VPN Server Rotated", "VPN Rotation Skipped") was filed as
            # something awaiting a decision and quietly accumulated.
            # monitor_blind means the agent could not read its own counters -
            # a failure to observe, not a condition (OPS-RULES.md D1).
            # It fires whenever a chain is rebuilt under the reader.
            if (sev_name in ("recover", "info")
                    or eid.lower().endswith("_blind")
                    or "monitor_blind" in title.lower()):
                fp_n = f"{eid}|{ev.get('ts','')}|{title}"
                if fp_n not in seen:
                    seen.add(fp_n)
                    with open(NOTICES, "a") as nf:
                        nf.write(json.dumps({
                            "timestamp": ev.get("ts", time.strftime("%Y-%m-%dT%H:%M:%S")),
                            "kind":      sev_name,
                            "event_id":  eid,
                            "title":     title,
                            "message":   msg[:1200],
                            "source":    "router_monitor",
                        }) + "\n")
                    notices += 1
                # A recovery answers the alarm it recovered from. Filing it as
                # a notice and leaving the proposal pending is what kept the
                # laundry extender "down" through nine recoveries while the
                # operator rebooted a working device.
                if sev_name == "recover":
                    _closed = resolve_recovered(
                        eid, ev.get("ts", time.strftime("%Y-%m-%dT%H:%M:%S")))
                    if _closed:
                        print(f"[RESOLVED] {_closed} proposal(s) closed "
                              f"by {eid} recovery")
                print(f"[NOTICE] {eid}: {title}")
                continue

            fp = f"{eid}|{ev.get('ts','')}|{title}"
            if fp in seen:
                continue
            seen.add(fp)

            severity, playbook, action = classify(eid, title)
            pid = f"R{time.strftime('%m%d%H%M%S')}-{eid[:12]}"

            out.write(json.dumps({
                "proposal_id":        pid,
                "timestamp":          ev.get("ts", time.strftime("%Y-%m-%dT%H:%M:%S")),
                "anomaly_type":       f"router_{eid}",
                "component":          "router",
                "severity":           severity,
                "details":            f"{title} - {msg}"[:1800],
                "recommended_action": action,
                "playbook_id":        playbook,
                "source":             "router_monitor",
                "status":             "pending",
            }) + "\n")
            added += 1
            print(f"[PROPOSAL] {pid}  L{severity}  {title}")

    save_seen(seen)
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] drained={len(lines)} proposals={added} notices={notices}")


if __name__ == "__main__":
    main()
