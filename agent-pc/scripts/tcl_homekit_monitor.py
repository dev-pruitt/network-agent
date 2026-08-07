#!/usr/bin/env python3
"""Monitor the TCL air conditioners.

WHAT THIS MEASURES, AND WHY IT CHANGED (2026-08-06)

  The original monitor declared an AC critical when it saw zero mDNS packets
  in an 8-second capture, with no reachability check:

      if mdns_count == 0:
          severity: critical   evidence: "TCL AC <ip> ZERO mDNS packets"

  Three separate faults, found in one morning:

  1. It watched the wrong devices. TCL_IPS was hardcoded to 192.168.1.214
     and .237. .214 is an unrelated device (vendor prefix 78:9c:85) and
     nothing at all answers on .237. The real units are TCL-AC-1 and
     TCL-AC-2 on vendor prefix bc:09:b9, and both were online throughout.

  2. It never corroborated. mDNS silence alone was treated as "device down",
     so a healthy, pingable unit with a DHCP lease read as critical.

  3. The premise was wrong for this hardware. These ACs are cloud devices -
     they hold an MQTT/TLS session out to TCL's cloud on port 8883. They do
     not advertise over mDNS and never will, so mDNS silence carries no
     information about them at all. Watching for it could only ever produce
     a permanent false alarm.

  Health is therefore an established outbound session, corroborated by
  reachability. mDNS is still counted, but recorded as an observation rather
  than used to assert a condition.

  The check also verifies the WG_LB pin. Those AC addresses drifted once
  already and nobody noticed for weeks; an invariant that matters should be
  measured, not assumed.
"""
import json
import os
import subprocess
from datetime import datetime

DIAGNOSTICS_LOG = os.path.expanduser("~/network-agent/logs/tcl_monitor.jsonl")

MDNS_WINDOW = 30
SSH_TIMEOUT = MDNS_WINDOW + 25

# Located by how the network already identifies them, not by address. A
# hardcoded list is what caused this monitor to watch two wrong addresses.
TCL_MAC_PREFIX = "bc:09:b9"
TCL_NAME_HINT = "tcl"
LEASES = "/tmp/dhcp.leases"

# WG_LB pins these devices to wgclient so automation has one stable path.
# 0xc000 == 49152. conntrack prints the mark in decimal.
EXPECTED_MARK = 49152
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.2", "172.30.", "172.31.", "127.")


def ssh_b3000(cmd, timeout=30):
    try:
        r = subprocess.run(["ssh", "b3000", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.stdout.strip() else (
            r.stderr.strip() if r.returncode != 0 else "")
    except Exception as e:
        return f"ERROR: {e}"


def discover_tcl():
    """Find the units in the DHCP leases by vendor OUI or hostname.

    Lease format: <expiry> <mac> <ip> <hostname> <clientid>
    """
    out = ssh_b3000(f"cat {LEASES} 2>/dev/null")
    found = {}
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) < 4:
            continue
        mac, ip, name = parts[1].lower(), parts[2], parts[3]
        if mac.startswith(TCL_MAC_PREFIX) or TCL_NAME_HINT in name.lower():
            found[ip] = {"ip": ip, "mac": mac,
                         "name": name if name != "*" else "(unnamed)"}
    return [found[k] for k in
            sorted(found, key=lambda a: [int(o) for o in a.split(".")])]


def check_reachable(ip):
    """Second signal, so silence is never mistaken for absence."""
    loss_out = ssh_b3000(
        f"ping -c 3 -W 2 {ip} 2>/dev/null | grep -o '[0-9]*% packet loss'")
    loss = 100
    try:
        loss = int(loss_out.split("%")[0].strip())
    except Exception:
        pass
    mac = ssh_b3000(
        "awk -v i=%s '$1==i && $4!=\"00:00:00:00:00:00\" {print $4}' /proc/net/arp" % ip)
    mac = mac.strip() or None
    if mac and ("ERROR" in mac or " " in mac):
        mac = None
    return (loss < 100), mac


def check_cloud_session(ip):
    """Established outbound session to a public address - the real health signal.

    Returns {established, dport, dst, mark, pinned}.
    """
    out = ssh_b3000(f"conntrack -L 2>/dev/null | grep 'src={ip} ' | grep ESTABLISHED")
    best = {"established": False, "dport": None, "dst": None,
            "mark": None, "pinned": None}
    if out.startswith("ERROR"):
        return best

    for line in out.split("\n"):
        fields = dict()
        for tok in line.split():
            if "=" in tok:
                k, _, v = tok.partition("=")
                fields.setdefault(k, v)
        dst = fields.get("dst")
        if not dst or dst.startswith(PRIVATE_PREFIXES):
            continue                      # LAN chatter is not a cloud session
        mark = fields.get("mark")
        try:
            mark_i = int(mark) if mark is not None else None
        except ValueError:
            mark_i = None
        best = {
            "established": True,
            "dport": fields.get("dport"),
            "dst": dst,
            "mark": mark_i,
            "pinned": (mark_i is not None and (mark_i & EXPECTED_MARK) == EXPECTED_MARK),
        }
        break
    return best


def check_mdns_all(ips):
    """Recorded as an observation only. These devices are not mDNS advertisers,
    so a zero here is expected and must not drive an alert."""
    if not ips:
        return {}
    hosts = " or ".join(f"src host {ip}" for ip in ips)
    out = ssh_b3000(
        f"timeout {MDNS_WINDOW} tcpdump -i br-lan -n -l 'udp port 5353 and ({hosts})' 2>&1",
        timeout=SSH_TIMEOUT)
    if out.startswith("ERROR"):
        return {ip: -1 for ip in ips}
    counts = {ip: 0 for ip in ips}
    for line in out.split("\n"):
        for ip in ips:
            if f"IP {ip}." in line:
                counts[ip] += 1
    return counts


def check_conntrack(ip):
    out = ssh_b3000(f"conntrack -L 2>/dev/null | grep -c 'src={ip} '")
    try:
        return int(out.strip())
    except Exception:
        return 0


def diagnose():
    issues = []
    units = discover_tcl()

    if not units:
        # Failing to find them is a failure to OBSERVE, not an outage.
        diagnosis = {
            "timestamp": datetime.now().isoformat(),
            "issues": [{
                "issue_type": "tcl_discovery_failed", "severity": "warning",
                "evidence": (f"No device matched OUI {TCL_MAC_PREFIX} or name "
                             f"'{TCL_NAME_HINT}' in {LEASES} - cannot observe"),
                "playbook_id": "PB-TCL-006", "escalation_level": 1,
                "parameters": {}}],
            "devices": [], "summary": "TCL units not found in DHCP leases",
            "requires_action": True, "escalation_level": 1,
        }
        with open(DIAGNOSTICS_LOG, "a") as f:
            f.write(json.dumps(diagnosis) + "\n")
        return diagnosis

    ips = [u["ip"] for u in units]
    mdns = check_mdns_all(ips)
    devices = []

    for unit in units:
        ip = unit["ip"]
        reachable, mac = check_reachable(ip)
        cloud = check_cloud_session(ip)

        devices.append({
            "ip": ip, "name": unit["name"], "mac": mac or unit["mac"],
            "reachable": reachable,
            "cloud_session": cloud["established"],
            "cloud_dst": cloud["dst"], "cloud_port": cloud["dport"],
            "pinned": cloud["pinned"], "mark": cloud["mark"],
            "mdns_packets": mdns.get(ip, -1),      # observation, not a verdict
        })

        if not reachable:
            issues.append({
                "issue_type": "device_offline", "severity": "critical",
                "evidence": (f"TCL AC {unit['name']} {ip} OFFLINE - no ping "
                             f"response and no ARP entry"),
                "playbook_id": "PB-TCL-001", "escalation_level": 3,
                "parameters": {"ip": ip}})

        # NOT an issue: a missing conntrack entry does not mean the unit is
        # uncontrollable. An idle long-lived MQTT session ages out of the
        # table and the device reconnects on demand - confirmed with the
        # operator on TCL-AC-2, which reads "no session" and works fine.
        # Recorded in devices[] as an observation instead. Asserting a
        # condition from a signal that cannot support it is exactly the fault
        # this monitor was rewritten to remove.

        elif cloud["pinned"] is False:
            # The WG_LB pin drifted. This exact invariant broke once already
            # when DHCP moved the units and nobody noticed for weeks.
            issues.append({
                "issue_type": "pin_missing", "severity": "warning",
                "evidence": (f"TCL AC {unit['name']} {ip} has a cloud session to "
                             f"{cloud['dst']}:{cloud['dport']} but mark="
                             f"{cloud['mark']} not {EXPECTED_MARK} - WG_LB pin "
                             f"is not being applied"),
                "playbook_id": "PB-TCL-004", "escalation_level": 2,
                "parameters": {"ip": ip}})

        ct = check_conntrack(ip)
        if ct > 50:
            issues.append({
                "issue_type": "conntrack_bloat", "severity": "warning",
                "evidence": f"TCL AC {unit['name']} {ip} has {ct} conntrack entries",
                "playbook_id": "PB-TCL-002", "escalation_level": 1,
                "parameters": {"ip": ip, "entry_count": ct}})

    healthy = [d for d in devices
               if d["reachable"] and d["cloud_session"] and d["pinned"]]
    offline = [d for d in devices if not d["reachable"]]

    if not issues:
        summary = f"All {len(devices)} TCL ACs healthy"
    else:
        bits = []
        if offline:
            bits.append(f"{len(offline)} offline")
        if healthy:
            bits.append(f"{len(healthy)} healthy")
        summary = f"{len(issues)} TCL issue(s)" + (" - " + ", ".join(bits) if bits else "")

    max_esc = max([i["escalation_level"] for i in issues]) if issues else 0
    diagnosis = {
        "timestamp": datetime.now().isoformat(),
        "issues": issues, "devices": devices, "summary": summary,
        "requires_action": len(issues) > 0, "escalation_level": max_esc,
    }
    with open(DIAGNOSTICS_LOG, "a") as f:
        f.write(json.dumps(diagnosis) + "\n")
    return diagnosis


def main():
    diag = diagnose()
    print(f"[{diag['timestamp']}] TCL Monitor: {diag['summary']}")
    for d in diag["devices"]:
        state = "reachable" if d["reachable"] else "UNREACHABLE"
        sess = (f"{d['cloud_dst']}:{d['cloud_port']}" if d["cloud_session"]
                else "no session")
        pin = "pinned" if d["pinned"] else ("UNPINNED" if d["cloud_session"] else "-")
        print(f"  {d['ip']:16} {d['name']:12} {state:12} {sess:24} {pin:9} mdns={d['mdns_packets']}")
    for issue in diag["issues"]:
        print(f"  [{issue['severity'].upper()}] {issue['issue_type']}: {issue['evidence']}")


if __name__ == "__main__":
    main()
