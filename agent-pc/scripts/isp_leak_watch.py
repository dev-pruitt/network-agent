#!/usr/bin/env python3
"""ISP-side leak watch.

The GL router (Marble) should be the ONLY thing on the ISP gateway's LAN
(10.0.0.x). Anything else there is a device that attached to the ISP gateway
DIRECTLY - bypassing the GL router, the VPN, the kill switch and the guest
portal. This scans that subnet from the router's WAN side and raises a Level-3
proposal listing any strays.

Why it recurs: ISP firmware updates sometimes silently re-enable the
gateway's WiFi, and devices that still remember the ISP SSID rejoin it.

Cost: one SSH to the router per run (the router runs the sweep). Meant for a
~15-minute cron cadence.

Usage:
  isp_leak_watch.py            # normal: may queue a proposal (agent posts it)
  isp_leak_watch.py --dry-run  # detect + print only, never writes/queues
  isp_leak_watch.py --prime    # record current strays as baseline + mute for
                                    # one cooldown, WITHOUT posting (used once at
                                    # install so it doesn't nag about known leaks)
Env:
  XLEAK_INPUT=/path   # read scan output from a file instead of SSH (testing)
"""
import os, re, json, sys, time, subprocess
from datetime import datetime

BASE      = os.path.expanduser("~/network-agent")
PROPOSALS = os.path.join(BASE, "logs/proposals.jsonl")
STATE     = os.path.join(BASE, "logs/.isp_leak_state")
COOLDOWN_SEC = 3600

# Runs on the ROUTER (via ssh b3000). Derives the WAN /24, sweeps it, prints the
# WAN IP, the gateway, and the resolved neighbor entries.
REMOTE = r'''
WANIP=$(ip -4 -o addr show eth1.1 | grep -oE '([0-9]+\.){3}[0-9]+' | head -1)
GW=$(ip route | grep -E 'default via .* dev eth1.1' | grep -oE '([0-9]+\.){3}[0-9]+' | head -1)
NET=$(echo "$WANIP" | cut -d. -f1-3)
for i in $(seq 1 254); do ping -c1 -W1 "$NET.$i" >/dev/null 2>&1 & done; wait
echo "WANIP=$WANIP"
echo "GW=$GW"
echo NEIGH:
ip neigh show dev eth1.1 | grep lladdr
echo ALLOW:
cat /etc/guest-security/isp-allowlist.conf 2>/dev/null || true
'''


def get_scan():
    override = os.environ.get("XLEAK_INPUT")
    if override:
        try:
            return open(override).read(), None
        except OSError as e:
            return None, "input file error: %s" % e
    try:
        r = subprocess.run(["ssh", "b3000", REMOTE],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None, "ssh timeout"
    if r.returncode != 0:
        return None, "ssh error: %s" % r.stderr.strip()
    return r.stdout, None


MAC_RE = re.compile(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')


def is_private_mac(mac):
    """Locally-administered bit set => randomised address that ROTATES.
    Weak evidence of a NEW device; may be a known device that changed MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def parse(out):
    """D4 -- model expected state; alert on deviation, not on presence.

    Devices on the ISP gateway LAN are NOT automatically leaks. The Xbox,
    the work laptop (own corporate VPN) and the secondary router used for TV
    tracking isolation are placed there deliberately. Only MACs absent from
    /etc/guest-security/isp-allowlist.conf are reported.
    """
    wanip = gw = None
    neigh = []
    allow_macs = set()
    in_allow = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("ALLOW:"):
            in_allow = True
            continue
        if in_allow:
            m = MAC_RE.search(s.split("#", 1)[0])
            if m:
                allow_macs.add(m.group(0).lower())
            continue
        if s.startswith("WANIP="):
            wanip = s.split("=", 1)[1].strip()
        elif s.startswith("GW="):
            gw = s.split("=", 1)[1].strip()
        elif "lladdr" in s:
            m = re.match(r'^([0-9.]+)\s+lladdr\s+([0-9a-fA-F:]+)', s)
            if m:
                neigh.append((m.group(1), m.group(2).lower()))
    allow_ips = {x for x in (wanip, gw) if x}
    strays = [(ip, mac) for ip, mac in neigh
              if ip not in allow_ips and mac not in allow_macs]
    return wanip, gw, strays


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


def build_proposal(wanip, gw, strays):
    pid = "PXLEAK" + datetime.now().strftime("%m%d%H%M%S")
    listing = "; ".join("%s (%s)" % (ip, mac) for ip, mac in strays)
    return {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(),
        "anomaly_type": "isp_lan_leak",
        "component": "wan1 (eth1.1 / ISP LAN)",
        # D6: weak proxy signal -- capped at Level 2. Real containment is
        # measured by leak-watch-monitor on the router (LEAK_WATCH counters),
        # which detects our OWN traffic escaping un-tunneled. Presence of a
        # device on the gateway LAN is not itself a leak.
        "severity": 2,
        "details": ("%d device(s) on the ISP gateway LAN are not in the "
                    "allowlist: %s.%s "
                    "NOTE: devices on this LAN are not automatically a containment "
                    "failure -- the Xbox, work laptop and secondary router live there "
                    "by design. Containment is measured by leak-watch-monitor on the "
                    "router, not by this check."
                    % (len(strays), listing,
                       (" %d use a private/randomised MAC, which rotates -- weak "
                        "evidence of a NEW device."
                        % sum(1 for _, m in strays if is_private_mac(m)))
                       if any(is_private_mac(m) for _, m in strays) else "")),
        "recommended_action": ("If a listed device is intentional, add its MAC to "
                    "/etc/guest-security/isp-allowlist.conf and it will stop "
                    "reporting. If it is genuinely unexpected, confirm the ISP "
                    "gateway WiFi is OFF (http://10.0.0.1 -> Gateway -> Connection "
                    "-> Wi-Fi; both radios Disabled), then reconnect the device to "
                    "the GL SSID and 'Forget' the ISP network."),
        "status": "pending",
    }


def main():
    dry   = "--dry-run" in sys.argv
    prime = "--prime" in sys.argv

    out, err = get_scan()
    if out is None:
        print("[warn] scan failed: %s" % err)
        return
    wanip, gw, strays = parse(out)
    if not wanip or not gw:
        print("[warn] could not determine WAN IP/gateway - skipping to avoid a "
              "false alarm (wanip=%s gw=%s)" % (wanip, gw))
        return

    stray_macs = sorted(m for _, m in strays)
    print("[scan] wan=%s gw=%s strays=%d %s"
          % (wanip, gw, len(strays),
             [("%s/%s" % (ip, mac)) for ip, mac in strays]))

    if dry:
        if strays:
            print("[dry-run] WOULD queue this proposal:")
            print(json.dumps(build_proposal(wanip, gw, strays), indent=2))
        else:
            print("[dry-run] clean - only router + gateway present")
        return

    state = load_state()

    if prime:
        state["baseline_macs"] = stray_macs
        state["last_alert_epoch"] = time.time()   # mute one cooldown window
        save_state(state)
        print("[prime] baseline recorded (%d known strays); muted for %ds"
              % (len(stray_macs), COOLDOWN_SEC))
        return

    if not strays:
        if state.get("last_alert_epoch"):
            state["last_alert_epoch"] = 0
            state["baseline_macs"] = []
            save_state(state)
        print("[ok] ISP LAN clean")
        return

    # Strays present. Alert if a NEW device appeared (not in baseline) or the
    # cooldown has lapsed.
    baseline = set(state.get("baseline_macs", []))
    new_device = any(m not in baseline for m in stray_macs)
    cooled = (time.time() - state.get("last_alert_epoch", 0)) >= COOLDOWN_SEC
    if new_device or cooled:
        p = build_proposal(wanip, gw, strays)
        with open(PROPOSALS, "a") as f:
            f.write(json.dumps(p) + "\n")
        state["last_alert_epoch"] = time.time()
        state["baseline_macs"] = stray_macs
        save_state(state)
        print("[ALERT] queued %s (%d strays; new_device=%s)"
              % (p["proposal_id"], len(strays), new_device))
    else:
        print("[hold] %d strays but within cooldown and no new device" % len(strays))


if __name__ == "__main__":
    main()
