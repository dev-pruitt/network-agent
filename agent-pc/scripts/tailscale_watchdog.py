#!/usr/bin/env python3
"""Keep remote phone access working, unattended.

WHAT BREAKS THIS SETUP, in rough order of likelihood

  1. tailscaled stops        agent lost power once this week; a dead daemon
                             takes the LAN route with it
  2. route stops being       another node claims primary, or prefs get reset
     advertised
  3. exit node un-advertised phone's internet dies while LAN still works,
                             which is a confusing failure to diagnose
  4. node key expires        SILENT. The route just stops. Nothing else in
                             this system would explain it. Cannot be fixed
                             from here - needs the admin console.

  1-3 are recoverable locally and are fixed automatically. 4 is not, so it
  warns early and loudly instead of pretending.

DESIGN RULES, learned the hard way this week

  - Corroborate before asserting. "tailscale status failed" means we could
    not observe, not that the tunnel is down. Those are logged differently.
  - A probe failure is never a condition (OPS-RULES.md D1).
  - Never claim a fix worked without re-checking. Every repair verifies.
  - Cooldown everything, so a persistent fault produces a steady note rather
    than a restart loop.

Actions are appended to logs/actions.jsonl in the same shape execute_action.py
uses, so they appear on the dashboard /actions page alongside tunnel rotations.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

BASE = os.path.expanduser("~/network-agent")
ACTION_LOG = os.path.join(BASE, "logs/actions.jsonl")
STATE_LOG = os.path.join(BASE, "logs/tailscale_state.jsonl")

WANT_ROUTE = "192.168.1.0/24"
RESTART_COOLDOWN_SEC = 600       # do not thrash a daemon that will not stay up
READVERTISE_COOLDOWN_SEC = 300
EXPIRY_WARN_DAYS = 14
ACTION_TYPE = "tailscale_repair"


def run(cmd, timeout=45):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 255, "", f"{type(e).__name__}: {e}"


def status():
    """Returns (dict, err). err set means we could not OBSERVE - not a fault."""
    rc, out, err = run(["tailscale", "status", "--json"])
    if rc != 0 or not out:
        return None, (err or f"exit {rc}")
    try:
        return json.loads(out), None
    except json.JSONDecodeError as e:
        return None, f"unparseable status: {e}"


def recent_action(kind, within_sec):
    """True if we already did this recently. Prevents repair loops."""
    if not os.path.exists(ACTION_LOG):
        return False
    cutoff = datetime.now() - timedelta(seconds=within_sec)
    try:
        for line in open(ACTION_LOG):
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e.get("action_type") != ACTION_TYPE or e.get("repair") != kind:
                continue
            if e.get("synthetic"):
                continue
            ts = datetime.fromisoformat(e["timestamp"])
            if ts > cutoff:
                return True
    except Exception:
        return False
    return False


def log_action(repair, cmd, success, detail):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "playbook_id": "PB-TS-001",
        "action_type": ACTION_TYPE,
        "issue_type": "tailscale_degraded",
        "component": "tailscale",
        "repair": repair,
        "command": cmd,
        "target": "local",
        "success": success,
        "error": None if success else detail,
        "rationale": detail,
        "autonomous": True,
    }
    with open(ACTION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def days_until(ts):
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (d - datetime.now(timezone.utc)).days
    except Exception:
        return None


def chain_exists(dump, name):
    """True if `name` is declared, in either iptables output format.

        iptables -S     ->  -N ts-forward
        iptables-save   ->  :ts-forward - [0:0]

    Grepping for one form while fetching the other is how this check produced
    three different false alarms. Accept both; the caller should not have to
    know which command was used.
    """
    return (re.search(r"^-N\s+" + re.escape(name) + r"\s*$", dump, re.M) is not None
            or re.search(r"^:" + re.escape(name) + r"\s", dump, re.M) is not None)


def check_forwarding_plumbing():
    """Is the route actually able to forward, or does it just LOOK advertised?

    Advertising a subnet says nothing about whether packets can traverse it.
    Tailscale installs ts-forward/ts-postrouting chains and relies on
    ip_forward; firewall.user rebuilds iptables chains on this network
    regularly, and a flush would leave the route looking perfectly healthy
    while silently dropping every packet.

    Checking configuration, not end-to-end reachability - proving the phone
    can reach the LAN requires testing from the phone, which cannot be done
    from here. Stated plainly rather than overclaimed.
    """
    problems = []
    notes = []

    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                problems.append("ip_forward disabled")
    except OSError:
        pass                      # cannot read is not a fault

    # iptables-save, not `iptables -S`. The latter dumps only the FILTER
    # table, and ts-postrouting lives in NAT - the old check asserted a nat
    # chain against filter output, so it could never pass. One call, every
    # table, one sudoers grant.
    # iptables-save dumps EVERY table. `iptables -S` dumps filter only, and
    # ts-postrouting lives in nat - so which command succeeded decides what
    # this function is entitled to conclude.
    saw_nat = True
    rc, out, _ = run(["sudo", "-n", "iptables-save"], timeout=20)
    if rc != 0:
        saw_nat = False
        rc, out, _ = run(["sudo", "-n", "iptables", "-S"], timeout=20)
    if rc != 0:
        # No permission to read the table. A failure to OBSERVE, not a fault.
        return problems, False, notes

    if not chain_exists(out, "ts-forward"):
        problems.append("ts-forward chain missing")
    elif "-A ts-forward -i tailscale0 -j MARK" not in out:
        problems.append("ts-forward present but not marking tailscale0")
    # Subnet SNAT is optional. With --snat-subnet-routes=false there is
    # legitimately no ts-postrouting chain, and calling that a fault is how
    # the old check invented an outage. Ask the daemon what it intends before
    # judging what it installed.
    snat_expected = True
    rc_p, prefs, _ = run(["tailscale", "debug", "prefs"], timeout=10)
    if rc_p == 0 and re.search(r'"NoSNAT"\s*:\s*true', prefs):
        snat_expected = False

    if not saw_nat:
        # Could not read the nat table at all. Absence of the string proves
        # nothing about the chain, so assert nothing. This is the difference
        # between "observed a fault" and "failed to observe", and collapsing
        # the two is what restarted a healthy daemon.
        notes.append("nat table unreadable (needs: sudo bash "
                     "agent-pc/scripts/grant-tailscale-ops.sh) - "
                     "ts-postrouting NOT verified")
    elif not snat_expected:
        notes.append("subnet SNAT disabled by preference - "
                     "ts-postrouting absent is expected")
    elif not chain_exists(out, "ts-postrouting"):
        problems.append("ts-postrouting chain missing (subnet NAT)")

    return problems, True, notes


def peer_reachable():
    """Ping a tailnet peer. Proves the tunnel carries traffic, not just that
    the daemon claims to be Running."""
    d, err = status()
    if err or not d:
        return None
    for _, p in (d.get("Peer") or {}).items():
        if not p.get("Online"):
            continue
        ip = (p.get("TailscaleIPs") or [None])[0]
        if not ip:
            continue
        rc, _, _ = run(["ping", "-c", "2", "-W", "3", ip], timeout=15)
        return rc == 0
    return None                   # no online peer to test against


# --------------------------------------------------------------------------
# repairs
# --------------------------------------------------------------------------
def repair_daemon():
    """tailscaled is not answering. Restart it and verify it came back."""
    if recent_action("restart_daemon", RESTART_COOLDOWN_SEC):
        print("  HOLD  restart within cooldown - not thrashing")
        return False
    cmd = "sudo -n systemctl restart tailscaled"
    rc, _, err = run(["sudo", "-n", "systemctl", "restart", "tailscaled"], timeout=60)
    if rc != 0:
        log_action("restart_daemon", cmd, False,
                   f"restart failed: {err[:160]}")
        print(f"  FAIL  could not restart tailscaled: {err[:100]}")
        return False

    # never claim success without re-checking
    import time
    time.sleep(8)
    d, err = status()
    ok = bool(d) and d.get("BackendState") == "Running"
    log_action("restart_daemon", cmd, ok,
               "tailscaled restarted and Running" if ok
               else f"restarted but state is {(d or {}).get('BackendState', err)}")
    print("  DONE  tailscaled restarted" if ok else "  FAIL  restart did not restore Running")
    return ok


def repair_advertisement(missing_route, missing_exit):
    """Prefs drifted. Re-assert what this node is supposed to advertise."""
    if recent_action("readvertise", READVERTISE_COOLDOWN_SEC):
        print("  HOLD  re-advertise within cooldown")
        return False
    args = ["tailscale", "set"]
    if missing_route:
        args.append(f"--advertise-routes={WANT_ROUTE}")
    if missing_exit:
        args.append("--advertise-exit-node")
    cmd = " ".join(args)

    rc, _, err = run(args)
    if rc != 0:
        log_action("readvertise", cmd, False, f"set failed: {err[:160]}")
        print(f"  FAIL  {err[:110]}")
        return False

    import time
    time.sleep(6)
    d, _ = status()
    s = (d or {}).get("Self", {})
    ok = (not missing_route or WANT_ROUTE in (s.get("PrimaryRoutes") or [])) and \
         (not missing_exit or s.get("ExitNodeOption"))
    log_action("readvertise", cmd, ok,
               f"re-advertised route={missing_route} exit={missing_exit}")
    print("  DONE  re-advertised" if ok else "  WARN  re-advertised but not yet primary")
    return ok


# --------------------------------------------------------------------------
def main():
    dry = "--dry-run" in sys.argv
    findings, repairs = [], 0

    d, err = status()

    if err:
        # Could not observe. NOT the same as "tailscale is down".
        if "connect" in err.lower() or "not running" in err.lower():
            print(f"[tailscale] daemon not answering: {err[:90]}")
            findings.append("daemon_unreachable")
            if not dry:
                repairs += 1 if repair_daemon() else 0
            else:
                print("  WOULD restart tailscaled")
        else:
            print(f"[tailscale] could not observe ({err[:90]}) - not asserting a fault")
        return 0

    self_ = d.get("Self", {})
    state = d.get("BackendState")
    routes = self_.get("PrimaryRoutes") or []
    exit_ok = bool(self_.get("ExitNodeOption"))

    print(f"[tailscale] state={state} routes={routes or 'NONE'} exit={exit_ok}")

    if state != "Running":
        findings.append(f"backend_{state}")
        print(f"  backend is {state}, not Running")
        if state == "NeedsLogin":
            # Re-auth needs a human with a browser. Do not pretend otherwise.
            print("  [WARN] NeedsLogin - requires re-authentication in a browser")
        elif not dry:
            repairs += 1 if repair_daemon() else 0

    missing_route = WANT_ROUTE not in routes
    missing_exit = not exit_ok
    if (missing_route or missing_exit) and state == "Running":
        findings.append("advertisement_drift")
        print(f"  drift: route_missing={missing_route} exit_missing={missing_exit}")
        if not dry:
            repairs += 1 if repair_advertisement(missing_route, missing_exit) else 0
        else:
            print("  WOULD re-advertise")

    # Key expiry - cannot be fixed from here, so warn early and clearly.
    exp = days_until(self_.get("KeyExpiry"))
    if exp is not None and exp <= EXPIRY_WARN_DAYS:
        findings.append("key_expiry")
        print(f"  [WARN] node key expires in {exp}d - when it does, the LAN "
              f"route dies silently. Disable key expiry for this node in the "
              f"admin console.")

    # Advertised is not the same as working. If iptables gets flushed - and
    # firewall.user rebuilds chains on this network regularly - the route
    # still reports healthy while dropping every packet.
    plumbing, observed, _fwd_notes = check_forwarding_plumbing()
    if observed and plumbing:
        findings.append("forwarding_broken")
        for p in plumbing:
            print(f"  [WARN] forwarding: {p}")
        print("  route is advertised but cannot carry traffic - "
              "restart tailscaled to reinstall its chains")
        if not dry and state == "Running":
            repairs += 1 if repair_daemon() else 0
    elif not observed:
        print("  (cannot read iptables - forwarding not verified)")

    # Proves the tunnel actually carries packets, rather than trusting that
    # BackendState=Running means traffic flows.
    reach = peer_reachable()
    if reach is False:
        findings.append("peer_unreachable")
        print("  [WARN] no online peer answered a ping over the tunnel")
    elif reach is None:
        print("  (no online peer to test against)")

    with open(STATE_LOG, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "backend_state": state, "routes": routes,
            "exit_node": exit_ok, "key_expiry_days": exp,
            "findings": findings, "repairs": repairs,
        }) + "\n")

    if not findings:
        for _n in (_fwd_notes or []):
            print(f"  [note] {_n}")
        print("  healthy" if not _fwd_notes
              else "  healthy - but see the note(s) above; not everything was verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
