#!/usr/bin/env python3
"""Detect a LAN device resolving DNS outside the router.

WHY THIS EXISTS
  Plain DNS is already forced to the router by DNAT, and DoT on 853 is
  rejected at the WAN. Neither of those can be bypassed quietly. DoH cannot be
  closed the same way: it is HTTPS on 443 and looks exactly like web traffic,
  so it is blockable only by knowing the resolver's address. A device using an
  unlisted DoH endpoint resolves names outside the router's view.

  That is not an ISP leak - it still egresses through Proton - but it means
  the DoH provider sees the query stream, and the router's DNS policy stops
  applying to that device. Worth knowing about; not worth panicking over.

WHAT IT CHECKS, and what each one can actually prove

  1. DNS_LEAK WAN counters
     Direct evidence. These rows only increment when a port-53 packet heads
     for a raw WAN interface. Nonzero means plain DNS genuinely escaped the
     tunnel. This is the strongest signal here and the one worth alerting on.

  2. Port 853 attempts
     The reject rules block DoT to the raw WAN, but the counter shows whether
     anything is TRYING. A device repeatedly attempting DoT is a device
     configured to bypass, even though it is failing.

  3. Conntrack to known DoH resolvers
     Best-effort by construction. The list below is well-known endpoints, so
     absence proves nothing - it cannot see an endpoint it does not know.
     Reported as an observation, never as "no DoH in use", because claiming
     the second from the first is exactly the overreach this project keeps
     finding.

Follows the rules the rest of the agent earned: a probe failure is not a
condition, corroborate before asserting, cooldown so a standing fault is a
steady note rather than a loop.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

BASE = os.path.expanduser("~/network-agent")
LOGS = os.path.join(BASE, "logs")
NOTICES = os.path.join(LOGS, "notices.jsonl")
PROPOSALS = os.path.join(LOGS, "proposals.jsonl")
STATE = os.path.join(LOGS, "dns_escape_state.json")
DIAG = os.path.join(LOGS, "dns_escape.jsonl")

ROUTER = "b3000"
SSH = ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", ROUTER]

CONSECUTIVE_BAD = 2
COOLDOWN = timedelta(hours=6)

# Well-known DoH endpoints. Deliberately incomplete - see the docstring. A hit
# is meaningful; a miss is not evidence of anything.
DOH_IPS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "45.90.28.0": "NextDNS", "45.90.30.0": "NextDNS",
}

# These are the router's own upstreams and probe targets. Traffic to them from
# the ROUTER is expected; only LAN clients going direct is interesting.
EXPECTED_FROM_ROUTER = {"9.9.9.9", "149.112.112.112", "10.2.0.1"}

# Resolvers whose use has been investigated and ACCEPTED. Still counted, still
# reported in the daily digest - they simply stop raising proposals.
#
# Without this the monitor had nowhere to record a decision, so it re-raised
# the same finding on 192 consecutive checks and the gate suppressed it 1511
# times. Suppression is not agreement; it just hides a question nobody
# answered. A decision belongs in the code, next to the thing it is about.
#
# An UNaccepted resolver appearing alongside an accepted one still pages
# normally, so this narrows the alert rather than blinding the check.
ACCEPTED_DOH = {
    # eufy OmniC20 vacuum resolves through Google DoH. Investigated: it still
    # egresses through the tunnel, so nothing bypasses the VPN - only the
    # router's own DNS policy. Judged low-stakes; count, do not block.
    "8.8.8.8": "eufy vacuum (accepted 2026-08-20)",
    "8.8.4.4": "eufy vacuum (accepted 2026-08-20)",
}


def router(cmd, timeout=25):
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
                     "message": msg, "source": "dns_escape_monitor"})


def propose(key, detail, action, severity=2):
    pid = f"D{datetime.now():%m%d%H%M%S}-{key}"
    append(PROPOSALS, {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anomaly_type": f"dns_escape_{key}", "component": "router",
        "severity": severity, "details": detail,
        "recommended_action": action, "playbook_id": "PB-DNS-001",
        "source": "dns_escape_monitor", "status": "pending"})
    return pid


# ---------------------------------------------------------------------------
def check_wan_leak():
    """Port-53 packets heading for a raw WAN interface. Direct evidence."""
    out, err = router(
        "iptables -L DNS_LEAK -v -n -x 2>/dev/null | "
        "awk '/eth1\\.[13]/ {print $1}'")
    if err:
        return {"observed": False, "why": f"cannot read DNS_LEAK ({err})"}
    nums = [int(x) for x in out.split() if x.isdigit()]
    if not nums:
        # The chain exists but no WAN rows matched. Cannot conclude clean.
        return {"observed": False,
                "why": "DNS_LEAK has no WAN rows - shape changed, check the chain"}
    total = sum(nums)
    return {"observed": True, "ok": total == 0, "count": total,
            "why": (f"{total} port-53 packet(s) have headed for a raw WAN "
                    f"interface" if total else
                    "no port-53 packet has ever left via a raw WAN interface")}


def check_dot_attempts():
    """Blocked, but are devices trying? A trier is a misconfigured device."""
    out, err = router(
        "iptables -L FORWARD -v -n -x 2>/dev/null | "
        "awk '/dports 53,853/ {s+=$1} END {print s+0}'")
    if err:
        return {"observed": False, "why": f"cannot read FORWARD ({err})"}
    try:
        n = int(out.strip().split()[0])
    except (ValueError, IndexError):
        return {"observed": False, "why": "unparseable counter"}
    return {"observed": True, "ok": n == 0, "count": n,
            "why": (f"{n} DNS/DoT packet(s) rejected at the WAN - something is "
                    f"trying to bypass" if n else
                    "nothing has attempted DNS or DoT direct to the WAN")}


def check_doh():
    """DoH attempts since the last poll, from accumulating counters.

    Replaces a conntrack sample. A DoH query lasts milliseconds, so sampling
    every 15 minutes observed almost none of them and reported that absence
    as a clean result - a claim the method could not support. The DOH_WATCH
    chain counts continuously, so a delta of zero means nothing happened in
    the whole window rather than nothing happened while I was looking.

    Still cannot see an endpoint that is not in the chain. That limit is
    stated in the alert text rather than papered over.
    """
    out, err = router(
        "iptables -L DOH_WATCH -v -n -x 2>/dev/null | "
        "awk '/doh-watch/ {print $1, $9}'")
    if err:
        return {"observed": False, "why": f"cannot read DOH_WATCH ({err})"}
    if not out.strip():
        return {"observed": False,
                "why": ("DOH_WATCH chain missing - run "
                        "router/remediation-*/b3000-doh-counters.sh")}

    totals = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            totals[parts[1]] = int(parts[0])

    # Read only. main() owns the state file and is the single writer - this
    # function used to save here and have main() overwrite it a moment later,
    # so the counters were erased every run and no delta was ever measured.
    prev = load_state().get("doh_counters", {})
    deltas = {ip: n - prev.get(ip, n) for ip, n in totals.items()}
    deltas = {ip: d for ip, d in deltas.items() if d > 0}

    if not prev:
        # First run establishes the baseline; a delta against nothing is not
        # a measurement.
        return {"observed": True, "ok": True, "hits": {}, "totals": totals,
                "why": (f"baseline recorded across {len(totals)} resolver(s); "
                        f"deltas measured from the next run")}

    # Accepted resolvers stay in `totals` (still counted, still in the digest)
    # but are kept out of `named`, which is what decides whether to raise.
    accepted = {ip: d for ip, d in deltas.items() if ip in ACCEPTED_DOH}
    deltas = {ip: d for ip, d in deltas.items() if ip not in ACCEPTED_DOH}
    named = {f"{DOH_IPS.get(ip, ip)} ({ip})": d for ip, d in deltas.items()}
    return {"observed": True, "ok": not named, "hits": named, "totals": totals,
            "why": (f"{sum(deltas.values())} packet(s) to "
                    f"{len(named)} known DoH resolver(s) since the last check"
                    if named else
                    "no traffic to any KNOWN DoH resolver since the last check "
                    "(unlisted endpoints remain invisible)")}


CHECKS = {
    "wan_leak": (check_wan_leak,
                 "Plain DNS escaped the tunnel",
                 "Check the DNS_LEAK chain and the port-53 DNAT rules on the "
                 "router; a device is reaching a resolver outside the tunnel."),
    "dot_attempt": (check_dot_attempts,
                    "A device is attempting DNS-over-TLS to the WAN",
                    "Blocked, so nothing leaked - but find the device and fix "
                    "its resolver setting rather than leaving it retrying."),
    "doh": (check_doh,
            "A LAN device is using an external DoH resolver",
            "Its queries bypass the router's DNS policy. Either point the "
            "device at the router or add the endpoint to the DoH blocklist."),
}


def main():
    quiet = "--quiet" in sys.argv
    st = load_state()
    now = datetime.now()
    results = {}

    def say(*a):
        if not quiet:
            print(*a)

    for key, (fn, title, action) in CHECKS.items():
        r = fn()
        results[key] = r
        # Fold any counters the check read into the state main() will save.
        # main() is the only writer; a check that saves its own copy gets
        # overwritten by this one.
        if r.get("totals"):
            st["doh_counters"] = r["totals"]
        s = st.setdefault(key, {"bad": 0, "last_alert": None})

        if not r.get("observed"):
            notice(f"dns_escape_{key}_blind",
                   f"DNS escape check could not run: {key}", r["why"])
            say(f"  {key:12} CANNOT OBSERVE - {r['why']}")
            continue

        if r.get("ok"):
            if s["bad"]:
                notice(f"dns_escape_{key}_clear", f"{key} clear", r["why"],
                       kind="recover")
                say(f"  {key:12} cleared after {s['bad']} bad round(s)")
            s["bad"] = 0
            say(f"  {key:12} ok - {r['why']}")
            continue

        s["bad"] += 1
        say(f"  {key:12} FAIL ({s['bad']}) - {r['why']}")
        if r.get("hits"):
            for h in r["hits"]:
                say(f"               {h}")
        if s["bad"] < CONSECUTIVE_BAD:
            continue
        last = s.get("last_alert")
        if last and now - datetime.fromisoformat(last) < COOLDOWN:
            continue
        detail = (f"{title}. {r['why']}. Seen on {s['bad']} consecutive checks. "
                  f"Scope: this watches counters and conntrack on the router. "
                  f"It cannot see a DoH endpoint that is not on its list, so a "
                  f"clean result here is not proof that no device is using DoH.")
        if r.get("hits"):
            detail += " Observed: " + "; ".join(r["hits"])
        propose(key, detail, action)
        s["last_alert"] = now.isoformat(timespec="seconds")
        say(f"               -> proposal raised")

    save_state(st)
    append(DIAG, {"timestamp": now.isoformat(timespec="seconds"),
                  "results": results})
    if "--json" in sys.argv:
        print(json.dumps({"checked_at": now.isoformat(timespec="seconds"),
                          "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
