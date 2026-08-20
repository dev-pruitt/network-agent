#!/usr/bin/env python3
"""Prove each tunnel actually carries LAN traffic. Not that it exists.

WHY THIS EXISTS
  wg2 was blocked from the LAN for the entire life of this setup. The load
  balancer sent 30% of new connections into it and the firewall rejected
  every one, because a wg2 ZONE had been created without the lan->wg2
  FORWARDING rule to go with it.

  Nothing noticed, because every existing check looked at the wrong thing:
  the tunnel handshook, the interface was up, the zone was present. All true,
  all irrelevant. None of them answered "can a packet get from the LAN into
  this tunnel", which was the only question that mattered.

  It surfaced because a git push failed often enough to be annoying.

WHAT THIS CHECKS
  Opens real TCP connections from the LAN side to a destination statically
  pinned to each tunnel, and compares the tunnels against EACH OTHER. Absolute
  thresholds cannot tell "this tunnel is broken" from "the internet is having
  a bad minute"; divergence between peers can.

  It must run on the agent, not the router. Router-originated traffic takes
  the OUTPUT path; LAN traffic takes FORWARD, and they hit different rules.
  That difference is exactly what hid the fault - the router could reach
  everything fine.

THE PART THAT MAKES IT DIAGNOSTIC
  On failure it reads the router's FORWARD-reject counter delta. That
  separates two faults that look identical from the LAN:

      rejects climbed  -> the firewall is refusing it   (config: a missing
                          forwarding rule, a zone policy)
      rejects flat     -> packets left and nothing came back  (transport: a
                          dead peer, a bad endpoint, a routing hole)

  Guessing between those two cost several wrong hypotheses when this was
  diagnosed by hand.

PATH ISOLATION - why the probe host is exempt from the load balancer
  Destination pinning alone does NOT isolate a tunnel. The load balancer sets
  a connmark, and the ip rule matching that mark is evaluated BEFORE the rule
  that consults the main table's per-destination routes. So the mark wins: a
  probe aimed at a wgclient-pinned address still lands on wg2 whenever the
  balancer says so.

  Consequence, measured: breaking wg2 dropped the WGCLIENT probe to 6/8 and
  then 3/8, because 30% of those connections were being sprayed into the
  broken tunnel. Every tunnel's number moved together, so nothing could be
  attributed to anything.

  Fix: a RETURN for this host at the top of the load-balancer chain. Its
  traffic is never sprayed, so a pinned destination now means exactly one
  tunnel and each measurement is about the tunnel it names.

  The cost is stated honestly: this host no longer exercises the balancer, so
  the probe measures TUNNEL health, not what a balanced client experiences.
  The balancer is covered separately by the FORWARD-reject delta below.

DESIGN RULES IT FOLLOWS, all learned the hard way in this project
  - Discover tunnels and probe targets; never hardcode. A hardcoded device
    list is the single most repeated bug here.
  - A probe failure is not a condition. If the router is unreachable or a
    tunnel has no pinned target, that is "cannot observe" - recorded, not
    alerted.
  - Corroborate before asserting: N consecutive bad rounds, not one.
  - Cooldown, so a persistent fault is a steady note rather than a loop.
  - State scope honestly: this proves LAN->tunnel reachability for one
    destination. It does not prove the tunnel is fast, or that every
    destination works.

Usage:  tunnel_reachability_probe.py            probe and report
        tunnel_reachability_probe.py --json     machine readable
        tunnel_reachability_probe.py --quiet    cron mode, only on change
"""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta

BASE = os.path.expanduser("~/network-agent")
LOGS = os.path.join(BASE, "logs")
PROPOSALS = os.path.join(LOGS, "proposals.jsonl")
NOTICES = os.path.join(LOGS, "notices.jsonl")
STATE = os.path.join(LOGS, "tunnel_probe_state.json")
DIAG = os.path.join(LOGS, "tunnel_probe.jsonl")

ROUTER = "b3000"
SSH = ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", ROUTER]

ATTEMPTS = 8            # connections per tunnel per round
PROBE_PORT = 853        # DoT: open on the resolvers already pinned per tunnel
CONNECT_TIMEOUT = 4

# PARTIAL degradation is only meaningful relative to a healthy peer - a tunnel
# at 70% while its peer is at 75% is a bad minute on the internet, not a
# broken tunnel. TOTAL failure needs no peer: a tunnel carrying nothing is
# broken whatever the others are doing.
#
# That distinction is not academic. The first version of this file required a
# healthy peer in all cases, and when the fault was induced it reported
# "all tunnels reachable" while one sat at 0/8 - because breaking one tunnel
# dragged the other down too (see PATH ISOLATION below), so no peer ever
# cleared the healthy bar. A check that cannot detect the thing it was built
# for is the most common defect in this project.
IMPAIRED_BELOW = 0.60
HEALTHY_ABOVE = 0.90

CONSECUTIVE_BAD = 2     # rounds before this becomes a proposal
COOLDOWN = timedelta(hours=6)


# ---------------------------------------------------------------------------
# discovery - nothing here is hardcoded on purpose
# ---------------------------------------------------------------------------
def router(cmd, timeout=25):
    """Run a command on the router. Returns (stdout, None) or (None, reason)."""
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


def discover_tunnels():
    """WireGuard interfaces currently configured on the router."""
    out, err = router("wg show interfaces")
    if err:
        return [], err
    return out.split(), None


def discover_targets(tunnels):
    """Find a destination statically pinned to each tunnel.

    The router pins specific resolver addresses per tunnel with routes like
        9.9.9.9 dev wgclient scope link
    which is what lets a LAN-side probe choose its path by destination rather
    than hoping a hash lands where it wants.

    Derived every run. If the pins are re-pointed by a rotation, this follows
    them - which is precisely what the endpoint-pin bug in this project failed
    to do.
    """
    out, err = router("ip route show table main")
    if err:
        return {}, err
    targets = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "dev" and parts[2] in tunnels:
            dst = parts[0]
            if dst == "default" or "/" in dst:
                continue
            targets.setdefault(parts[2], dst)
    return targets, None


def forward_rejects():
    """fw3 default FORWARD reject counter. None means we could not read it."""
    out, err = router(
        "iptables -L FORWARD -v -n -x 2>/dev/null | "
        "awk '/\\/\\* !fw3 \\*\\// && /reject/ {print $1; exit}'")
    if err or not out.strip():
        return None
    try:
        return int(out.strip().split()[0])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------
def probe(ip, attempts=ATTEMPTS):
    """TCP connects from THIS host (the LAN side). Returns (ok, refused, other)."""
    ok = refused = other = 0
    for _ in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect((ip, PROBE_PORT))
            ok += 1
        except ConnectionRefusedError:
            refused += 1
        except Exception:
            other += 1
        finally:
            s.close()
    return ok, refused, other


# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(st, f, indent=2)
    except OSError:
        pass


def append(path, rec):
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def notice(event_id, title, message, kind="info"):
    append(NOTICES, {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "kind": kind, "event_id": event_id, "title": title,
        "message": message, "source": "tunnel_probe",
    })


def propose(tunnel, detail, action):
    pid = f"T{datetime.now():%m%d%H%M%S}-tunnel_{tunnel}"
    append(PROPOSALS, {
        "proposal_id": pid,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anomaly_type": f"tunnel_unreachable_{tunnel}",
        "component": "router",
        "severity": 2,
        "details": detail,
        "recommended_action": action,
        "playbook_id": "PB-TUN-001",
        "source": "tunnel_probe",
        "status": "pending",
    })
    return pid


# ---------------------------------------------------------------------------
def main():
    as_json = "--json" in sys.argv
    quiet = "--quiet" in sys.argv
    st = load_state()
    now = datetime.now()

    def say(*a):
        if not quiet:
            print(*a)

    tunnels, err = discover_tunnels()
    if err or not tunnels:
        # Cannot observe is not a fault. Say so, do not raise a condition.
        notice("tunnel_probe_blind", "tunnel probe could not run",
               f"router unreachable or no tunnels configured: {err or 'none found'}")
        say(f"[tunnel-probe] cannot observe: {err or 'no tunnels'}")
        return 0

    targets, err = discover_targets(tunnels)
    if err:
        notice("tunnel_probe_blind", "tunnel probe could not read routes",
               f"could not read the router routing table: {err}")
        say(f"[tunnel-probe] cannot observe: {err}")
        return 0

    unpinned = [t for t in tunnels if t not in targets]
    if unpinned:
        # Honest about scope: an unpinned tunnel is not tested, and silence
        # about it would read as a pass.
        notice("tunnel_probe_unpinned", "tunnel not covered by the probe",
               f"no statically pinned destination for: {', '.join(unpinned)} - "
               f"these tunnels are NOT being verified")

    rej_before = forward_rejects()
    results = {}
    for t in sorted(targets):
        ip = targets[t]
        ok, refused, other = probe(ip)
        results[t] = {"target": ip, "ok": ok, "refused": refused,
                      "other": other, "rate": round(ok / ATTEMPTS, 3)}
        say(f"  {t:<10} -> {ip:<16} {ok}/{ATTEMPTS} ok"
            f"{'  refused=' + str(refused) if refused else ''}"
            f"{'  failed=' + str(other) if other else ''}")
    rej_after = forward_rejects()

    rej_delta = None
    if rej_before is not None and rej_after is not None:
        rej_delta = rej_after - rej_before

    append(DIAG, {"timestamp": now.isoformat(timespec="seconds"),
                  "results": results, "forward_reject_delta": rej_delta})

    # ---- impairment ---------------------------------------------------------
    # Two independent tests, because they answer different questions.
    rates = {t: r["rate"] for t, r in results.items()}
    best = max(rates.values()) if rates else 0

    dead = [t for t, v in rates.items() if v == 0.0]
    diverged = [t for t, v in rates.items()
                if v < IMPAIRED_BELOW and best >= HEALTHY_ABOVE and v > 0.0]
    impaired = sorted(set(dead) | set(diverged))

    if not impaired and rates and best < HEALTHY_ABOVE:
        # Everything sagging together, nothing at zero. That reads as upstream
        # rather than per-tunnel, and calling it a tunnel fault would send you
        # chasing the wrong thing. Note it; do not raise a condition.
        notice("tunnel_probe_all_degraded", "all tunnels degraded together",
               "no tunnel reached the healthy threshold and none is at zero, "
               "so this looks upstream rather than per-tunnel: "
               + ", ".join(f"{t} {v:.0%}" for t, v in sorted(rates.items())))
        say("  all tunnels degraded together, none at zero - "
            "reads as upstream, not a tunnel fault")

    changed = False
    for t in sorted(rates):
        ts = st.setdefault(t, {"bad_rounds": 0, "last_alert": None})
        if t in impaired:
            ts["bad_rounds"] += 1
        else:
            if ts["bad_rounds"]:
                changed = True
                say(f"  {t}: recovered after {ts['bad_rounds']} bad round(s)")
                notice(f"tunnel_{t}_recovered", f"{t} reachable again",
                       f"{t} back to {rates[t]:.0%} from the LAN side.",
                       kind="recover")
            ts["bad_rounds"] = 0

        if ts["bad_rounds"] < CONSECUTIVE_BAD:
            continue

        last = ts.get("last_alert")
        if last and now - datetime.fromisoformat(last) < COOLDOWN:
            say(f"  {t}: still impaired, within cooldown - not re-raising")
            continue

        # Attribute the failure rather than just reporting it.
        r = results[t]
        if rej_delta and rej_delta > 0:
            cause = (f"The router FORWARD-reject counter rose by {rej_delta} "
                     f"during this probe, so these are being REFUSED BY THE "
                     f"FIREWALL, not lost in transit. Check that a lan->{t} "
                     f"zone forwarding exists and is enabled - a zone can be "
                     f"present and still have no forwarding rule.")
            action = (f"Verify: uci show firewall | grep -i {t}  -- expect both "
                      f"a '{t}=zone' AND a 'lan2{t}=forwarding' with enabled=1. "
                      f"Adding the forwarding rule is a config change and needs "
                      f"your approval.")
        elif r["refused"] > r["other"]:
            cause = ("Connections were actively refused rather than timing "
                     "out, but the router's FORWARD reject counter did not "
                     "move - so something beyond the router is rejecting. "
                     "Likely the tunnel peer or the exit.")
            action = f"Consider rotating {t} to a different peer."
        else:
            cause = ("Connections timed out rather than being refused, and "
                     "the firewall counter did not move - packets left and "
                     "nothing came back. Points at the tunnel transport: a "
                     "dead peer, a stale endpoint, or a routing hole.")
            action = f"Check the handshake age and endpoint for {t}, then rotate it."

        peers = ", ".join(f"{p} {rates[p]:.0%}" for p in sorted(rates) if p != t)
        detail = (f"{t} reached {r['ok']}/{ATTEMPTS} ({rates[t]:.0%}) from the "
                  f"LAN side to {r['target']}, across {ts['bad_rounds']} "
                  f"consecutive rounds, while {peers or 'no peer'}. "
                  f"{cause} "
                  f"Scope: this proves LAN-to-tunnel reachability for one "
                  f"destination on port {PROBE_PORT}. It does not measure "
                  f"throughput or test other destinations.")
        pid = propose(t, detail, action)
        ts["last_alert"] = now.isoformat(timespec="seconds")
        changed = True
        say(f"  PROPOSAL {pid}: {t} impaired ({rates[t]:.0%})")

    save_state(st)

    if as_json:
        print(json.dumps({"checked_at": now.isoformat(timespec="seconds"),
                          "results": results, "impaired": impaired,
                          "forward_reject_delta": rej_delta,
                          "unpinned": unpinned}, indent=2))
    elif not quiet:
        if impaired:
            print(f"  IMPAIRED: {', '.join(impaired)}")
        else:
            print("  all pinned tunnels reachable from the LAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
