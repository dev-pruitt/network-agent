#!/usr/bin/env python3
"""Execute WireGuard rotations - autonomously for L2, approval-gated otherwise.

AUTONOMY POSTURE (set 2026-08-05, operator decision)
  Autonomous : L2 tunnel_restart on wgclient / wg2 only.
  Gated      : everything else. Non-WG components are never touched here.
  Ceiling    : 300s cooldown, plus AUTO_DAILY_CAP autonomous rotations per
               rolling 24h. Past the cap this stops acting and leaves the
               proposal pending, so discord_relay.py posts it for approval.
               Autonomy degrades to the old behaviour; it never goes dark.

TWO PATHS, EVALUATED IN ORDER
  1. autonomous  - pending L2 proposals for wgclient/wg2, no approval needed
  2. approved    - anything you explicitly approved in Discord

Manual approvals do NOT consume the autonomous budget; the cap counts only
entries written with "autonomous": true.

SAFETY NOTES
  - Only the NEWEST pending proposal per tunnel is acted on. Older pending
    proposals for the same tunnel are marked superseded, not executed. A
    backlog of three wgclient proposals produces one rotation, not three.
  - Proposals older than AUTO_MAX_AGE_SEC are not acted on autonomously; a
    stale proposal describes a condition that may no longer hold.
  - Dry run by default. --execute is required to act. The cron entry passes it.

Run:  execute_wireguard_rotation.py --autonomous --execute
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta

try:
    import tomllib
except ImportError:
    tomllib = None

BASE          = os.path.expanduser("~/network-agent")
PROPOSALS_LOG = os.path.join(BASE, "logs/proposals.jsonl")
APPROVALS_LOG = os.path.join(BASE, "logs/approvals.jsonl")
ACTION_LOG    = os.path.join(BASE, "logs/actions.jsonl")
GUARDRAILS    = os.path.join(BASE, "config/guardrails.toml")

# wg-rotate probes up to MAX_TRY candidates at ~50s each, then may
# re-apply the winner or revert - roughly 250s worst case. A shorter
# timeout here kills the SSH but NOT wg-rotate, which holds a flock
# and finishes anyway, so the rotation succeeds while being recorded
# as a failure. That happened three times overnight on 2026-08-06.
ROTATE_TIMEOUT       = 330
ACTION_TYPE          = "tunnel_restart"
DEFAULT_COOLDOWN_SEC = 300
MAX_APPROVAL_AGE_SEC = 3600     # approval path: ignore approvals older than 1h
AUTO_MAX_AGE_SEC     = 1800     # autonomous path: condition must be recent
AUTO_DAILY_CAP       = 6        # autonomous rotations per rolling 24h
AUTO_ANOMALIES       = ("performance_degradation", "tunnel_down")
VALID_TUNNELS        = ("wgclient", "wg2")
TERMINAL_STATUSES    = ("executed", "failed", "rejected", "expired", "superseded")


# --------------------------------------------------------------------------
# io
# --------------------------------------------------------------------------
def _read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _write_proposals(props):
    tmp = PROPOSALS_LOG + ".tmp"
    with open(tmp, "w") as f:
        for p in props:
            f.write(json.dumps(p) + "\n")
    os.replace(tmp, PROPOSALS_LOG)      # atomic


def load_cooldown():
    if tomllib is None or not os.path.exists(GUARDRAILS):
        return DEFAULT_COOLDOWN_SEC
    try:
        with open(GUARDRAILS, "rb") as f:
            cfg = tomllib.load(f)
        return int(cfg.get("cooldowns", {}).get(
            f"{ACTION_TYPE}_cooldown_sec", DEFAULT_COOLDOWN_SEC))
    except Exception:
        return DEFAULT_COOLDOWN_SEC


def _parse_ts(v):
    try:
        return datetime.fromisoformat(v)
    except (TypeError, ValueError):
        return None


def in_cooldown(cooldown_sec):
    """True if any real rotation ran inside the window."""
    if cooldown_sec <= 0:
        return False, None
    cutoff = datetime.now() - timedelta(seconds=cooldown_sec)
    for e in _read_jsonl(ACTION_LOG):
        if e.get("action_type") != ACTION_TYPE or e.get("synthetic"):
            continue
        ts = _parse_ts(e.get("timestamp"))
        if ts and ts > cutoff:
            return True, ts
    return False, None


def autonomous_count_24h():
    """Autonomous rotations in the last rolling 24h. Manual ones don't count."""
    cutoff = datetime.now() - timedelta(hours=24)
    n = 0
    for e in _read_jsonl(ACTION_LOG):
        if e.get("action_type") != ACTION_TYPE or e.get("synthetic"):
            continue
        if not e.get("autonomous"):
            continue
        # A timed-out or failed attempt must not spend the daily
        # allowance - three timeouts burned half of it overnight.
        if not e.get("success"):
            continue
        ts = _parse_ts(e.get("timestamp"))
        if ts and ts > cutoff:
            n += 1
    return n


def log_action(proposal, cmd, success, error, autonomous):
    entry = {
        "timestamp":   datetime.now().isoformat(),
        "playbook_id": proposal.get("playbook_id", "PB-WG-ROTATE"),
        "action_type": ACTION_TYPE,
        "issue_type":  proposal.get("anomaly_type"),
        "component":   proposal.get("component"),
        "command":     cmd,
        "target":      "ssh",
        "success":     success,
        "error":       error,
        "rationale":   proposal.get("details", ""),
        "proposal_id": proposal.get("proposal_id"),
        "autonomous":  bool(autonomous),
    }
    with open(ACTION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def set_status(props, pid, status, result="", by=None):
    for p in props:
        if p.get("proposal_id") == pid and p.get("status") not in TERMINAL_STATUSES:
            p["status"] = status
            p["executed_at"] = datetime.now().isoformat()
            if result:
                p["execution_result"] = result[:500]
            if by:
                p["executed_by"] = by
            return True
    return False


# --------------------------------------------------------------------------
# action
# --------------------------------------------------------------------------
def current_endpoint(tunnel):
    """Peer IP the tunnel is currently pointed at, or None if unreadable."""
    try:
        r = subprocess.run(["ssh", "b3000", f"wg show {tunnel} endpoints"],
                           capture_output=True, text=True, timeout=20)
        parts = r.stdout.split()
        return parts[1].split(":")[0] if len(parts) > 1 else None
    except Exception:
        return None


def rotate(tunnel):
    """Returns (cmd, status, detail) where status is rotated|skipped|failed.

    wg-rotate exits 0 on three paths that do NOT rotate: its own 6h per-tunnel
    cooldown, the other tunnel being unhealthy, and the WAN gateway failing to
    ping. Exit status alone therefore cannot distinguish "rotated" from
    "declined". Without this check the executor would record a success, mark
    the proposal executed, and spend a slot of the daily budget for a rotation
    that never happened - draining all six slots inside half an hour while the
    underlying condition persisted.

    So we compare the peer endpoint either side of the call. Changed endpoint
    is the only trustworthy evidence a rotation actually occurred.
    """
    before = current_endpoint(tunnel)
    cmd = f"ssh b3000 '/usr/bin/wg-rotate {tunnel} --force'"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=ROTATE_TIMEOUT)
    except Exception as e:
        return cmd, "failed", str(e)

    if r.returncode != 0:
        return cmd, "failed", (r.stderr or r.stdout).strip()

    after = current_endpoint(tunnel)
    if before and after and before == after:
        return cmd, "skipped", (
            f"wg-rotate declined: endpoint unchanged ({before}). "
            f"Its 6h cooldown, peer health, or WAN gate blocked the swap. "
            f"stdout: {r.stdout.strip()[:200]}")
    return cmd, "rotated", f"{before} -> {after}. {r.stdout.strip()[:200]}"


# --------------------------------------------------------------------------
# path 1: autonomous
# --------------------------------------------------------------------------
def run_autonomous(props, cooldown_sec, dry):
    now = datetime.now()
    used = autonomous_count_24h()
    acted = 0

    # newest pending candidate per tunnel
    by_tunnel = {}
    for p in props:
        if p.get("status") != "pending":
            continue
        if p.get("component") not in VALID_TUNNELS:
            continue
        if p.get("anomaly_type") not in AUTO_ANOMALIES:
            continue
        ts = _parse_ts(p.get("timestamp"))
        if not ts:
            continue
        cur = by_tunnel.get(p["component"])
        if cur is None or ts > cur[0]:
            by_tunnel[p["component"]] = (ts, p)

    print(f"  autonomy budget: {used}/{AUTO_DAILY_CAP} used in last 24h")

    for tunnel, (ts, prop) in sorted(by_tunnel.items()):
        pid = prop["proposal_id"]

        # supersede older pending proposals for this same tunnel
        for other in props:
            if (other.get("component") == tunnel
                    and other.get("status") == "pending"
                    and other.get("proposal_id") != pid):
                if not dry:
                    set_status(props, other["proposal_id"], "superseded",
                               f"Superseded by {pid}")
                print(f"  SUPERSEDE {other['proposal_id']}: newer proposal exists")

        age = (now - ts).total_seconds()
        if age > AUTO_MAX_AGE_SEC:
            print(f"  STALE   {pid}: {int(age/60)}m old, condition may have cleared")
            continue

        if used >= AUTO_DAILY_CAP:
            print(f"  CAP     {pid}: daily autonomy cap reached "
                  f"({used}/{AUTO_DAILY_CAP}) - left pending for approval")
            continue

        blocked, last = in_cooldown(cooldown_sec)
        if blocked:
            print(f"  HOLD    {pid}: cooldown active "
                  f"(last {last.isoformat(timespec='seconds')})")
            continue

        if dry:
            print(f"  WOULD   {pid}: autonomously rotate {tunnel}")
            acted += 1
            used += 1
            continue

        cmd, status, result = rotate(tunnel)

        if status == "skipped":
            # Nothing happened. Do not log an action, do not spend budget, and
            # leave the proposal pending so it is retried or escalated later.
            print(f"  DECLINE {pid}: {result[:90]}")
            continue

        ok = status == "rotated"
        log_action(prop, cmd, ok, None if ok else result, autonomous=True)
        set_status(props, pid, "executed" if ok else "failed", result, by="autonomous")
        print(f"  {'AUTO-OK ' if ok else 'AUTO-ERR'}{pid}: rotate {tunnel} - {result[:70]}")
        acted += 1
        used += 1

    return acted


# --------------------------------------------------------------------------
# path 2: explicit approvals
# --------------------------------------------------------------------------
def run_approvals(props, cooldown_sec, max_age, dry):
    now = datetime.now()
    index = {p.get("proposal_id"): p for p in props}
    acted = 0

    approvals = {}
    for a in _read_jsonl(APPROVALS_LOG):
        pid = a.get("proposal_id")
        if pid:
            approvals[pid] = a

    for pid, a in sorted(approvals.items(), key=lambda kv: kv[1].get("timestamp", "")):
        prop = index.get(pid)
        if not prop or prop.get("status") in TERMINAL_STATUSES:
            continue
        if a.get("decision") != "approved":
            print(f"  REJECT  {pid}: denied")
            if not dry:
                set_status(props, pid, "rejected", "Denied by operator")
            continue
        if prop.get("component") not in VALID_TUNNELS:
            print(f"  SKIP    {pid}: component "
                  f"'{prop.get('component')}' is not this script's job")
            continue

        ts = _parse_ts(a.get("timestamp"))
        age = (now - ts).total_seconds() if ts else float("inf")
        if age > max_age:
            print(f"  EXPIRE  {pid}: approved {int(age/3600)}h ago, too old to replay")
            if not dry:
                set_status(props, pid, "expired",
                           f"Approval {int(age)}s exceeded max_age {max_age}s")
            continue

        blocked, last = in_cooldown(cooldown_sec)
        if blocked:
            print(f"  HOLD    {pid}: cooldown active "
                  f"(last {last.isoformat(timespec='seconds')})")
            continue

        if dry:
            print(f"  WOULD   {pid}: rotate {prop['component']} (approved)")
            acted += 1
            continue

        cmd, status, result = rotate(prop["component"])

        if status == "skipped":
            print(f"  DECLINE {pid}: {result[:90]}")
            continue

        ok = status == "rotated"
        log_action(prop, cmd, ok, None if ok else result, autonomous=False)
        set_status(props, pid, "executed" if ok else "failed", result, by="approval")
        print(f"  {'DONE    ' if ok else 'FAILED  '}{pid}: "
              f"rotate {prop['component']} - {result[:70]}")
        acted += 1

    return acted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true",
                    help="actually act; without this the run is a dry run")
    ap.add_argument("--autonomous", action="store_true",
                    help="also act on pending L2 wgclient/wg2 without approval")
    ap.add_argument("--max-age", type=int, default=MAX_APPROVAL_AGE_SEC)
    args = ap.parse_args()
    dry = not args.execute

    props = _read_jsonl(PROPOSALS_LOG)
    cooldown_sec = load_cooldown()
    total = 0

    print(f"[{datetime.now().isoformat(timespec='seconds')}] "
          f"{'DRY RUN' if dry else 'EXECUTE'} | "
          f"cooldown={cooldown_sec}s | cap={AUTO_DAILY_CAP}/24h")

    if args.autonomous:
        total += run_autonomous(props, cooldown_sec, dry)
    total += run_approvals(props, cooldown_sec, args.max_age, dry)

    if not dry:
        _write_proposals(props)

    print(f"  -- {total} action(s) {'identified' if dry else 'performed'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
