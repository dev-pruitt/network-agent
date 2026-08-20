#!/usr/bin/env python3
"""Phase 3: Execute approved remediation actions with guardrails.

2026-07-27 audit fixes:
  - guardrails.toml is now actually PARSED and ENFORCED (was decorative)
  - reads tcl_monitor.jsonl in addition to diagnostics.jsonl (TCL issues
    were previously detected but unreachable by remediation)
  - check_cooldown() scans all recent entries of the matching action_type
    instead of only the last log line (was trivially bypassable)
  - forbidden-action matching restored to the full list from the TOML
  - fail-closed: if guardrails.toml is missing/unparseable, refuse to act
"""
import json, os, subprocess, sys
from datetime import datetime, timedelta

try:
    import tomllib  # py3.11+
except ImportError:
    tomllib = None

BASE            = os.path.expanduser("~/network-agent")
ACTION_LOG      = os.path.join(BASE, "logs/actions.jsonl")
DIAGNOSTICS_LOG = os.path.join(BASE, "logs/diagnostics.jsonl")
TCL_LOG         = os.path.join(BASE, "logs/tcl_monitor.jsonl")
GUARDRAILS      = os.path.join(BASE, "config/guardrails.toml")

# Fallback cooldowns used only if the TOML omits a key.
DEFAULT_COOLDOWNS = {
    "tunnel_restart":   300,
    "log_rotation":     3600,
    "conntrack_flush":  600,
    "lb_reset":         600,
    "wan_recovery":     900,
}


def load_guardrails():
    """Load and enforce guardrails.toml. Fail CLOSED on any problem."""
    if tomllib is None:
        print("[FATAL] tomllib unavailable (need Python 3.11+). Refusing to act.")
        sys.exit(1)
    if not os.path.exists(GUARDRAILS):
        print(f"[FATAL] {GUARDRAILS} missing. Refusing to act.")
        sys.exit(1)
    try:
        with open(GUARDRAILS, "rb") as f:
            cfg = tomllib.load(f)
    except Exception as e:
        print(f"[FATAL] guardrails.toml unparseable ({e}). Refusing to act.")
        sys.exit(1)

    forbidden = cfg.get("execution", {}).get("forbidden_actions", [])
    if not forbidden:
        print("[FATAL] no forbidden_actions defined. Refusing to act.")
        sys.exit(1)

    cooldowns = dict(DEFAULT_COOLDOWNS)
    for k, v in cfg.get("cooldowns", {}).items():
        # keys look like "tunnel_restart_cooldown_sec"
        cooldowns[k.replace("_cooldown_sec", "")] = v

    level1 = cfg.get("rules", {}).get("level1_conditions", [])
    return {"forbidden": forbidden, "cooldowns": cooldowns, "level1": level1}


def check_forbidden(action_desc, command, forbidden):
    """Match against the FULL forbidden list from the TOML.

    Checks both the human description and the literal command string, so a
    playbook cannot smuggle a forbidden operation past a benign description.
    """
    haystack = f"{action_desc} {command}".lower()
    for rule in forbidden:
        # Match on the distinctive words of each rule rather than the whole
        # sentence, so "reboot router without approval" still catches "reboot".
        tokens = [t for t in rule.lower().split()
                  if t not in ("the", "a", "an", "without", "approval", "both", "simultaneously")]
        if tokens and all(t in haystack for t in tokens[:2]):
            return rule
    # Belt-and-braces literal checks that must never pass.
    for literal in ("reboot", "iptables -f", "iptables --flush", "passwd ", "rm -rf /"):
        if literal in haystack:
            return f"literal match: {literal}"
    return None


def check_cooldown(action_type, cooldowns):
    """True if this action_type ran within its cooldown window.

    AUDIT FIX: previously inspected only lines[-1], so alternating action
    types bypassed cooldown entirely. Now scans every entry.
    """
    sec = cooldowns.get(action_type, 0)
    if sec == 0 or not os.path.exists(ACTION_LOG):
        return False
    cutoff = datetime.now() - timedelta(seconds=sec)
    try:
        with open(ACTION_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("action_type") != action_type:
                    continue
                if e.get("synthetic"):        # ignore test-data entries
                    continue
                try:
                    ts = datetime.fromisoformat(e["timestamp"])
                except (KeyError, ValueError):
                    continue
                if ts > cutoff:
                    return True
    except OSError:
        return False
    return False


def execute_ssh(cmd):
    try:
        r = subprocess.run(["ssh", "b3000", cmd], capture_output=True, text=True, timeout=30)
        return {"success": r.returncode == 0, "output": r.stdout.strip(),
                "error": r.stderr.strip() if r.returncode else None}
    except Exception as e:
        return {"success": False, "output": None, "error": str(e)}


def execute_local(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return {"success": r.returncode == 0, "output": r.stdout.strip(),
                "error": r.stderr.strip() if r.returncode else None}
    except Exception as e:
        return {"success": False, "output": None, "error": str(e)}


def build_playbooks(issue):
    p = issue.get("parameters", {}) or {}
    tunnel = p.get("tunnel_name", "unknown")
    ip     = p.get("ip", "")
    return {
        "PB-WG-001":  ("tunnel_restart",  "ssh",
                       f"wg-quick down {tunnel} && wg-quick up {tunnel}"),
        "PB-LB-001":  ("conntrack_flush", "ssh",
                       "conntrack -F && /usr/bin/wg-lb-fast"),
        "PB-LOG-001": ("log_rotation",    "local",
                       f"find {BASE}/logs -name '*.jsonl.gz' -mtime +30 -exec rm -f {{}} \\;"),
        # AUDIT FIX: TCL conntrack flush is Level 1 and was previously
        # unreachable because the executor never read tcl_monitor.jsonl.
        "PB-TCL-002": ("conntrack_flush", "ssh",
                       f"conntrack -D -s {ip}" if ip else ""),
    }


def execute_remediation(issue, rails):
    playbook = issue.get("playbook_id")
    pb = build_playbooks(issue).get(playbook)
    if not pb:
        return {"success": False, "reason": f"UNKNOWN_PLAYBOOK:{playbook}"}

    action_type, target, cmd = pb
    if not cmd:
        return {"success": False, "reason": "EMPTY_COMMAND"}

    desc = f"Remediate {issue.get('issue_type')} via {playbook}"
    hit = check_forbidden(desc, cmd, rails["forbidden"])
    if hit:
        print(f"[FORBIDDEN] {playbook} blocked by rule: {hit}")
        return {"success": False, "reason": "FORBIDDEN"}

    if check_cooldown(action_type, rails["cooldowns"]):
        return {"success": False, "reason": f"COOLDOWN({rails['cooldowns'].get(action_type)}s)"}

    res = execute_ssh(cmd) if target == "ssh" else execute_local(cmd)

    entry = {
        "timestamp":   datetime.now().isoformat(),
        "playbook_id": playbook,
        "action_type": action_type,
        "issue_type":  issue.get("issue_type"),
        "command":     cmd,
        "target":      target,
        "success":     res["success"],
        "error":       res.get("error"),
        "rationale":   issue.get("evidence") or desc,
    }
    with open(ACTION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    if not res["success"]:
        res["reason"] = "EXECUTION_ERROR"
    return res


def _tail_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            lines = [l for l in f if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except (OSError, json.JSONDecodeError):
        return None


def collect_issues():
    """Gather issues from BOTH diagnostic sources.

    AUDIT FIX: tcl_monitor.jsonl was never read, so HomeKit issues were
    detected, classified, and then dropped on the floor.
    """
    level1, escalated = [], []
    for path, src in ((DIAGNOSTICS_LOG, "diagnostics"), (TCL_LOG, "tcl_monitor")):
        rec = _tail_json(path)
        if not rec:
            continue
        for issue in rec.get("issues", []) or []:
            issue["_source"] = src
            lvl = issue.get("escalation_level", rec.get("escalation_level", 0))
            (level1 if lvl == 1 else escalated).append((lvl, issue))
    return [i for _, i in level1], escalated


def main():
    rails = load_guardrails()
    level1, escalated = collect_issues()

    if escalated:
        for lvl, issue in escalated:
            print(f"[ESCALATED] L{lvl} {issue.get('playbook_id')} "
                  f"({issue.get('_source')}): {issue.get('evidence')} "
                  f"-- requires approval, not executing")

    if not level1:
        print("[INFO] No Level 1 issues pending")
        return

    print(f"[INFO] Processing {len(level1)} Level 1 issue(s)")
    for issue in level1:
        print(f"[EXEC] {issue.get('playbook_id')}: {issue.get('evidence')}")
        res = execute_remediation(issue, rails)
        if res.get("success"):
            print("[OK] Executed successfully")
        else:
            print(f"[BLOCKED] {res.get('reason', res.get('error', 'UNKNOWN'))}")


if __name__ == "__main__":
    main()
