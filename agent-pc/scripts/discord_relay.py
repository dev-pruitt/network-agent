#!/usr/bin/env python3
"""Discord approval bridge - replaces the IMAP approval workflow.

WHY THIS REPLACES EMAIL
-----------------------
approval_monitor.py parsed IMAP for "approve-<ID>" strings. Over its entire
operating life it processed 0 approvals against 29 proposals. Email is a poor
approval channel: UID tracking, threading, and free-text parsing all have to
work perfectly, and any one of them silently drops the decision.

Here the decision is a reaction, not text. Reading it is one API call that
returns a list of user IDs. There is nothing to parse and nothing to mis-parse.

SECURITY
--------
- Only reactions from DISCORD_APPROVER_ID count. Anyone else reacting is
  ignored, so a public channel is still safe for approvals.
- This script NEVER executes anything. It only marks proposals approved or
  denied. execute_action.py remains the sole executor and keeps enforcing
  guardrails.toml, cooldowns, and the escalation levels.
- Level 3 proposals are posted for visibility but cannot be approved here;
  they require manual intervention by design.

NETWORK
-------
Forces IPv4. The agent had a broken IPv6 default route that stalled every
outbound connection ~10s. The route is fixed, but pinning to v4 keeps this
path deterministic.
"""
import json
import os
import socket
import time
import urllib.error
import urllib.request

# --- force IPv4 (see module docstring) --------------------------------------
_orig_gai = socket.getaddrinfo
def _gai_v4(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_gai(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _gai_v4

BASE       = os.path.expanduser("~/network-agent")
CONF       = os.path.join(BASE, "config/discord.conf")
PROPOSALS  = os.path.join(BASE, "logs/proposals.jsonl")
APPROVALS  = os.path.join(BASE, "logs/approvals.jsonl")
POSTED     = os.path.join(BASE, "logs/discord_posted.json")

API        = "https://discord.com/api/v10"
MAX_POST   = 4          # per run, to stay well inside rate limits
OK, NO     = "✅", "❌"     # white_check_mark, x


def load_conf():
    cfg = {}
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip("'\"")
    missing = [k for k in ("DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID",
                           "DISCORD_APPROVER_ID") if not cfg.get(k)]
    if missing:
        raise SystemExit(f"[FATAL] discord.conf missing: {', '.join(missing)}")
    if "PASTE" in cfg["DISCORD_BOT_TOKEN"]:
        raise SystemExit("[FATAL] token placeholder not replaced")
    return cfg


def api(cfg, method, path, body=None, retries=3):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bot " + cfg["DISCORD_BOT_TOKEN"])
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "NetworkAgent (self-hosted, 1.0)")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 429:                       # rate limited
                try:
                    wait = json.loads(e.read()).get("retry_after", 2)
                except Exception:
                    wait = 2
                time.sleep(float(wait) + 0.5)
                continue
            print(f"[ERROR] {method} {path} -> HTTP {e.code}")
            return None
        except Exception as e:
            if attempt == retries - 1:
                print(f"[ERROR] {method} {path} -> {e}")
                return None
            time.sleep(2 * (attempt + 1))
    return None


def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def write_jsonl(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, path)


def load_posted():
    try:
        with open(POSTED) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_posted(d):
    tmp = POSTED + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, POSTED)


def dedupe_pending(proposals):
    """Collapse repeat proposals for the same issue.

    The queue is dominated by repeated latency-degradation reports for the
    same two tunnels. Posting all of them would bury the signal. Keep the
    newest per (anomaly_type, component) and mark the rest superseded, so
    the channel shows current state rather than a backlog.
    """
    newest, superseded = {}, []
    for p in proposals:
        if p.get("status") != "pending":
            continue
        key = (p.get("anomaly_type"), p.get("component"))
        prev = newest.get(key)
        if prev is None or p.get("timestamp", "") > prev.get("timestamp", ""):
            if prev is not None:
                superseded.append(prev)
            newest[key] = p
        else:
            superseded.append(p)
    return list(newest.values()), superseded


SEV_COLOR = {1: 0x639922, 2: 0xBA7517, 3: 0xE24B4A}


def post_proposal(cfg, p):
    sev = int(p.get("severity", 2))
    lvl3 = sev >= 3
    fields = [
        {"name": "Component", "value": str(p.get("component", "?")), "inline": True},
        {"name": "Severity", "value": f"Level {sev}", "inline": True},
        {"name": "Detected", "value": str(p.get("timestamp", "?"))[:19].replace("T", " "), "inline": True},
        {"name": "Recommended action", "value": str(p.get("recommended_action", "?"))[:1000]},
    ]
    footer = ("Level 3 - manual intervention required. Reactions are disabled."
              if lvl3 else f"React {OK} to approve  |  {NO} to deny")
    body = {"embeds": [{
        "title": f"{p.get('anomaly_type', 'anomaly')}  -  {p.get('proposal_id')}",
        "description": str(p.get("details", ""))[:2000],
        "color": SEV_COLOR.get(sev, 0xBA7517),
        "fields": fields,
        "footer": {"text": footer},
    }]}
    msg = api(cfg, "POST", f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages", body)
    if not msg:
        return None
    if not lvl3:
        for emoji in (OK, NO):
            api(cfg, "PUT",
                f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages/{msg['id']}"
                f"/reactions/{urllib.request.quote(emoji)}/@me")
            time.sleep(0.3)
    return msg["id"]


def check_reaction(cfg, message_id, emoji):
    """Return True if the configured approver reacted with this emoji."""
    users = api(cfg, "GET",
                f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages/{message_id}"
                f"/reactions/{urllib.request.quote(emoji)}")
    if not users:
        return False
    return any(u.get("id") == cfg["DISCORD_APPROVER_ID"] for u in users)


def main():
    cfg = load_conf()
    proposals = read_jsonl(PROPOSALS)
    if not proposals:
        print("[INFO] no proposals")
        return

    posted = load_posted()
    by_id = {}
    for p in proposals:
        by_id.setdefault(p.get("proposal_id"), []).append(p)

    # 1. Resolve decisions on anything already posted.
    decided = 0
    for pid, mid in list(posted.items()):
        rows = by_id.get(pid) or []
        if not rows or all(r.get("status") != "pending" for r in rows):
            continue
        verdict = None
        if check_reaction(cfg, mid, OK):
            verdict = "approved"
        elif check_reaction(cfg, mid, NO):
            verdict = "denied"
        if not verdict:
            continue
        for r in rows:
            r["status"] = verdict
            r["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            r["decided_via"] = "discord"
        with open(APPROVALS, "a") as f:
            f.write(json.dumps({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "proposal_id": pid, "decision": verdict,
                "channel": "discord", "message_id": mid,
                "approver": cfg["DISCORD_APPROVER_ID"],
            }) + "\n")
        decided += 1
        print(f"[DECISION] {pid} -> {verdict}")

    # 2. Collapse the backlog so the channel shows current state.
    current, superseded = dedupe_pending(proposals)
    for p in superseded:
        p["status"] = "superseded"
    if superseded:
        print(f"[INFO] marked {len(superseded)} superseded")

    # 3. Post what is still pending and not yet in the channel.
    posted_now = 0
    for p in sorted(current, key=lambda x: x.get("timestamp", "")):
        pid = p.get("proposal_id")
        if pid in posted or p.get("status") != "pending":
            continue
        if posted_now >= MAX_POST:
            break
        mid = post_proposal(cfg, p)
        if mid:
            posted[pid] = mid
            posted_now += 1
            print(f"[POSTED] {pid}")
            time.sleep(0.5)

    write_jsonl(PROPOSALS, proposals)
    save_posted(posted)

    remaining = sum(1 for p in proposals if p.get("status") == "pending"
                    and p.get("proposal_id") not in posted)
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] "
          f"decided={decided} posted={posted_now} awaiting_post={remaining}")


if __name__ == "__main__":
    main()
