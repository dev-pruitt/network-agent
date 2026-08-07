#!/usr/bin/env python3
"""Daily status digest -> Discord (replaces the 7am email).

Everything now lands in one channel: router alerts, proposals, approvals, and
this digest. The iCloud credential is no longer needed by any agent-side path.

The digest is assembled from structured logs, not from the LLM narrative. The
model writes the summary paragraph only; every number here is computed in
Python. A 3B model on CPU is useful for prose and unreliable for arithmetic -
see logs/model_bench.json for the evidence behind that split.
"""
import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

_orig_gai = socket.getaddrinfo
def _gai_v4(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_gai(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _gai_v4

BASE      = os.path.expanduser("~/network-agent")
CONF      = os.path.join(BASE, "config/discord.conf")
API       = "https://discord.com/api/v10"

TELEM     = os.path.join(BASE, "logs/router_telemetry.jsonl")
ANALYSES  = os.path.join(BASE, "logs/analyses.jsonl")
PROPOSALS = os.path.join(BASE, "logs/proposals.jsonl")
ACTIONS   = os.path.join(BASE, "logs/actions.jsonl")
APPROVALS = os.path.join(BASE, "logs/approvals.jsonl")
TCL       = os.path.join(BASE, "logs/tcl_monitor.jsonl")


def load_conf():
    cfg = {}
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip("'\"")
    return cfg


def rows(path, since=None):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since and str(d.get("timestamp", "")) < since:
                continue
            out.append(d)
    return out


def main():
    cfg = load_conf()
    if not cfg.get("DISCORD_BOT_TOKEN") or "PASTE" in cfg["DISCORD_BOT_TOKEN"]:
        raise SystemExit("[FATAL] discord.conf not configured")

    since = (datetime.now() - timedelta(days=1)).isoformat()

    telem     = rows(TELEM, since)
    analyses  = rows(ANALYSES, since)
    proposals = rows(PROPOSALS)
    actions   = rows(ACTIONS, since)
    approvals = rows(APPROVALS, since)
    tcl       = rows(TCL, since)

    latest = telem[-1] if telem else {}
    lb     = str(latest.get("lb_state", "")).strip()
    tunnels = ("both up" if lb == "11" else
               "BOTH DOWN" if lb == "00" else
               "one down" if len(lb) == 2 else "unknown")

    up_h = latest.get("uptime_human", "?")

    # Reboot detection from parsed uptime, not the raw two-value string.
    reboots = 0
    prev = None
    for t in telem:
        u = t.get("uptime_seconds")
        if isinstance(u, (int, float)):
            if prev is not None and u < prev - 60:
                reboots += 1
            prev = u

    pending  = sum(1 for p in proposals if p.get("status") == "pending")
    approved = sum(1 for a in approvals if a.get("decision") == "approved")
    denied   = sum(1 for a in approvals if a.get("decision") == "denied")
    real_actions = [a for a in actions if not a.get("synthetic")]

    tcl_issues = tcl[-1].get("issues", []) if tcl else []

    lat = [t.get("wgclient_latency_ms") for t in telem
           if isinstance(t.get("wgclient_latency_ms"), (int, float))]
    lat2 = [t.get("wg2_latency_ms") for t in telem
            if isinstance(t.get("wg2_latency_ms"), (int, float))]

    def avg(xs):
        return f"{sum(xs)/len(xs):.0f}ms" if xs else "n/a"

    summary = ""
    for a in reversed(analyses):
        if a.get("llm_analysis"):
            summary = str(a["llm_analysis"])[:900]
            break

    healthy = (lb == "11") and not tcl_issues and reboots == 0
    color = 0x639922 if healthy else (0xBA7517 if lb == "11" else 0xE24B4A)

    fields = [
        {"name": "Tunnels",     "value": tunnels,                    "inline": True},
        {"name": "Router up",   "value": str(up_h),                  "inline": True},
        {"name": "Reboots 24h", "value": str(reboots),               "inline": True},
        {"name": "Latency wgclient", "value": avg(lat),              "inline": True},
        {"name": "Latency wg2",      "value": avg(lat2),             "inline": True},
        {"name": "Telemetry samples", "value": str(len(telem)),      "inline": True},
        {"name": "Proposals pending", "value": str(pending),         "inline": True},
        {"name": "Approved / denied", "value": f"{approved} / {denied}", "inline": True},
        {"name": "Actions executed",  "value": str(len(real_actions)),"inline": True},
    ]
    if tcl_issues:
        fields.append({"name": "HomeKit devices",
                       "value": "\n".join("- " + str(i.get("evidence", ""))[:150]
                                          for i in tcl_issues)[:1000]})

    body = {"embeds": [{
        "title": f"Daily digest - {datetime.now().strftime('%A %d %B, %H:%M')}",
        "description": summary or "No analysis available for this period.",
        "color": color,
        "fields": fields,
        "footer": {"text": "Figures computed from logs. Narrative is LLM-written - treat as advisory."},
    }]}

    req = urllib.request.Request(
        f"{API}/channels/{cfg['DISCORD_CHANNEL_ID']}/messages",
        data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization", "Bot " + cfg["DISCORD_BOT_TOKEN"])
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "NetworkAgent (self-hosted, 1.0)")

    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                r.read()
            print(f"[{time.strftime('%Y-%m-%d %H:%M')}] digest posted to Discord")
            return
        except Exception as e:
            if attempt == 3:
                raise SystemExit(f"[ERROR] digest failed: {e}")
            time.sleep(min(300, 30 * (2 ** attempt)))


if __name__ == "__main__":
    main()
