#!/usr/bin/env python3
"""Poll the Tailscale API for tailnet state.

WHAT TOUCHES THE KEY
  - read_key() opens config/tailscale.conf, takes the api_key line, returns it
  - it is passed as an Authorization header to api.tailscale.com
  - it is never printed, never logged, never written to the telemetry file

  The key is redacted in every error path too: a failed request prints the
  status code and URL, never the header. Verify that yourself before creating
  a key - that is the point of showing you this first.

WHY THIS EXISTS
  Route approvals, exit-node status and key expiry live only in the admin
  console. During this migration that meant reading the console aloud to find
  out whether a subnet route was approved - and one of those readings was
  wrong in a way that cost a round trip (a route showed unapproved when it was
  actually approved but not primary). Polling the API removes the guesswork.

  It also catches the thing most likely to bite later: auth keys and node keys
  EXPIRE. A subnet router whose key silently expires takes the LAN route down
  with it, and nothing on the dashboard would say why.

CONFIG  ~/network-agent/config/tailscale.conf   (gitignored, mode 600)
    api_key = tskey-api-...
    tailnet = -                # "-" means the default tailnet for the key

Run:  tailscale_poll.py            human readable
      tailscale_poll.py --json     machine readable, for the dashboard
"""
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = os.path.expanduser("~/network-agent")
CONF = os.path.join(BASE, "config/tailscale.conf")
OUT = os.path.join(BASE, "logs/tailscale_state.json")
API = "https://api.tailscale.com/api/v2"
TIMEOUT = 20

# A node key expiring is the failure mode that takes the LAN route down
# silently, so warn well before it happens rather than after.
EXPIRY_WARN_DAYS = 14


def read_key():
    """Returns (api_key, tailnet). Never logs or echoes the key."""
    if not os.path.exists(CONF):
        return None, None
    key = tailnet = None
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k == "api_key":
                key = v
            elif k == "tailnet":
                tailnet = v
    return key, (tailnet or "-")


def api_get(path, key):
    req = urllib.request.Request(f"{API}{path}",
                                 headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        # status and path only - the Authorization header is never surfaced
        return None, f"HTTP {e.code} on {path}"
    except Exception as e:
        return None, f"{type(e).__name__} on {path}"


def days_until(ts):
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (d - datetime.now(timezone.utc)).days
    except Exception:
        return None


def collect():
    key, tailnet = read_key()
    if not key:
        return {"ok": False, "error": f"no api_key in {CONF}", "devices": []}

    # ?fields=all is required - without it advertisedRoutes/enabledRoutes are
    # omitted entirely and every device silently reports no routes.
    data, err = api_get(f"/tailnet/{tailnet}/devices?fields=all", key)
    if err:
        return {"ok": False, "error": err, "devices": []}

    devices = []
    for d in data.get("devices", []):
        exp_days = days_until(d.get("expires"))
        devices.append({
            "name": d.get("hostname"),
            "os": d.get("os"),
            "addresses": d.get("addresses", []),
            "online": not d.get("blocksIncomingConnections", False),
            "last_seen": d.get("lastSeen"),
            "update_available": d.get("updateAvailable", False),
            "client_version": d.get("clientVersion"),
            "key_expiry_disabled": d.get("keyExpiryDisabled", False),
            "expires_in_days": exp_days,
            "advertised_routes": (d.get("advertisedRoutes") or []),
            "enabled_routes": (d.get("enabledRoutes") or []),
        })

    warnings = []

    # The API token has the same silent-death property the node keys had:
    # when it expires this poller simply stops reporting, and nothing else
    # would explain the silence. Watch the watcher.
    keys, kerr = api_get(f"/tailnet/{tailnet}/keys", key)
    token_expiry_days = None
    if not kerr:
        for k in (keys or {}).get("keys", []):
            if k.get("keyType") != "api":
                continue
            dleft = days_until(k.get("expires"))
            if dleft is None:
                continue
            if token_expiry_days is None or dleft < token_expiry_days:
                token_expiry_days = dleft
        if token_expiry_days is not None and token_expiry_days <= 21:
            warnings.append(f"API token expires in {token_expiry_days}d - "
                            f"this poller goes silent when it does")

    for d in devices:
        # advertised but never approved - the exact trap from this migration
        pending = set(d["advertised_routes"]) - set(d["enabled_routes"])
        if pending:
            warnings.append(f"{d['name']}: routes advertised but NOT approved: "
                            f"{', '.join(sorted(pending))}")
        if (not d["key_expiry_disabled"] and d["expires_in_days"] is not None
                and d["expires_in_days"] <= EXPIRY_WARN_DAYS):
            warnings.append(f"{d['name']}: node key expires in "
                            f"{d['expires_in_days']}d - the route dies with it")
        if d["update_available"]:
            warnings.append(f"{d['name']}: client update available "
                            f"(running {d['client_version']})")

    return {"ok": True, "checked_at": datetime.now().isoformat(),
            "devices": devices, "warnings": warnings,
            "api_token_expires_in_days": token_expiry_days}


def main():
    state = collect()
    try:
        with open(OUT, "w") as f:
            json.dump(state, f, indent=2)
    except OSError:
        pass

    if "--json" in sys.argv:
        print(json.dumps(state, indent=2))
        return 0 if state["ok"] else 1

    if not state["ok"]:
        print(f"[tailscale] {state['error']}")
        return 1

    print(f"[tailscale] {len(state['devices'])} device(s)")
    for d in state["devices"]:
        addr = (d["addresses"] or ["?"])[0]
        routes = ",".join(d["enabled_routes"]) or "-"
        exp = ("never" if d["key_expiry_disabled"]
               else (f"{d['expires_in_days']}d" if d["expires_in_days"] is not None else "?"))
        print(f"  {d['name']:14} {addr:16} {(d['os'] or ''):8} "
              f"routes={routes:18} expires={exp}")
    for w in state["warnings"]:
        print(f"  [WARN] {w}")
    if not state["warnings"]:
        print("  no warnings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
