#!/usr/bin/env python3
"""Remove the retired router node from the tailnet.

WHY IT MATTERS, beyond tidiness
  b3000-router still advertises the SAME routes as the live subnet router,
  including the LAN subnet. Tailscale elects ONE primary per subnet route.
  While the node is offline it cannot win, but if it ever came back - a
  firmware reflash, someone re-enabling the service - it could take the route
  and silently break remote access. A duplicate advertiser is a latent
  failover to a host that no longer forwards anything.

SAFETY ORDER
  Verify the live node actually holds the route BEFORE removing anything.
  Removing the standby first and discovering the primary was wrong is the
  wrong order to find that out.

Reversible: the device can re-authenticate and rejoin. This removes the
authorisation, not the machine.

Usage:  remove_stale_node.py --check        show what would happen
        remove_stale_node.py --remove       do it
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.path.expanduser("~/network-agent")
CONF = os.path.join(BASE, "config/tailscale.conf")
API = "https://api.tailscale.com/api/v2"

STALE_NAME = "b3000-router"
LIVE_NAME = "agent-pc"
CRITICAL_ROUTE = "192.168.1.0/24"


def creds():
    key = tailnet = None
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k == "api_key":
                key = v
            elif k == "tailnet":
                tailnet = v
    return key, (tailnet or "-")


def api(path, key, method="GET"):
    req = urllib.request.Request(f"{API}{path}", method=method,
                                 headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read()
            return (json.loads(body) if body else {}), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} on {path}"      # never echo the header
    except Exception as e:
        return None, f"{type(e).__name__} on {path}"


def main():
    do_remove = "--remove" in sys.argv
    key, tailnet = creds()
    if not key:
        sys.exit(f"FATAL: no api_key in {CONF}")

    data, err = api(f"/tailnet/{tailnet}/devices?fields=all", key)
    if err:
        sys.exit(f"FATAL: {err}")

    devices = {d.get("hostname"): d for d in data.get("devices", [])}
    stale = devices.get(STALE_NAME)
    live = devices.get(LIVE_NAME)

    if not stale:
        print(f"  {STALE_NAME} not in the tailnet - nothing to do")
        return 0
    if not live:
        sys.exit(f"FATAL: {LIVE_NAME} not found. Refusing to remove anything.")

    print("=== current state ===")
    for name, d in ((LIVE_NAME, live), (STALE_NAME, stale)):
        print(f"  {name:14} id={d.get('id')}  last_seen={d.get('lastSeen')}")
        print(f"  {'':14} enabled_routes={d.get('enabledRoutes') or []}")

    # --- the pre-check that has to pass first -------------------------------
    print()
    print("=== safety check ===")
    live_routes = live.get("enabledRoutes") or []
    if CRITICAL_ROUTE not in live_routes:
        print(f"  FAIL: {LIVE_NAME} does not have {CRITICAL_ROUTE} approved.")
        print(f"        Removing {STALE_NAME} could leave the LAN unreachable.")
        print(f"        Approve the route on {LIVE_NAME} first.")
        return 1
    print(f"  OK: {LIVE_NAME} has {CRITICAL_ROUTE} approved")

    if stale.get("online"):
        print(f"  WARNING: {STALE_NAME} reports ONLINE. Expected it to be "
              f"stopped. Not removing - check why it is running.")
        return 1
    print(f"  OK: {STALE_NAME} is offline")

    if not do_remove:
        print()
        print(f"  --check only. Re-run with --remove to delete {STALE_NAME}.")
        return 0

    print()
    print("=== removing ===")
    _, err = api(f"/device/{stale.get('id')}", key, method="DELETE")
    if err:
        print(f"  FAILED: {err}")
        return 1
    print(f"  {STALE_NAME} removed")

    # Verify rather than trust the status code.
    data, err = api(f"/tailnet/{tailnet}/devices?fields=all", key)
    if err:
        print(f"  could not verify: {err}")
        return 1
    names = [d.get("hostname") for d in data.get("devices", [])]
    print(f"  tailnet now: {', '.join(sorted(n for n in names if n))}")
    if STALE_NAME in names:
        print("  VERIFY FAILED: still present")
        return 1
    print("  verified: gone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
