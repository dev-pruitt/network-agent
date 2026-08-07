#!/usr/bin/env python3
"""Persist the router's syslog to the agent PC.

WHY THIS EXISTS
---------------
On 2026-07-28 the router rebooted after 6.58 days of uptime and the cause
could not be determined: OpenWrt's `logread` is an in-memory ring buffer on
tmpfs, so the reboot destroyed its own evidence. Every future reboot would
be equally unexplainable.

This drains that ring buffer to durable storage on the agent PC before it
can wrap or vanish. Pull-based over the existing SSH channel: no syslog
listener, no inbound port on the agent, no change to the trust direction.

Dedupe strategy: the ring buffer is re-read in full each run and we append
only lines after the last one we have already stored. Matching on the exact
last stored line handles both wrap-around and reboot (after a reboot no
line matches, so the whole new buffer is taken, which is what we want).
"""
import os
import subprocess
from datetime import datetime

BASE     = os.path.expanduser("~/network-agent")
SYSLOG   = os.path.join(BASE, "logs/router_syslog.log")
MARKER   = os.path.join(BASE, "logs/.router_syslog_marker")
MAX_SIZE = 20 * 1024 * 1024          # rotate at 20 MB
KEEP     = 3                          # rotated generations to retain


def ssh(cmd, timeout=25):
    try:
        r = subprocess.run(["ssh", "b3000", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def rotate_if_needed():
    if not os.path.exists(SYSLOG) or os.path.getsize(SYSLOG) < MAX_SIZE:
        return
    oldest = f"{SYSLOG}.{KEEP}"
    if os.path.exists(oldest):
        os.remove(oldest)
    for i in range(KEEP - 1, 0, -1):
        src, dst = f"{SYSLOG}.{i}", f"{SYSLOG}.{i+1}"
        if os.path.exists(src):
            os.rename(src, dst)
    os.rename(SYSLOG, f"{SYSLOG}.1")


def last_stored_line():
    try:
        with open(MARKER) as f:
            return f.read().rstrip("\n")
    except OSError:
        return None


def main():
    buf = ssh("logread")
    if buf is None:
        print("[WARN] router unreachable - nothing captured")
        return

    lines = [l for l in buf.splitlines() if l.strip()]
    if not lines:
        print("[INFO] empty ring buffer")
        return

    marker = last_stored_line()
    new = lines
    rebooted = False

    if marker:
        try:
            # Take everything after the last line we already have.
            idx = len(lines) - 1 - lines[::-1].index(marker)
            new = lines[idx + 1:]
        except ValueError:
            # Marker absent: buffer wrapped, or the router rebooted and this
            # is a fresh buffer. Either way take it all rather than lose it.
            rebooted = True

    if not new:
        print("[INFO] no new log lines")
        return

    rotate_if_needed()
    stamp = datetime.now().isoformat()
    with open(SYSLOG, "a") as f:
        if rebooted:
            f.write(f"\n===== [{stamp}] BUFFER DISCONTINUITY "
                    f"(reboot or wrap) - captured {len(new)} lines =====\n")
        for l in new:
            f.write(l + "\n")

    with open(MARKER, "w") as f:
        f.write(lines[-1])

    print(f"[OK] captured {len(new)} line(s)"
          + ("  [DISCONTINUITY - likely reboot]" if rebooted else ""))


if __name__ == "__main__":
    main()
