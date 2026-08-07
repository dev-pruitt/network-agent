#!/usr/bin/env python3
"""Alert pipeline tick - runs every 5 minutes via the existing systemd timer.

Formerly an IMAP poller that processed 0 approvals against 29 proposals over
its entire operating life. It connected, found messages, matched nothing, and
said so quietly. Reactions replaced free-text parsing, so there is nothing
left to mis-parse.

Each tick does two things, in order:
  1. drain_router_alerts.py  - pull the router's alert spool over the existing
                               SSH channel and turn each alert into a proposal
                               with a playbook, severity, and recommended action
  2. discord_relay.py        - post pending proposals to Discord and read back
                               approve/deny reactions

Kept under the original filename so the existing systemd unit and timer work
unchanged (editing those needs root). The retired IMAP implementation is
preserved as approval_monitor.py.imap-retired.
"""
import os
import runpy
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))

STAGES = [
    ("router alert drain", "drain_router_alerts.py"),
    ("discord relay",      "discord_relay.py"),
]


def main():
    failed = False
    for label, script in STAGES:
        path = os.path.join(HERE, script)
        if not os.path.exists(path):
            print(f"[WARN] {label}: {script} missing, skipping")
            continue
        try:
            sys.argv = [script]
            runpy.run_path(path, run_name="__main__")
        except SystemExit as e:
            # A stage may exit non-zero on config problems. Record it, but
            # never let one stage stop the other - a broken Discord config
            # must not also stop router alerts being captured as proposals.
            if e.code:
                failed = True
                print(f"[ERROR] {label}: exited {e.code}")
        except Exception:
            failed = True
            print(f"[ERROR] {label} raised:")
            traceback.print_exc()

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
