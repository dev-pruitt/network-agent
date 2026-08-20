#!/usr/bin/env python3
"""Cron sweep for day_export.py's 30-minute retention (2026-08-19, per agent).

WHY THIS EXISTS SEPARATELY FROM THE ROUTES
  day_export.py already sweeps expired exports on every /export_day,
  /export_status and /export_file request, which covers the person who
  actually built the file. It does nothing for the case that matters more:
  someone builds a full-day export and never comes back to the page. Without
  this, that file just sits in _exports/ - several GB, indefinitely - until
  the next time ANYONE happens to hit an export route. Running this on its
  own schedule means the 30-minute window is real regardless of whether the
  page gets visited again.
"""
import os, sys, time

SCRIPTS = os.path.expanduser("~/network-agent-backup/agent-pc/scripts")
LOG = os.path.expanduser("~/network-agent/logs/export_retention.log")

sys.path.insert(0, SCRIPTS)
import day_export  # noqa: E402


def main():
    quiet = "--quiet" in sys.argv
    removed = day_export.sweep_expired()
    if removed:
        line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] removed: {', '.join(removed)}"
        try:
            with open(LOG, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass
        if not quiet:
            print(line)
    elif not quiet:
        print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] nothing expired")


if __name__ == "__main__":
    main()
