#!/usr/bin/env python3
"""Daily digest - now Discord, not email.

Kept under the original filename so the existing systemd unit works
unchanged. Email version preserved as send_email_alert.py.email-retired.
"""
import os, runpy, sys
sys.argv = ["send_daily_digest.py"]
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "send_daily_digest.py"), run_name="__main__")
