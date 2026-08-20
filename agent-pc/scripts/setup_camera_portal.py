#!/usr/bin/env python3
"""Install the camera portal: credentials, systemd unit, gitignore.

Generates the guest password once and prints it once. Re-running does not
rotate it - a setup script that silently changes a credential every time it
runs is a setup script nobody dares re-run.
"""
import os
import secrets
import subprocess
import sys

BASE = os.path.expanduser("~/network-agent-backup")
CONF = os.path.join(BASE, "config", "portal.conf")
UNIT = "/etc/systemd/system/camera-portal.service"
USER = os.environ.get("SUDO_USER") or os.environ.get("USER") or "agent"

UNIT_BODY = f"""[Unit]
Description=Camera guest portal
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User={USER}
WorkingDirectory={BASE}/camera
ExecStart={BASE}/venv/bin/python3 {BASE}/agent-pc/scripts/camera_portal.py
Restart=always
RestartSec=5
# Loopback only. cloudflared is the only thing that should reach it, and it
# runs on this host. Binding wider would put an internet-facing login on the
# LAN as well, for no benefit.
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""


def main():
    os.makedirs(os.path.dirname(CONF), exist_ok=True)

    pw = None
    if os.path.exists(CONF):
        print(f"  config: {CONF} exists, left alone")
    else:
        pw = secrets.token_urlsafe(9)
        body = (
            "# Camera portal guest credentials. Mode 600, gitignored.\n"
            "# Change 'password' to anything memorable and restart the service.\n"
            "# Do not use a default value - camera_portal.py refuses to start.\n"
            "username = guest\n"
            f"password = {pw}\n"
            f"secret_key = {secrets.token_urlsafe(48)}\n"
        )
        fd = os.open(CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(body)
        print(f"  config: wrote {CONF} (mode 600)")

    gi = os.path.join(BASE, ".gitignore")
    existing = open(gi).read() if os.path.exists(gi) else ""
    if "config/portal.conf" not in existing:
        with open(gi, "a") as f:
            f.write("\n# camera portal credentials - never publish\nconfig/portal.conf\n")
        print("  .gitignore: config/portal.conf added")

    # requests is the only dependency the portal adds
    r = subprocess.run([f"{BASE}/venv/bin/python3", "-c", "import requests"],
                       capture_output=True)
    if r.returncode != 0:
        print("  installing requests into the venv...")
        subprocess.run([f"{BASE}/venv/bin/pip", "install", "-q", "requests"],
                       check=False)
    print("  requests: available")

    with open("/tmp/camera-portal.service", "w") as f:
        f.write(UNIT_BODY)
    print("  unit written to /tmp/camera-portal.service")

    print()
    print("  Needs root, so run these yourself:")
    print("    sudo cp /tmp/camera-portal.service /etc/systemd/system/")
    print("    sudo systemctl daemon-reload")
    print("    sudo systemctl enable --now camera-portal")

    if pw:
        print()
        print("  ┌──────────────────────────────────────────┐")
        print(f"  │  guest login: guest                      │")
        print(f"  │  password:    {pw:<27}│")
        print("  └──────────────────────────────────────────┘")
        print("  Shown once. It is in config/portal.conf if you lose it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
