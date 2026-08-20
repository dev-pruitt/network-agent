#!/bin/bash
# Add read-only iptables to the agent's scoped sudoers rule.
#
# The watchdog needs to see whether Tailscale's ts-forward / ts-postrouting
# chains still exist. Without it the forwarding check reports "cannot read
# iptables" and silently verifies nothing - which is worse than not having
# the check, because it looks like it passed.
#
# -S is list-only. It cannot modify a rule. Validated with visudo -c before
# install, since a malformed sudoers file locks you out of sudo entirely.
set -euo pipefail

USER_="${SUDO_USER:-agent}"
SUDOERS=/etc/sudoers.d/network-agent-tailscale
IPT=$(command -v iptables)
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT

cp "$SUDOERS" "$TMP"
grep -q "$IPT -S" "$TMP" && { echo "already present"; exit 0; }
echo "$USER_ ALL=(root) NOPASSWD: $IPT -S" >> "$TMP"

if visudo -c -f "$TMP" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$TMP" "$SUDOERS"
    echo "  VALID - installed"
    sed 's/^/    /' "$SUDOERS"
else
    echo "  INVALID - nothing changed"; visudo -c -f "$TMP" || true; exit 1
fi

echo
sudo -u "$USER_" sudo -n "$IPT" -S >/dev/null 2>&1 \
    && echo "  verified: $USER_ can read iptables" \
    || echo "  verification FAILED"
