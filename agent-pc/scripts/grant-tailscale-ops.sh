#!/bin/bash
# ============================================================================
# Let the network agent repair Tailscale without a password
#
# WHY
#   The watchdog can currently observe but not act:
#     tailscale set     -> Access denied: checkprefs access denied
#     systemctl restart -> Interactive authentication required
#   A watchdog that detects a dead tunnel and cannot restart it is decoration.
#
# WHAT THIS GRANTS - deliberately narrow
#   1. tailscale operator = your user. This is Tailscale's own mechanism for
#      non-root management; it covers `tailscale set` and friends and grants
#      nothing outside Tailscale.
#   2. A sudoers rule for exactly three systemctl verbs on exactly one unit.
#      No wildcards, no shell, no other services.
#
#   It does NOT grant general sudo, and it cannot be used to escalate: the
#   permitted commands take no user-controlled arguments.
#
# SAFETY
#   The sudoers fragment is written to a temp file and validated with
#   `visudo -c` BEFORE being installed. An invalid sudoers file can lock you
#   out of sudo entirely, so it is never written directly.
#
# Run:  sudo bash grant-tailscale-ops.sh
# ============================================================================
set -euo pipefail

TARGET_USER="${SUDO_USER:-agent}"
SUDOERS=/etc/sudoers.d/network-agent-tailscale
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "### granting tailscale repair rights to: $TARGET_USER"

echo
echo "=== 1/2 tailscale operator ==="
tailscale set --operator="$TARGET_USER"
echo "  operator set - '$TARGET_USER' can now run tailscale set/up/down"

echo
echo "=== 2/2 scoped sudoers rule ==="
SYSTEMCTL=$(command -v systemctl)
cat > "$TMP" <<EOF
# Installed by grant-tailscale-ops.sh for the network agent's Tailscale
# watchdog. Scope: three verbs, one unit, no wildcards, no arguments the
# caller controls.
$TARGET_USER ALL=(root) NOPASSWD: $SYSTEMCTL restart tailscaled
$TARGET_USER ALL=(root) NOPASSWD: $SYSTEMCTL start tailscaled
$TARGET_USER ALL=(root) NOPASSWD: $SYSTEMCTL is-active tailscaled
EOF

echo "  proposed:"
sed 's/^/    /' "$TMP"

echo
echo "  validating with visudo -c ..."
if visudo -c -f "$TMP" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$TMP" "$SUDOERS"
    echo "  VALID - installed to $SUDOERS"
else
    echo "  INVALID - refusing to install. Nothing changed."
    visudo -c -f "$TMP" || true
    exit 1
fi

echo
echo "=== verifying as $TARGET_USER ==="
sudo -u "$TARGET_USER" tailscale debug prefs >/dev/null 2>&1 \
    && echo "  tailscale read : OK" || echo "  tailscale read : FAILED"
sudo -u "$TARGET_USER" sudo -n "$SYSTEMCTL" is-active tailscaled >/dev/null 2>&1 \
    && echo "  systemctl      : OK (passwordless, scoped)" \
    || echo "  systemctl      : FAILED"

echo
echo "### done - tell Claude and it will run the watchdog and schedule it"
