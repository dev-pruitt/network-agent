#!/bin/bash
# ============================================================================
# Tailscale UDP GRO forwarding - apply now and persist across reboots
#
# WHY
#   tailscaled warns: "UDP GRO forwarding is suboptimally configured on
#   enp1s0, UDP forwarding throughput capability will increase with a
#   configuration change." This matters more than usual here - the agent is
#   now the exit node carrying all of the phone's traffic, so every packet
#   from cellular passes through this interface.
#
#   ethtool settings are runtime-only and reset on reboot, so a plain
#   `ethtool -K` would silently stop applying the next time the box restarts.
#   Given the agent already lost power once this week, "silently stops
#   applying" is not hypothetical.
#
# The interface is derived from the default route rather than hardcoded, so
# this keeps working if the NIC is ever renamed or replaced.
#
# Run:  sudo bash setup-gro.sh
# ============================================================================
set -euo pipefail

IFACE=$(ip -o route show default | awk '{print $5; exit}')
[ -n "$IFACE" ] || { echo "ABORT: could not determine default interface"; exit 1; }
echo "### UDP GRO forwarding on ${IFACE}"

echo
echo "=== before ==="
ethtool -k "$IFACE" 2>/dev/null | grep -E 'rx-udp-gro-forwarding|rx-gro-list' | sed 's/^/  /'

echo
echo "=== applying now ==="
ethtool -K "$IFACE" rx-udp-gro-forwarding on rx-gro-list off
echo "  applied"

echo
echo "=== persisting via systemd ==="
cat > /etc/systemd/system/tailscale-gro.service <<'UNIT'
[Unit]
Description=UDP GRO forwarding tuning for Tailscale subnet router / exit node
After=network-online.target
Wants=network-online.target
Before=tailscaled.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Interface derived at runtime so a NIC rename does not silently break this.
ExecStart=/bin/sh -c 'IF=$(ip -o route show default | awk "{print \$5; exit}"); \
  [ -n "$IF" ] && exec /usr/sbin/ethtool -K "$IF" rx-udp-gro-forwarding on rx-gro-list off'

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now tailscale-gro.service
echo "  unit installed and enabled"

echo
echo "=== after ==="
ethtool -k "$IFACE" 2>/dev/null | grep -E 'rx-udp-gro-forwarding|rx-gro-list' | sed 's/^/  /'
echo
systemctl is-enabled tailscale-gro.service | sed 's/^/  enabled: /'
systemctl is-active  tailscale-gro.service | sed 's/^/  active : /'

echo
echo "### done - survives reboot. remove with:"
echo "    sudo systemctl disable --now tailscale-gro.service && sudo rm /etc/systemd/system/tailscale-gro.service"
