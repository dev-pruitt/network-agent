#!/bin/sh
# ============================================================================
# B3000 remediation - 2026-08-05
#
# Reverses the Aug 2 changes that (a) silently disabled DNS leak detection
# and (b) left duplicate/unguarded firewall rules, then pins wgclient's
# endpoint to WAN1 so it stops floating across both WANs.
#
# Idempotent. Safe to re-run. Backs up every file it touches.
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-remediate.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
echo "### B3000 remediation  $TS"

# ---------------------------------------------------------------------------
# [1/5] Backups
# ---------------------------------------------------------------------------
echo
echo "=== [1/5] Backups ==="
cp /usr/bin/leak-watch-monitor "/usr/bin/leak-watch-monitor.bak-remediate-$TS"
cp /etc/firewall.user          "/etc/firewall.user.bak-remediate-$TS"
echo "saved with suffix .bak-remediate-$TS"

# ---------------------------------------------------------------------------
# [2/5] Repair leak-watch-monitor (restores DNS leak detection)
#
# Aug 2 applied two seds that each independently kill the monitor:
#   NR>=3        -> NR>=4            drops the 1st counter of every chain read
#   DNS_LEAK     -> DNS_LEAK_LOG     reads a 1-rule chain where >=4 is required
# Result: "torn read of LEAK_WATCH, skipping cycle" every 5 min since Aug 2.
# ---------------------------------------------------------------------------
echo
echo "=== [2/5] Repairing leak-watch-monitor ==="
sed -i 's/NR>=4 && NF>=6/NR>=3 \&\& NF>=6/'          /usr/bin/leak-watch-monitor
sed -i 's/read_chain DNS_LEAK_LOG/read_chain DNS_LEAK/' /usr/bin/leak-watch-monitor
echo "read_chain now: $(grep -m1 'iptables -L "\$1"' /usr/bin/leak-watch-monitor)"
echo "DNS source now: $(grep -m1 'DNS_COUNTS=' /usr/bin/leak-watch-monitor)"

# ---------------------------------------------------------------------------
# [3/5] Rebuild firewall.user tail
#
# Removes the 14 unguarded lines appended Aug 2 (4 were literal duplicates,
# none used -w, none had a delete-before-insert guard, so every firewall
# reload stacked 14 more). Replaces them with one idempotent block that:
#   - keeps the DNS force-to-local redirect (needed: several LAN devices
#     have hardcoded public DNS) but scopes it to -i br-lan so it no longer
#     punches guest traffic into the LAN interface
#   - keeps the inbound WAN DNS block on both WANs, deduplicated
#   - drops the redundant FORWARD DROP rules (PREROUTING DNAT already
#     handles them, and they were inserted above the guest Tor/DoH rules)
#   - drops the redundant ip6tables rules (this file already sets
#     ip6tables -P INPUT DROP a few sections above)
# ---------------------------------------------------------------------------
echo
echo "=== [3/5] Rebuilding firewall.user tail ==="
awk '{print} /router-leak-install/{exit}' /etc/firewall.user > /tmp/fw.new
cat >> /tmp/fw.new <<'CLEAN'

# === DNS force-to-local + WAN DNS hardening (remediated 2026-08-05) ===
# Idempotent delete-then-insert, matching the style of the sections above.
for P in udp tcp; do
  iptables -w -t nat -D PREROUTING -i br-lan -p $P --dport 53 ! -d 192.168.1.1 -j DNAT --to-destination 192.168.1.1 2>/dev/null
  iptables -w -t nat -A PREROUTING -i br-lan -p $P --dport 53 ! -d 192.168.1.1 -j DNAT --to-destination 192.168.1.1
  for W in eth1.1 eth1.3; do
    iptables -w -D INPUT -i $W -p $P --dport 53 -j DROP 2>/dev/null
    iptables -w -I INPUT 1 -i $W -p $P --dport 53 -j DROP
  done
done
CLEAN
mv /tmp/fw.new /etc/firewall.user
chmod 755 /etc/firewall.user
echo "firewall.user rebuilt ($(wc -l < /etc/firewall.user) lines)"

# ---------------------------------------------------------------------------
# [4/5] Pin wgclient's endpoint to WAN1
#
# wg2 has a host route pinning its endpoint to eth1.3, so its outer packets
# always leave via WAN2. wgclient has none - the uci route 'wg1pin' still
# targets wg2's endpoint rather than wgclient's. So
# wgclient's outer packets fall onto the ECMP default (eth1.1 weight 10 /
# eth1.3 weight 5) and can switch WANs on any flap, changing the public
# source IP Proton sees. That is the likely driver of the recurring
# wgclient latency spikes and peer failures.
# ---------------------------------------------------------------------------
echo
echo "=== [4/5] Pinning wgclient endpoint to WAN1 ==="
EP=$(wg show wgclient endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)
if [ -n "${EP:-}" ]; then
  echo "wgclient endpoint = $EP"
  uci set network.wg1pin.target="$EP"
  uci set network.wg1pin.interface='wan'
  uci set network.wg1pin.gateway='10.0.0.1'
  uci commit network
  ip route replace "$EP/32" via 10.0.0.1 dev eth1.1 metric 10
  echo "pinned: $(ip route get "$EP" | head -1)"
else
  echo "WARN: could not read wgclient endpoint; skipping pin"
fi

# ---------------------------------------------------------------------------
# [5/5] Apply + verify
# ---------------------------------------------------------------------------
echo
echo "=== [5/5] Applying firewall ==="
/etc/init.d/firewall restart >/dev/null 2>&1
sleep 3

echo
echo "--- rule counts (each should be 2, not climbing) ---"
echo "nat PREROUTING dns DNAT : $(iptables -w -t nat -S PREROUTING | grep -c 'dport 53')"
echo "INPUT wan dns DROP      : $(iptables -w -S INPUT | grep -c 'dport 53 -j DROP')"
echo "FORWARD dns DROP (want 0): $(iptables -w -S FORWARD | grep -c 'dport 53 -j DROP')"

echo
echo "--- leak-watch live test ---"
/usr/bin/leak-watch-monitor
sleep 1
logread | grep leak-watch | tail -3
echo "(no 'torn read' line above = detector is alive again)"

echo
echo "--- WAN state ---"
ip route show | grep -A2 '^default proto static'
echo "WAN1 eth1.1 : $(ip -4 addr show eth1.1 | grep -m1 inet)"
echo "WAN2 eth1.3 : $(ip -4 addr show eth1.3 | grep -m1 inet)"

echo
echo "--- tunnels ---"
wg show wgclient endpoints
wg show wg2 endpoints

echo
echo "### done. rollback: restore *.bak-remediate-$TS and run /etc/init.d/firewall restart"
