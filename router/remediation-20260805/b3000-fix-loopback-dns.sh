#!/bin/sh
# ============================================================================
# DNS_LEAK: stop dropping the router's own loopback DNS - 2026-08-07
#
# THE BUG
#   /etc/resolv.conf on the router is "nameserver 127.0.0.1" - the standard
#   OpenWrt arrangement, pointing at local dnsmasq. But DNS_LEAK only RETURNs
#   for 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16. 127.0.0.0/8 is not in
#   that list, so every query the router makes to its own resolver falls
#   through to the catch-all and is DROPPED.
#
#   Proven: one `curl https://example.com` from the router moved
#   DNS_LEAK_LOG's udp counter 3185 -> 3189. The same dnsmasq answers
#   correctly when queried at 192.168.1.1, which IS inside 192.168.0.0/16.
#
#   So the router has had no working name resolution. LAN clients were never
#   affected - they query 192.168.1.1 - which is why this went unseen. It is
#   also the real cause of the "nslookup: write to '127.0.0.1': Operation not
#   permitted" error from Aug 2, which was written off as a BusyBox quirk. It
#   was not; the packets were being dropped.
#
#   Consequences: tailscaled cannot reach controlplane.tailscale.com, ddns
#   cannot update, opkg cannot fetch, and the router's own dropped queries
#   have been inflating the very leak counter meant to detect real leaks.
#
#   DNS to your own loopback is not a privacy leak by any definition.
#
# THE CARE REQUIRED
#   Adding 127.0.0.0/8 adds two rules (udp + tcp), so DNS_LEAK goes 12 -> 14
#   and the four WAN-egress counters the monitor reads shift from fields
#   9-12 to 11-14. leak-watch-monitor gates on the exact rule count and reads
#   by position, so both files must change together - otherwise the shape
#   gate fails every cycle and detection goes blind, which is precisely the
#   failure mode fixed earlier today.
#
# Idempotent. Verifies the chain, the monitor, and real DNS before finishing.
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-loopback-dns.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
INST=/usr/bin/leak-watch-install
MON=/usr/bin/leak-watch-monitor
echo "### loopback DNS fix  $TS"

for f in "$INST" "$MON"; do
    [ -f "$f" ] || { echo "ABORT: $f missing"; exit 1; }
    cp "$f" "$f.bak-loopback-$TS"
done
echo "backups: *.bak-loopback-$TS"

if grep -q '127.0.0.0/8' "$INST"; then
    echo "already patched - nothing to do"
    exit 0
fi

echo
echo "=== before ==="
echo "  DNS_LEAK rules   : $(iptables -w -L DNS_LEAK -v -n -x 2>/dev/null | awk 'NR>=3 && NF>0' | wc -l)"
echo "  monitor expects  : $(grep -o 'expected 12' "$MON" | head -1)"
echo "  monitor reads    : $(grep -m1 '^D_W1_U=' "$MON")"

# --- 1. installer: add loopback to the private-destination list -------------
sed -i 's|^for _n in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do|for _n in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do|' "$INST"
sed -i 's|# 1-6: private destinations are not a privacy leak|# 1-8: private + loopback destinations are not a privacy leak.\n# 127.0.0.0/8 matters: resolv.conf points at 127.0.0.1, so without it the\n# router cannot resolve anything and its own queries inflate the counter.|' "$INST"
sed -i 's|#   DNS_LEAK    = 12 rules  (6 private-RETURN + 2 LOG + 4 counters)|#   DNS_LEAK    = 14 rules  (8 private/loopback-RETURN + 2 LOG + 4 counters)|' "$INST"
sed -i 's|# 7-8: log whatever survives|# 9-10: log whatever survives|' "$INST"
sed -i 's|# 9-12: the counters the monitor reads|# 11-14: the counters the monitor reads|' "$INST"
echo "  installer patched"

# --- 2. monitor: shape gate 12 -> 14, field offsets 9-12 -> 11-14 -----------
sed -i 's|expected 12|expected 14|g' "$MON"
sed -i 's|!= "12" |!= "14" |g' "$MON"
sed -i 's|"$DNS_COUNTS")" -eq 12 |"$DNS_COUNTS")" -eq 14 |' "$MON"
sed -i 's|^D_W1_U=${9}; D_W1_T=${10}; D_W2_U=${11}; D_W2_T=${12}$|D_W1_U=${11}; D_W1_T=${12}; D_W2_U=${13}; D_W2_T=${14}|' "$MON"
echo "  monitor patched"

echo
echo "=== syntax ==="
for f in "$INST" "$MON"; do
    if sh -n "$f"; then echo "  OK $(basename $f)"
    else echo "  SYNTAX ERROR in $(basename $f) - restoring both"
         cp "$INST.bak-loopback-$TS" "$INST"; cp "$MON.bak-loopback-$TS" "$MON"; exit 1; fi
done

echo
echo "=== rebuilding the chain ==="
"$INST" 2>&1 | sed 's/^/  /'

echo
echo "=== after ==="
N=$(iptables -w -L DNS_LEAK -v -n -x 2>/dev/null | awk 'NR>=3 && NF>0' | wc -l)
echo "  DNS_LEAK rules   : $N  (want 14)"
echo "  monitor reads    : $(grep -m1 '^D_W1_U=' "$MON")"
echo "  loopback RETURN  :"
iptables -w -L DNS_LEAK -v -n -x | awk '$3=="RETURN" && $NF ~ /^127\./ {print "    " $0}'

echo
echo "=== does the router resolve now? ==="
B=$(iptables -w -L DNS_LEAK -v -n -x | awk '$3=="DNS_LEAK_LOG" && $4=="udp" {print $1; exit}')
CODE=$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://example.com 2>/dev/null)
A=$(iptables -w -L DNS_LEAK -v -n -x | awk '$3=="DNS_LEAK_LOG" && $4=="udp" {print $1; exit}')
echo "  https://example.com     : $CODE   (000 = still broken)"
echo "  drops during that call  : $((A-B))   (0 = loopback DNS now permitted)"

echo
echo "=== monitor cycle, must not go blind ==="
"$MON"
sleep 1
logread | grep leak-watch | tail -2 | sed 's/^/  /'
echo "  (no 'expected'/'torn read' line = shape gate agrees with the new chain)"

echo
echo "### done. rollback: for f in $INST $MON; do cp \$f.bak-loopback-$TS \$f; done && $INST"
