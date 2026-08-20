#!/bin/sh
# Which device is talking DoH to 8.8.8.8?
#
# The DOH_WATCH chain proves it is happening - 7 packets and climbing - but it
# counts by DESTINATION, so it cannot name the culprit. This adds a chain that
# counts by SOURCE for that one destination, waits, and reads it.
#
# Counting rather than sampling, for the same reason as before: a DoH query is
# milliseconds long and conntrack forgets it almost immediately.
set -e
CHAIN=DOH_SRC
TARGET=8.8.8.8

iptables -w -N "$CHAIN" 2>/dev/null || iptables -w -F "$CHAIN"

# One rule per known host. RETURN so nothing is blocked - this is observation,
# not enforcement.
for ip in $(awk '{print $3}' /tmp/dhcp.leases 2>/dev/null | sort -u); do
    iptables -w -A "$CHAIN" -s "$ip" -m comment --comment "dohsrc" -j RETURN
done
# Catch-all for anything without a lease (static addresses).
iptables -w -A "$CHAIN" -m comment --comment "dohsrc-other" -j RETURN

iptables -w -C FORWARD -d "$TARGET" -p tcp --dport 443 -j "$CHAIN" 2>/dev/null \
    || iptables -w -I FORWARD 1 -d "$TARGET" -p tcp --dport 443 -j "$CHAIN"

n=$(iptables -w -L "$CHAIN" -n 2>/dev/null | grep -c dohsrc)
echo "  watching $n source rules for tcp/443 to $TARGET"
echo "  waiting 120s..."
sleep 120

echo
echo "=== sources with traffic ==="
iptables -w -L "$CHAIN" -v -n -x 2>/dev/null | while read -r pkts bytes rest; do
    case "$pkts" in
        ''|*[!0-9]*) continue ;;
    esac
    [ "$pkts" -eq 0 ] && continue
    src=$(echo "$rest" | awk '{print $4}')
    name=$(grep " $src " /tmp/dhcp.leases 2>/dev/null | awk '{print $4}')
    echo "  $pkts packets from $src  ${name:+($name)}"
done
echo "  (nothing listed = no DoH traffic in that window)"

echo
echo "=== destination totals for context ==="
iptables -w -L DOH_WATCH -v -n -x 2>/dev/null \
    | awk '$1+0>0 && /doh-watch/ {print "  " $1 " pkts -> " $9}'
