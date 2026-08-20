#!/bin/sh
# Watch the August lock at 192.168.1.214 while it re-establishes after a
# power cycle - the exact moment the operator reports it hanging.
#
# Identified by correlation, not guesswork: its DHCP lease renewed ~2 minutes
# after the batteries were pulled and replaced, and nothing else on the
# network renewed in that window.
#
# What each observation would mean:
#   connects to :443 or :8883 and stays  -> cloud session fine
#   repeated SYNs to the same address    -> being dropped, not refused; that
#                                            is the multi-minute stall
#   AAAA lookups then IPv6 attempts      -> the half-present IPv6 path
#   DNS to something other than the router -> resolving outside policy
LOCK=192.168.1.214

echo "=== identity ==="
grep " $LOCK " /tmp/dhcp.leases 2>/dev/null | sed 's/^/  /'
ip neigh show "$LOCK" 2>/dev/null | sed 's/^/  /'
iwinfo wlan0 assoclist 2>/dev/null | grep -iA2 "78:9C:85" | sed 's/^/  /'

echo
echo "=== give it a name so it stops showing as '*' ==="
if ! uci show dhcp 2>/dev/null | grep -qi "aa:bb:cc:dd:ee:ff"; then
    uci add dhcp host >/dev/null
    uci set dhcp.@host[-1].name='August-Lock'
    uci set dhcp.@host[-1].mac='aa:bb:cc:dd:ee:ff'
    uci set dhcp.@host[-1].ip="$LOCK"
    uci commit dhcp
    /etc/init.d/dnsmasq restart >/dev/null 2>&1
    echo "  reserved $LOCK as August-Lock"
else
    echo "  already reserved"
fi

echo
echo "=== everything it is talking to right now ==="
grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null \
  | sed -E 's/.*(tcp|udp).*src=([0-9.]+) dst=([0-9.]+).*dport=([0-9]+).*/  \1 \2 -> \3:\4/' \
  | sort | uniq -c | sort -rn | head -12
echo "  (blank = idle)"

echo
echo "=== resolve what it reached ==="
for ip in $(grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null \
            | sed -E 's/.*dst=([0-9.]+).*/\1/' | sort -u | head -8); do
    case "$ip" in 192.168.*|10.*) continue ;; esac
    printf "  %-16s " "$ip"
    nslookup "$ip" 127.0.0.1 2>/dev/null | awk '/name =/{print $NF}' | head -1
    echo
done

echo
echo "=== is it retrying? (repeated SYN_SENT to one address = being dropped) ==="
grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null | grep -c SYN_SENT | sed 's/^/  SYN_SENT entries: /'
echo "  (more than a couple means packets are going somewhere that never answers)"

echo
echo "=== does it use the router for DNS? ==="
grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null | grep "dport=53" \
  | sed -E 's/.*dst=([0-9.]+).*/  DNS -> \1/' | sort -u
echo "  (should be 192.168.1.1; anything else bypasses policy)"

echo
echo "=== per-destination counter, so brief attempts are not missed ==="
iptables -w -N LOCKWATCH 2>/dev/null || iptables -w -F LOCKWATCH
iptables -w -A LOCKWATCH -p tcp --dport 443  -m comment --comment "lw https" -j RETURN
iptables -w -A LOCKWATCH -p tcp --dport 8883 -m comment --comment "lw mqtt"  -j RETURN
iptables -w -A LOCKWATCH -p udp --dport 53   -m comment --comment "lw dns"   -j RETURN
iptables -w -A LOCKWATCH -p tcp --dport 80   -m comment --comment "lw http"  -j RETURN
iptables -w -A LOCKWATCH -m comment --comment "lw other" -j RETURN
iptables -w -C FORWARD -s "$LOCK" -j LOCKWATCH 2>/dev/null \
    || iptables -w -I FORWARD 1 -s "$LOCK" -j LOCKWATCH
echo "  installed - read with: iptables -L LOCKWATCH -v -n"
