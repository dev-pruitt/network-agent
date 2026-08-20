#!/bin/sh
# Capture the lock DURING the failure. This is the state that answers it.
LOCK=192.168.1.214
MAC=aa:bb:cc:dd:ee:ff

echo "=== 1. RADIO: is it even associated? ==="
iwinfo wlan0 assoclist 2>/dev/null | grep -iA2 "$MAC" | sed 's/^/  /' \
    || echo "  NOT ASSOCIATED on wlan0"
iwinfo wlan1 assoclist 2>/dev/null | grep -iA2 "$MAC" | sed 's/^/  /'
echo "  (associated + failing = network layer; gone = radio/power)"

echo
echo "=== 2. ARP ==="
ip neigh show "$LOCK" 2>/dev/null | sed 's/^/  /' || echo "  no entry"

echo
echo "=== 3. does it answer us? ==="
ping -c 3 -W 2 "$LOCK" 2>&1 | tail -2 | sed 's/^/  /'

echo
echo "=== 4. EVERY connection it has, with STATE ==="
grep "src=$LOCK \|dst=$LOCK " /proc/net/nf_conntrack 2>/dev/null \
  | sed -E 's/^ipv[46] +[0-9]+ +([a-z]+).*/\1 &/' \
  | awk '{
      state="-"; dst="-"; dport="-"
      for(i=1;i<=NF;i++){
        if($i ~ /^(SYN_SENT|SYN_RECV|ESTABLISHED|FIN_WAIT|TIME_WAIT|CLOSE|LAST_ACK|CLOSE_WAIT)$/) state=$i
        if($i ~ /^dst=/ && dst=="-") dst=substr($i,5)
        if($i ~ /^dport=/ && dport=="-") dport=substr($i,7)
      }
      print "  " state "  -> " dst ":" dport
    }' | sort | uniq -c | sort -rn | head -20
echo "  (many SYN_SENT to one address = packets vanishing, the multi-min stall)"

echo
echo "=== 5. protocol counters since the watch was installed ==="
iptables -w -L LOCKWATCH -v -n -x 2>/dev/null \
  | awk '/lw /{printf "  %10s pkts %12s bytes  %s\n", $1, $2, $NF}'

echo
echo "=== 6. is it resolving, and where? ==="
grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null | grep "dport=53" \
  | sed -E 's/.*dst=([0-9.]+).*/  DNS -> \1/' | sort -u
echo "  (blank = not resolving right now)"

echo
echo "=== 7. is it trying IPv6? ==="
grep -i "$LOCK\|$MAC" /proc/net/nf_conntrack 2>/dev/null | grep -c ipv6 | sed 's/^/  ipv6 entries: /'
ip -6 neigh show 2>/dev/null | grep -i "$MAC" | sed 's/^/  /'
echo "  (an IPv6 entry with no IPv6 route is the stall we suspected)"

echo
echo "=== 8. is the firewall rejecting anything of its? ==="
iptables -w -L FORWARD -v -n -x 2>/dev/null | awk '/reject/ {print "  FORWARD reject total: " $1}'

echo
echo "=== 9. reverse-lookup its destinations ==="
for ip in $(grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null \
            | sed -E 's/.*dst=([0-9.]+).*/\1/' | sort -u | head -6); do
    case "$ip" in 192.168.*) continue ;; esac
    printf "  %-16s " "$ip"
    nslookup "$ip" 127.0.0.1 2>/dev/null | awk '/name =/{print $NF}' | head -1
    echo
done
