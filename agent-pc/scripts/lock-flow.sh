#!/bin/sh
# Is the lock's TLS session moving data during the hang, or open but frozen?
#
# Distinguishes the last two candidates:
#   counter climbing  -> packets flow; the stall is above the network, in
#                        August's cloud or the lock's firmware
#   counter frozen    -> the socket is open but dead, which the network is
#                        responsible for
#
# Also compares LAN latency against another device on the same radio, because
# 62ms average to a LAN host is either a fault or ordinary WiFi power-save on
# a battery device - and only the comparison tells you which.
LOCK=192.168.1.214
PEER=192.168.1.215     # doorbell, same 2.4GHz radio, also battery-ish

echo "=== HTTPS counter over 36s ==="
i=1
while [ "$i" -le 4 ]; do
    line=$(iptables -w -L LOCKWATCH -v -n -x 2>/dev/null | grep "lw https")
    p=$(echo "$line" | awk '{print $1}')
    b=$(echo "$line" | awk '{print $2}')
    echo "  t$i  ${p:-?} pkts  ${b:-?} bytes"
    i=$((i + 1))
    [ "$i" -le 4 ] && sleep 12
done
echo "  (unchanged across all four = frozen socket)"

echo
echo "=== conntrack entry for that session ==="
grep "src=$LOCK " /proc/net/nf_conntrack 2>/dev/null | head -2 | sed 's/^/  /'

echo
echo "=== LAN latency, lock vs a peer on the same radio ==="
printf "  lock     "
ping -c 6 -W 2 "$LOCK" 2>/dev/null | tail -1
printf "  doorbell "
ping -c 6 -W 2 "$PEER" 2>/dev/null | tail -1
printf "  agent    "
ping -c 6 -W 2 192.168.1.50 2>/dev/null | tail -1
echo "  (if the lock and the doorbell are both slow, it is WiFi power save,"
echo "   not a fault - battery devices sleep between beacons on purpose)"
