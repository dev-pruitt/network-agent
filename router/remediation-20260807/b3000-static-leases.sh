#!/bin/sh
# ============================================================================
# b3000-static-leases.sh - pin the addresses that other config depends on
#
# WHY THIS IS NOT HOUSEKEEPING
#   Two rules in this deployment name an IP literally:
#     - the WG_LB probe-host exemption   -> 192.168.1.50 (agent)
#     - the camera portal RTSP source    -> 192.168.1.117 (camera)
#   Neither notices if DHCP hands that address to something else. The rule
#   keeps matching, just on the wrong host, and everything downstream keeps
#   reporting healthy. That is the exact failure this project has now hit
#   four separate times - a hardcoded value that stopped tracking reality.
#
#   A reservation does not remove the coupling. It makes the coupling true.
#
# Safe to re-run. Skips hosts that already have a reservation.
# ============================================================================
set -e

echo "=== b3000-static-leases ==="
date

# name                mac                  ip
RESERVATIONS="
agent-pc|aa:bb:cc:dd:ee:ff|192.168.1.50
Camera-G100|aa:bb:cc:dd:ee:ff|192.168.1.117
"

BK="/tmp/dhcp.bak-$(date +%Y%m%d-%H%M%S)"
cp /etc/config/dhcp "$BK"
echo "  backup: $BK"

echo
echo "--- existing reservations ---"
uci show dhcp 2>/dev/null | grep -E "\.mac=|\.ip=" | sed 's/^/  /' || echo "  (none)"

echo
echo "--- applying ---"
CHANGED=0
echo "$RESERVATIONS" | while IFS='|' read -r name mac ip; do
    [ -z "$mac" ] && continue

    # Already reserved? Match on MAC, which is the stable identifier - matching
    # on IP would happily create a second entry for the same device.
    if uci show dhcp 2>/dev/null | grep -qi "mac='$mac'"; then
        echo "  $name ($mac) already reserved - skipped"
        continue
    fi

    uci add dhcp host >/dev/null
    uci set dhcp.@host[-1].name="$name"
    uci set dhcp.@host[-1].mac="$mac"
    uci set dhcp.@host[-1].ip="$ip"
    echo "  $name -> $ip  reserved"
    CHANGED=1
done

uci commit dhcp
/etc/init.d/dnsmasq restart >/dev/null 2>&1
sleep 3

echo
echo "--- after ---"
uci show dhcp 2>/dev/null | grep -A2 "=host" | grep -E "name=|mac=|ip=" | sed 's/^/  /'

echo
echo "--- verify: dnsmasq came back and both hosts still answer ---"
pgrep dnsmasq >/dev/null && echo "  dnsmasq running" || { echo "  FAIL: dnsmasq down - restoring"; cp "$BK" /etc/config/dhcp; /etc/init.d/dnsmasq restart; exit 1; }
for ip in 192.168.1.50 192.168.1.117; do
    printf "  %-15s " "$ip"
    ping -c 2 -W 2 "$ip" >/dev/null 2>&1 && echo "reachable" || echo "NO RESPONSE"
done

echo
echo "=== done ==="
echo "Reservations bind on next lease renewal. Both hosts keep their current"
echo "address either way - this stops them being reassigned later, it does not"
echo "move them now."
