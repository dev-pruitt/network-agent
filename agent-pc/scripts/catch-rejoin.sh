#!/bin/sh
# The lock was just power-cycled. Find what re-joined.
#
# A device losing power and coming back leaves three marks, and they
# corroborate each other rather than relying on any one:
#   - a fresh DHCP lease expiry (renewed within the last few minutes)
#   - a recent wifi association (low "ago" time on the radio)
#   - a burst of new connections as it re-establishes its cloud session
#
# This is the cleanest identification available: the operator performed a
# known action at a known time, so anything correlating with it is the device.
NOW=$(date +%s)

echo "=== DHCP leases renewed in the last 10 minutes ==="
awk -v now="$NOW" '{
    # field 1 is the lease EXPIRY. A 12h lease renewed just now expires ~12h
    # out; anything expiring much later than its peers just renewed.
    age = $1 - now
    printf "%d %s %s %s\n", age, $2, $3, $4
}' /tmp/dhcp.leases 2>/dev/null | sort -rn | head -8 | while read -r rem mac ip name; do
    hrs=$((rem / 3600)); mins=$(((rem % 3600) / 60))
    printf "  expires in %2dh%02dm  %-15s %-18s %s\n" "$hrs" "$mins" "$ip" "$mac" "${name:-UNNAMED}"
done
echo "  (the freshest lease - largest remaining time - renewed most recently)"

echo
echo "=== wifi: who associated most recently? ==="
for w in wlan0 wlan1 wlan2 wlan3; do
    iwinfo "$w" assoclist 2>/dev/null | grep -E "dBm|ago" | paste - - 2>/dev/null | \
    while read -r line; do
        mac=$(echo "$line" | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
        ago=$(echo "$line" | grep -oE '[0-9]+ ms ago' | head -1)
        [ -n "$mac" ] && printf "  %-6s %-18s %s\n" "$w" "$mac" "${ago:-?}"
    done
done | sort -t' ' -k3 -n | head -12
echo "  (a device that just rebooted shows a LOW ms-ago, or appears newly)"

echo
echo "=== raw assoclist with times ==="
for w in wlan0 wlan1; do
    echo "  --- $w ---"
    iwinfo "$w" assoclist 2>/dev/null | grep -E "^[0-9A-F]" | sed 's/^/    /'
done

echo
echo "=== hosts with brand-new connections (session re-establishment) ==="
/usr/bin/lock-catch read 2>/dev/null | head -10

echo
echo "=== recent DHCP activity in the log ==="
logread 2>/dev/null | grep -iE "DHCPACK|DHCPREQUEST|DHCPDISCOVER" | tail -12 | sed 's/^/  /'
echo "  (a DHCPDISCOVER means a device booted rather than merely renewed)"
