#!/bin/sh
# ============================================================================
# wg-rotate wgclient-pin fix - 2026-08-05
#
# WHY THIS BLOCKS AUTONOMY
#   apply() maintains the endpoint pin for wg2 but not for wgclient:
#
#     wg2 branch      uci set network.wg2pin.target="$a_ip"
#                     ip route add "$a_ip/32" via 192.168.12.1 dev eth1.3
#     wgclient branch (nothing)
#
#   So every wgclient rotation leaves network.wg1pin pointing at the previous
#   endpoint and installs no host route for the new one. wgclient's outer
#   packets then fall back onto the ECMP default and float across both WANs -
#   the exact condition that produced the 20ms-to-444ms baseline swings and
#   the four rotation approvals on Aug 4.
#
#   Pinning wgclient by hand fixed today's symptom. Without this patch the
#   next rotation re-breaks it - and with autonomy enabled, that rotation
#   happens unattended.
#
# CHANGES
#   1. apply() wgclient branch now mirrors wg2: updates wg1pin (target,
#      interface, gateway) and installs the host route via 10.0.0.1/eth1.1.
#      Uses `ip route replace` so a stale route is overwritten, not duplicated.
#   2. Success path removes the old wgclient host route, mirroring wg2.
#
# Idempotent. Verifies with `sh -n` and restores the backup on any failure.
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-wgrotate-pin.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
F=/usr/bin/wg-rotate
echo "### wg-rotate wgclient-pin fix  $TS"

[ -f "$F" ] || { echo "ABORT: $F not found"; exit 1; }
cp "$F" "$F.bak-wgpin-$TS"
echo "backup: $F.bak-wgpin-$TS"

if grep -q 'network.wg1pin.target' "$F"; then
    echo "already patched - nothing to do"
    exit 0
fi

echo
echo "=== before: apply() wgclient branch ==="
sed -n '/^apply()/,/^}/p' "$F"

# --- rewrite the wgclient branch of apply() -------------------------------
awk '
/^  else$/ && inapply && !done_else {
    print "  else"
    print "    uci set wireguard.peer_2001.public_key=\"$a_key\""
    print "    uci set wireguard.peer_2001.end_point=\"$a_ip:51820\""
    print "    uci commit wireguard"
    print "    # keep the WAN1 endpoint pin in step with the new peer, exactly as"
    print "    # the wg2 branch does for wg2pin - without this wgclient falls back"
    print "    # onto the ECMP default and floats between both WANs."
    print "    uci set network.wg1pin.target=\"$a_ip\""
    print "    uci set network.wg1pin.interface='\''wan'\''"
    print "    uci set network.wg1pin.gateway='\''10.0.0.1'\''"
    print "    uci commit network"
    print "    ip route replace \"$a_ip/32\" via 10.0.0.1 dev eth1.1 metric 10 2>/dev/null"
    print "    ifup wgclient >/dev/null 2>&1"
    skip = 4          # drop the 4 original lines of this branch
    done_else = 1
    next
}
/^apply\(\)/ { inapply = 1 }
/^}/ && inapply && done_else { inapply = 0 }
skip > 0 { skip--; next }
{ print }
' "$F" > /tmp/wgr.new || { echo "AWK FAILED"; exit 1; }

mv /tmp/wgr.new "$F"

# --- mirror the old-route cleanup on the success path ---------------------
if ! grep -q 'ip route del "$CUR_IP" via 10.0.0.1' "$F"; then
    sed -i 's|\[ "\$T" = "wg2" \] && ip route del "\$CUR_IP" via 192.168.12.1 2>/dev/null|&\n    [ "$T" = "wgclient" ] \&\& ip route del "$CUR_IP" via 10.0.0.1 2>/dev/null|' "$F"
fi

chmod 755 "$F"

echo
echo "=== after: apply() ==="
sed -n '/^apply()/,/^}/p' "$F"

echo
echo "=== old-route cleanup lines ==="
grep -n 'ip route del "\$CUR_IP"' "$F"

echo
echo "=== syntax check ==="
if sh -n "$F"; then
    echo "OK"
else
    echo "SYNTAX ERROR - restoring backup"
    cp "$F.bak-wgpin-$TS" "$F"
    exit 1
fi

echo
echo "=== current pin state ==="
echo "wg1pin.target = $(uci -q get network.wg1pin.target)   (wgclient endpoint: $(wg show wgclient endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1))"
echo "wg2pin.target = $(uci -q get network.wg2pin.target)   (wg2 endpoint:      $(wg show wg2 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1))"

echo
echo "### done. rollback: cp $F.bak-wgpin-$TS $F"
