#!/bin/sh
# ============================================================================
# Refresh ROUTER_LEAK exclusions on rotation - 2026-08-06
#
# PROBLEM
#   router-leak-install builds its "expected traffic" exclusions from the live
#   endpoints - correctly, and the author explicitly noted "never hardcode":
#
#       E1=$(uci -q get wireguard.peer_2001.end_point | cut -d: -f1)
#       E2=$(uci -q get network.wg2peer.endpoint_host | cut -d: -f1)
#       iptables -w -A ROUTER_LEAK -d "$E1" -j RTRLEAK_OK
#       iptables -w -A ROUTER_LEAK -d "$E2" -j RTRLEAK_OK
#
#   But it only ever runs from /etc/firewall.user, i.e. on boot or a firewall
#   restart. wg-rotate never calls it:
#
#       grep -c 'router-leak-install' /usr/bin/wg-rotate  ->  0
#
#   So the moment a tunnel rotates, the chain still excludes the OLD endpoint
#   and the new server's own handshake traffic is counted as un-tunnelled
#   router egress. That raises a Level 3 "the GL-B3000 sent its OWN traffic to
#   an ISP outside the WireGuard tunnel" - about the tunnel itself.
#
#   Observed today:
#     11:52  Carrier (eth1.3): 7480 packets   (after wg2 rotated at 11:50)
#     12:02  Carrier (eth1.3):   50 packets   (after a 3-candidate probe)
#
#   Both false. This is the third instance of one pattern: something that must
#   follow the endpoint does not. The first two were the wg1pin route pin and
#   the wg2 firewall zone.
#
# FIX
#   Refresh the exclusions inside apply(), which is the single place any
#   endpoint changes. That covers commit, revert, and each probe in the new
#   measured-candidate loop - during probing the endpoint legitimately moves
#   several times, and the exclusion list should track every one.
#
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-routerleak-drift.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
F=/usr/bin/wg-rotate
echo "### ROUTER_LEAK drift fix  $TS"

[ -f "$F" ] || { echo "ABORT: $F not found"; exit 1; }
cp "$F" "$F.bak-rlrefresh-$TS"
echo "backup: $F.bak-rlrefresh-$TS"

if grep -q 'router-leak-install' "$F"; then
    echo "already patched - nothing to do"
    exit 0
fi

echo
echo "=== apply() before ==="
sed -n '/^apply()/,/^}/p' "$F"

# insert the refresh as the last statement inside apply(), before its closing brace
awk '
/^apply\(\)/ { inapply = 1 }
inapply && /^}/ && !done {
    print "  # The endpoint just changed, so the ROUTER_LEAK exclusion list is now"
    print "  # stale and this tunnels own handshakes to the new server would be"
    print "  # counted as un-tunnelled router egress, raising a false Level 3."
    print "  [ -x /usr/bin/router-leak-install ] && /usr/bin/router-leak-install >/dev/null 2>&1"
    print "}"
    inapply = 0; done = 1
    next
}
{ print }
' "$F" > /tmp/wgr.rl || { echo "AWK FAILED"; exit 1; }

mv /tmp/wgr.rl "$F"
chmod 755 "$F"

echo
echo "=== apply() after ==="
sed -n '/^apply()/,/^}/p' "$F"

echo
echo "=== syntax check ==="
if sh -n "$F"; then
    echo "OK"
else
    echo "SYNTAX ERROR - restoring backup"
    cp "$F.bak-rlrefresh-$TS" "$F"
    exit 1
fi

echo
echo "=== rebuild exclusions now so the current endpoints are covered ==="
/usr/bin/router-leak-install >/dev/null 2>&1
echo "  drift file: $(cat /tmp/router-leak.endpoints 2>/dev/null)"
echo "  wgclient  : $(wg show wgclient endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)"
echo "  wg2       : $(wg show wg2 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)"

echo
echo "=== exclusions now in the chain ==="
iptables -w -L ROUTER_LEAK -v -n -x 2>/dev/null | awk '$3=="RTRLEAK_OK"' | sed 's/^/  /'

echo
echo "### done. rollback: cp $F.bak-rlrefresh-$TS $F"
