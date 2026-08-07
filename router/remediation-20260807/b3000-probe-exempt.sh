#!/bin/sh
# ============================================================================
# b3000-probe-exempt.sh - exempt the monitoring host from the WG load balancer
#
# WHY
#   The reachability probe aims at destinations statically pinned per tunnel,
#   on the assumption that the destination decides the path. It does not. The
#   load balancer sets a connmark, and ip rule 1098 (fwmark 0x4000 -> table
#   8002) is evaluated BEFORE rule 1100, which is the one that consults the
#   main table's per-destination routes. The mark wins.
#
#   Measured: with wg2 broken, the WGCLIENT probe fell to 6/8 then 3/8,
#   because 30% of those connections were sprayed into the broken tunnel.
#   Every tunnel's number moved together and nothing could be attributed.
#
#   A RETURN for the probe host at the top of WG_LB removes it from the
#   spray, so a pinned destination means exactly one tunnel.
#
# SCOPE AND COST, stated rather than buried
#   Only this one host is exempt. Every other client stays balanced.
#   The probe therefore measures TUNNEL health, not what a balanced client
#   experiences - the balancer is covered separately by the FORWARD-reject
#   delta the probe reads.
#
# NOT A SECURITY CHANGE
#   The host still egresses through a tunnel; it is pinned to one rather than
#   sprayed across two. lan->wan (raw ISP) forwarding is untouched, and
#   asserted below.
#
# Idempotent. Restores its backup if the post-check fails.
# ============================================================================
set -e

PROBE_HOST="${PROBE_HOST:-192.168.1.50}"
echo "=== b3000-probe-exempt ==="
date
echo "  probe host: $PROBE_HOST"

BK="/tmp/firewall.user.bak-$(date +%Y%m%d-%H%M%S)"
[ -f /etc/firewall.user ] && cp /etc/firewall.user "$BK" && echo "  backup: $BK"

echo
echo "--- before ---"
printf "  WG_LB RETURN for probe host: "
iptables -t mangle -S WG_LB 2>/dev/null | grep -c "$PROBE_HOST.*RETURN" || echo 0

# --------------------------------------------------------------------------
# Insert at position 1 so it precedes every spray rule. WG_LB is rebuilt by
# firewall.user on reload, so the rule is added there too - an iptables
# command alone would vanish at the next reload, which is the "config that
# does not survive" failure this project has hit repeatedly.
# --------------------------------------------------------------------------
echo
echo "--- applying ---"

if ! iptables -t mangle -S WG_LB 2>/dev/null | grep -q "$PROBE_HOST.*RETURN"; then
    iptables -w -t mangle -I WG_LB 1 -s "$PROBE_HOST"/32 \
        -m comment --comment "probe-host-exempt" -j RETURN
    echo "  live rule inserted at WG_LB position 1"
else
    echo "  live rule already present"
fi

MARK="# probe-host-exempt (managed)"
if ! grep -q "probe-host-exempt" /etc/firewall.user 2>/dev/null; then
    cat >> /etc/firewall.user <<EOF

$MARK
# Keep the monitoring host out of the WireGuard load balancer so that
# destination-pinned probes isolate a single tunnel. Without this, the
# balancer mark overrides the per-destination route and every tunnel's
# measurement moves together.
iptables -w -t mangle -D WG_LB -s $PROBE_HOST/32 -m comment --comment "probe-host-exempt" -j RETURN 2>/dev/null
iptables -w -t mangle -I WG_LB 1 -s $PROBE_HOST/32 -m comment --comment "probe-host-exempt" -j RETURN
EOF
    echo "  persisted to /etc/firewall.user"
else
    echo "  already persisted in /etc/firewall.user"
fi

# --------------------------------------------------------------------------
echo
echo "--- after ---"
echo "  WG_LB head:"
iptables -t mangle -S WG_LB 2>/dev/null | head -3 | sed 's/^/    /'

echo
echo "  kill-switch assertion (lan->wan must stay OFF):"
KS=$(uci get firewall.@forwarding[0].enabled 2>/dev/null || echo 0)
if [ "$KS" = "1" ]; then
    echo "    FAIL: lan->wan forwarding is ENABLED - restoring"
    [ -f "$BK" ] && cp "$BK" /etc/firewall.user
    exit 1
fi
echo "    OK: lan->wan still disabled"

echo
echo "  survives a firewall reload?"
/etc/init.d/firewall reload >/dev/null 2>&1
sleep 3
if iptables -t mangle -S WG_LB 2>/dev/null | grep -q "$PROBE_HOST.*RETURN"; then
    echo "    OK: rule still present after reload"
else
    echo "    FAIL: rule vanished on reload - firewall.user did not reapply it"
    exit 1
fi

echo
echo "=== done ==="
