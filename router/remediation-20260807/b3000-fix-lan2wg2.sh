#!/bin/sh
# ============================================================================
# b3000-fix-lan2wg2.sh
#
# THE FAULT
#   The WireGuard load balancer assigns 30% of new connections to wg2:
#       -A WG_LB ... statistic mode random probability 0.3 CONNMARK xset 0x4000/0xc000
#   fwmark 0x4000 routes them to table 8002 (wg2). But the firewall had a wg2
#   ZONE with no lan->wg2 FORWARDING, so every one of those connections was
#   rejected by fw3's default forward policy.
#
#   Measured before this fix, from the LAN:
#       -> 9.9.9.9         (pinned to wgclient)   11/15 ok
#       -> 149.112.112.112 (pinned to wg2)         0/15 ok, FORWARD-reject +15
#
#   The 30% splitter and the missing forwarding rule multiply out to the ~25-30%
#   whole-network connection failure rate that showed up as flaky git pushes.
#   wg2 carrying 261 KB against wgclient's 3.7 GB was not an idle tunnel. It
#   was a blocked one.
#
#   Root cause: the wg2 zone was added earlier in this project to match
#   wgclient, and the forwarding rules that make a zone useful were not. Half
#   a change - the zone existed, so everything that inspected the zone
#   reported healthy.
#
# WHY THIS IS NOT A LEAK
#   wg2 is a WireGuard tunnel, the same as wgclient. This permits LAN -> VPN,
#   which is the intended path. The lan->wan forwarding (raw ISP, the actual
#   kill-switch bypass) stays disabled and is asserted below.
#
# Safe to re-run. Verifies before and after, and restores the firewall config
# if the post-check fails.
# ============================================================================
set -e

echo "=== b3000-fix-lan2wg2 ==="
date

BK="/tmp/firewall.bak-$(date +%Y%m%d-%H%M%S)"
cp /etc/config/firewall "$BK"
echo "  backup: $BK"

# --------------------------------------------------------------------------
echo
echo "--- before ---"
printf "  lan2wg2 present:   "; uci show firewall 2>/dev/null | grep -c "lan2wg2=" || true
printf "  guest2wg2 present: "; uci show firewall 2>/dev/null | grep -c "guest2wg2=" || true
printf "  lan->wan enabled:  "
uci get firewall.@forwarding[0].enabled 2>/dev/null || echo "(unset)"

# --------------------------------------------------------------------------
echo
echo "--- applying ---"

add_fwd() {                     # add_fwd <name> <src> <dest>
    if uci show "firewall.$1" >/dev/null 2>&1; then
        uci set "firewall.$1.enabled=1"
        echo "  $1 existed - enabled"
    else
        uci set "firewall.$1=forwarding"
        uci set "firewall.$1.src=$2"
        uci set "firewall.$1.dest=$3"
        uci set "firewall.$1.enabled=1"
        echo "  $1 created ($2 -> $3)"
    fi
}

add_fwd lan2wg2   lan   wg2
add_fwd guest2wg2 guest wg2

uci commit firewall
echo "  committed"

echo "  reloading firewall..."
/etc/init.d/firewall reload >/dev/null 2>&1 || fw3 reload >/dev/null 2>&1
sleep 3

# --------------------------------------------------------------------------
echo
echo "--- after ---"
printf "  lan2wg2:   "; uci get firewall.lan2wg2.enabled 2>/dev/null || echo MISSING
printf "  guest2wg2: "; uci get firewall.guest2wg2.enabled 2>/dev/null || echo MISSING

echo
echo "  kill-switch assertion (lan->wan must stay OFF):"
KS=$(uci get firewall.@forwarding[0].enabled 2>/dev/null || echo 0)
if [ "$KS" = "1" ]; then
    echo "    FAIL: lan->wan forwarding is ENABLED - restoring backup"
    cp "$BK" /etc/config/firewall
    /etc/init.d/firewall reload >/dev/null 2>&1
    exit 1
fi
echo "    OK: lan->wan still disabled"

echo
echo "  forward chain now accepts lan->wg2?"
iptables -S FORWARD 2>/dev/null | grep -iE "wg2" | head -5 | sed 's/^/    /'
iptables -S 2>/dev/null | grep -E "^-A zone_lan_forward.*wg2|^-A forwarding_lan.*wg2" | head -3 | sed 's/^/    /'

echo
echo "=== done ==="
echo "Verify from the LAN, not from here - router traffic takes OUTPUT, not"
echo "FORWARD, so it cannot demonstrate that this worked:"
echo "    for i in \$(seq 1 15); do timeout 4 nc -z 149.112.112.112 853 && echo ok; done"
echo "Expect 15/15. Before this fix it was 0/15."
