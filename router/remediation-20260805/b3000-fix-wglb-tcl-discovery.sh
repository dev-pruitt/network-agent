#!/bin/sh
# ============================================================================
# wg-lb-watchdog: locate the TCL ACs instead of hardcoding them - 2026-08-06
#
# INTENT (confirmed with the operator and against the routing tables)
#   Every Apple/HomeKit device in this list is pinned to ONE tunnel rather
#   than being randomly split, so automation has a stable path to it:
#
#       CONNMARK 0xc000  ->  rule 1101 "not fwmark 0x8000/0xc000 lookup 8000"
#                        ->  table 8000: "default dev wgclient"
#
#   IPv6 is dropped globally in /etc/firewall.user (ip6tables -P DROP on all
#   chains) because Apple devices prefer v6 and would otherwise bypass this
#   pinning entirely. That block is intact and untouched here.
#
# PROBLEM
#   The two AC entries name addresses that are no longer the ACs:
#
#       -s 192.168.1.237   no DHCP lease, no ARP entry - nothing there
#       -s 192.168.1.214   an unrelated device, vendor prefix 78:9c:85
#
#   The real units are TCL-AC-1 at 192.168.1.221 and TCL-AC-2 at
#   192.168.1.189, vendor prefix bc:09:b9. Both online. Neither pinned.
#   DHCP moved them; the hardcoded rules stayed behind, so the ACs have been
#   silently unpinned - the likely reason they are reachable but not
#   advertising to HomeKit.
#
#   This watchdog rebuilds the chain every 15s, so it has been reasserting
#   the wrong addresses continuously.
#
# FIX
#   Discover them the way the network already identifies them - vendor OUI or
#   lease hostname - so they stay pinned wherever DHCP puts them. This is the
#   same rot that produced the stale wg1pin, the missing wg2 firewall zone,
#   and the stale ROUTER_LEAK exclusions.
#
# NOTE on "MARK --set-mark 1"
#   Kept, pointed at the correct devices, but it is provably inert today:
#   no ip rule, no ip -6 rule and no iptables/ip6tables rule anywhere selects
#   fwmark 0x1. Only the CONNMARK does real work. Left in place rather than
#   removed because it is the operator's call, not mine.
#
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-wglb-tcl-discovery.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
F=/usr/bin/wg-lb-watchdog
echo "### wg-lb-watchdog TCL discovery  $TS"

[ -f "$F" ] || { echo "ABORT: $F not found"; exit 1; }
cp "$F" "$F.bak-tcldisc-$TS"
echo "backup: $F.bak-tcldisc-$TS"

if grep -q 'TCL_AC_OUI' "$F"; then
    echo "already patched - nothing to do"
    exit 0
fi

echo
echo "=== before ==="
grep -n '192.168.1.237\|192.168.1.214' "$F"

# Replace the four hardcoded AC lines with a discovery loop. Everything else
# in rebuild_lb() - the other pinned devices, the RETURNs, the split modes -
# is untouched.
awk '
/-s 192\.168\.8\.237 -j MARK --set-mark 1/ && !done {
    print "  # TCL ACs, located by vendor OUI or lease hostname. Hardcoding these"
    print "  # is what silently unpinned them when DHCP moved the units off"
    print "  # 192.168.1.214/.237 - see b3000-fix-wglb-tcl-discovery.sh."
    print "  TCL_AC_OUI=bc:09:b9"
    print "  for _ac in $(awk -v o=\"$TCL_AC_OUI\" '\''tolower($2) ~ (\"^\" o) || tolower($4) ~ /tcl/ {print $3}'\'' /tmp/dhcp.leases 2>/dev/null); do"
    print "    iptables -w -t mangle -A WG_LB -s \"$_ac\" -j MARK --set-mark 1"
    print "    iptables -w -t mangle -A WG_LB -s \"$_ac\" -j CONNMARK --set-xmark 0xc000/0xc000"
    print "  done"
    done = 1
    next
}
/-s 192\.168\.8\.214 -j MARK --set-mark 1/          { next }
/-s 192\.168\.8\.237 -j CONNMARK --set-xmark 0xc000/ { next }
/-s 192\.168\.8\.214 -j CONNMARK --set-xmark 0xc000/ { next }
{ print }
' "$F" > /tmp/wglb.new || { echo "AWK FAILED"; exit 1; }

mv /tmp/wglb.new "$F"
chmod 755 "$F"

echo
echo "=== after ==="
sed -n '/TCL ACs, located by/,/^  done$/p' "$F"

echo
echo "=== syntax check ==="
if sh -n "$F"; then
    echo "OK"
else
    echo "SYNTAX ERROR - restoring backup"
    cp "$F.bak-tcldisc-$TS" "$F"
    exit 1
fi

echo
echo "=== what discovery resolves to right now ==="
awk 'tolower($2) ~ /^bc:09:b9/ || tolower($4) ~ /tcl/ {print "  " $3 "  " $4 "  " $2}' /tmp/dhcp.leases

echo
echo "=== forcing a chain rebuild ==="
/usr/bin/wg-lb-watchdog >/dev/null 2>&1
sleep 2
echo "  pinned sources in WG_LB now:"
iptables -w -t mangle -S WG_LB | grep -E '^-A WG_LB -s' | sed 's/^/    /'

echo
echo "### done. rollback: cp $F.bak-tcldisc-$TS $F"
