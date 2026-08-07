#!/bin/sh
# ============================================================================
# wg2 firewall zone - 2026-08-05
#
# PROBLEM
#   wgclient has a firewall zone with masquerade. wg2 has no zone at all:
#
#     firewall.wgclient.masq='1'      <- exists
#     firewall.wg2                    <- does not exist, anywhere
#     iptables -t nat -S | grep -c wg2  ->  0
#
#   Consequences observed:
#     - ping 149.112.112.112 (routed via wg2) is 100% loss, while
#       ping 9.9.9.9 (via wgclient) answers in ~83ms
#     - conntrack shows the wg2 probe [UNREPLIED]
#     - wg2_latency_ms has been null in 200 of 200 telemetry polls, so the
#       dashboard chart has only ever had one line to draw
#     - a reply on wg2 arrived addressed to 192.168.2.228, a guest LAN
#       address, so private sources have reached the far end un-NATted
#     - wg2 has moved 4 MB in three days against wgclient's 9.4 GB
#
#   This is the same shape as the wg1pin/wg2pin defect fixed earlier today:
#   the two tunnels were each configured once, differently, and never
#   diffed against each other.
#
# FIX
#   Create firewall.wg2 mirroring firewall.wgclient field for field. No
#   forwardings are added because wgclient has none either - mirroring means
#   mirroring, not improving one side.
#
# Idempotent. Verifies with a real ping and rolls back if wg2 gets worse.
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-wg2-zone.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
echo "### wg2 firewall zone  $TS"

cp /etc/config/firewall "/etc/config/firewall.bak-wg2zone-$TS"
echo "backup: /etc/config/firewall.bak-wg2zone-$TS"

if [ -n "$(uci -q get firewall.wg2)" ]; then
    echo "firewall.wg2 already exists - nothing to do"
    exit 0
fi

# ---- baseline ------------------------------------------------------------
echo
echo "=== before ==="
BEFORE_LOSS=$(ping -c 3 -W 2 149.112.112.112 2>/dev/null | grep -o '[0-9]*% packet loss' | head -1)
echo "  wg2 probe  149.112.112.112 : ${BEFORE_LOSS:-no reply}"
echo "  wgclient   9.9.9.9         : $(ping -c 2 -W 2 9.9.9.9 2>/dev/null | grep -o '[0-9]*% packet loss' | head -1)"
echo "  nat rules mentioning wg2   : $(iptables -w -t nat -S | grep -c wg2)"

# ---- apply, mirroring wgclient field for field ---------------------------
echo
echo "=== creating firewall.wg2 ==="
uci set firewall.wg2=zone
uci set firewall.wg2.name='wg2'
uci set firewall.wg2.network='wg2'
uci set firewall.wg2.input='ACCEPT'
uci set firewall.wg2.output='ACCEPT'
uci set firewall.wg2.forward='DROP'
uci set firewall.wg2.masq='1'
uci set firewall.wg2.masq6='1'
uci set firewall.wg2.mtu_fix='1'
uci set firewall.wg2.enabled='1'
uci commit firewall

echo "--- new zone ---"
uci show firewall | grep '^firewall\.wg2\.'
echo "--- wgclient, for comparison ---"
uci show firewall | grep '^firewall\.wgclient\.'

echo
echo "=== reloading firewall ==="
/etc/init.d/firewall restart >/dev/null 2>&1
sleep 4

# ---- verify --------------------------------------------------------------
echo
echo "=== after ==="
NAT_WG2=$(iptables -w -t nat -S | grep -c wg2)
echo "  nat rules mentioning wg2   : $NAT_WG2"
iptables -w -t nat -S | grep -i 'wg2.*MASQUERADE' | sed 's/^/    /'

AFTER_LOSS=$(ping -c 4 -W 2 149.112.112.112 2>/dev/null | grep -o '[0-9]*% packet loss' | head -1)
RTT=$(ping -c 4 -W 2 149.112.112.112 2>/dev/null | grep -o 'min/avg/max = [0-9./]*' | head -1)
echo "  wg2 probe  149.112.112.112 : ${AFTER_LOSS:-no reply}  ${RTT:-}"
echo "  wgclient   9.9.9.9         : $(ping -c 2 -W 2 9.9.9.9 2>/dev/null | grep -o '[0-9]*% packet loss' | head -1)"

echo
case "${AFTER_LOSS:-100% packet loss}" in
  "0% packet loss")
      echo "RESULT: wg2 now answers. Latency measurement should populate on the"
      echo "        next poll, and the dashboard chart will show both tunnels."
      ;;
  "100% packet loss")
      echo "RESULT: still 100% loss. The missing zone was real but was not the"
      echo "        whole cause. Zone left in place - it is correct regardless"
      echo "        and wg2 should not be egressing un-NATted private sources."
      echo "        Next suspect: both tunnels carry the same 10.2.0.2/32"
      echo "        address, so return traffic cannot be disambiguated."
      ;;
  *)
      echo "RESULT: partial recovery (${AFTER_LOSS}). Worth another look."
      ;;
esac

echo
echo "### done. rollback: cp /etc/config/firewall.bak-wg2zone-$TS /etc/config/firewall && /etc/init.d/firewall restart"
