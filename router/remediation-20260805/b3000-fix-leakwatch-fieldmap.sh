#!/bin/sh
# ============================================================================
# leak-watch-monitor field-map fix - 2026-08-05
#
# ROOT CAUSE OF THE AUG 2 "DNS LEAK" CRISIS
#
# DNS_LEAK chain layout built by leak-watch-install (12 rules):
#    1  RETURN       udp -> 10.0.0.0/8        <- healthy in-tunnel DNS (10.2.0.1)
#    2  RETURN       tcp -> 10.0.0.0/8
#    3  RETURN       udp -> 172.16.0.0/12
#    4  RETURN       tcp -> 172.16.0.0/12
#    5  RETURN       udp -> 192.168.0.0/16
#    6  RETURN       tcp -> 192.168.0.0/16
#    7  DNS_LEAK_LOG udp -> anywhere          <- catch-all, DROPs
#    8  DNS_LEAK_LOG tcp -> anywhere
#    9  (count)      udp out eth1.1           <- ACTUAL WAN1 egress
#   10  (count)      tcp out eth1.1
#   11  (count)      udp out eth1.3           <- ACTUAL WAN2 egress
#   12  (count)      tcp out eth1.3
#
# The monitor reads fields 1-4 and calls them D_W1_U / D_W1_T / D_W2_U / D_W2_T
# ("DNS WAN1 udp/tcp, WAN2 udp/tcp"). Fields 1-4 are the RFC1918 RETURN rules.
# So every legitimate DNS query dnsmasq forwards to 10.2.0.1 through the tunnel
# was counted and reported as "DNS packets egressed the raw WAN".
#
# The chain grew from 4 rules to 12 at some point; the shape gate was updated
# to "expected 12" but these field offsets never were. Fields 9-12 are correct
# and have read 0 the entire time - nothing has ever actually egressed.
#
# Fix: read fields 9-12. Tighten the field-count guard from >=4 to ==12.
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-leakwatch-fieldmap.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
F=/usr/bin/leak-watch-monitor
echo "### leak-watch field-map fix  $TS"

cp "$F" "$F.bak-fieldmap-$TS"
echo "backup: $F.bak-fieldmap-$TS"

echo
echo "=== before ==="
grep -n 'D_W1_U=' "$F"
grep -n 'count_fields "$DNS_COUNTS"' "$F"

# --- patch the field map (line-addressed; avoids regex escaping of $1..$4) ---
LN=$(grep -n '^D_W1_U=' "$F" | cut -d: -f1)
if [ -z "$LN" ]; then echo "ABORT: could not locate D_W1_U line"; exit 1; fi
awk -v ln="$LN" 'NR==ln{print "D_W1_U=${9}; D_W1_T=${10}; D_W2_U=${11}; D_W2_T=${12}"; next} {print}' \
    "$F" > /tmp/lwm.new && mv /tmp/lwm.new "$F"

# --- tighten the guard: a short read must not silently pass ---
sed -i 's/"$DNS_COUNTS")" -ge 4 /"$DNS_COUNTS")" -eq 12 /' "$F"

chmod 755 "$F"

echo
echo "=== after ==="
grep -n 'D_W1_U=' "$F"
grep -n 'count_fields "$DNS_COUNTS"' "$F"

# --- syntax check before we let cron near it ---
echo
echo "=== syntax check ==="
if sh -n "$F"; then echo "OK"; else echo "SYNTAX ERROR - restoring backup"; cp "$F.bak-fieldmap-$TS" "$F"; exit 1; fi

# --- rebaseline so the corrected counters do not fire a transition alert ---
echo
echo "=== rebaselining state ==="
rm -f /tmp/leak-watch.state
/usr/bin/leak-watch-monitor
sleep 1
echo "state now: $(cat /tmp/leak-watch.state 2>/dev/null)"

echo
echo "=== live values the monitor now reads (fields 9-12, should be 0 0 0 0) ==="
iptables -w -L DNS_LEAK -v -n -x | awk 'NR>=3 && NF>=6 {printf "%s ", $1}' | awk '{print "  W1_udp="$9"  W1_tcp="$10"  W2_udp="$11"  W2_tcp="$12}'

echo
echo "### done. rollback: cp $F.bak-fieldmap-$TS $F"
