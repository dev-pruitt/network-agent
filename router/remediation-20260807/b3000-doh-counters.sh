#!/bin/sh
# ============================================================================
# b3000-doh-counters.sh - count DoH attempts instead of sampling for them
#
# WHY SAMPLING FAILED
#   The first version read /proc/net/nf_conntrack every 15 minutes looking for
#   a live connection to a known DoH resolver on 443. It caught the robot
#   vacuum once and then could not reproduce it three samples later.
#
#   That is not a flaky device, it is the wrong instrument. A DoH query is a
#   short TCP conversation; the conntrack entry is gone in seconds. Sampling
#   every 15 minutes sees a few milliseconds of every interval and calls the
#   rest silence. It cannot tell "no DoH" from "DoH I did not happen to catch",
#   which is the same cannot-observe-vs-observed-fault confusion this project
#   keeps finding.
#
# WHAT THIS DOES INSTEAD
#   An iptables chain with one counting rule per known DoH resolver. Counters
#   accumulate continuously and survive between polls, so a single query at
#   03:00 is still visible at 09:00. The monitor then reads a number rather
#   than hoping to be looking at the right moment.
#
#   Counting only - no DROP. Blocking a device's resolver without warning
#   tends to break the device in ways that are hard to attribute later. Decide
#   what to block once there is evidence of who is doing what.
#
# Idempotent. Survives firewall reload via firewall.user.
# ============================================================================
set -e

CHAIN=DOH_WATCH
LAN=192.168.1.0/24
GUEST=192.168.2.0/24

# Well-known DoH endpoints. Incomplete by nature - an unlisted endpoint is
# invisible here, and the monitor says so rather than claiming a clean result.
RESOLVERS="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 \
94.140.14.14 94.140.15.15 208.67.222.222 208.67.220.220 45.90.28.0 45.90.30.0"

echo "=== DoH counters ==="
date

install_chain() {
    iptables -w -N "$CHAIN" 2>/dev/null || iptables -w -F "$CHAIN"
    for r in $RESOLVERS; do
        iptables -w -A "$CHAIN" -d "$r" -p tcp --dport 443 \
            -m comment --comment "doh-watch $r" -j RETURN
    done
    # Hook it where LAN and guest traffic is forwarded out.
    for src in "$LAN" "$GUEST"; do
        iptables -w -C FORWARD -s "$src" -p tcp --dport 443 -j "$CHAIN" 2>/dev/null \
            || iptables -w -I FORWARD 1 -s "$src" -p tcp --dport 443 -j "$CHAIN"
    done
}

install_chain
echo "  chain installed with $(echo $RESOLVERS | wc -w) resolver rules"

# Persist. firewall.user re-runs on reload, and without this the chain
# disappears the next time anything touches the firewall - the exact failure
# that made the Tailscale forwarding check inert for weeks.
MARK="# doh-watch (managed by b3000-doh-counters.sh)"
if ! grep -q "doh-watch" /etc/firewall.user 2>/dev/null; then
    cat >> /etc/firewall.user <<EOF

$MARK
# Counting only, never blocking. Accumulates so a short DoH query at 03:00 is
# still visible when the monitor polls at 09:00.
$(command -v sh) /usr/bin/doh-watch-install 2>/dev/null || true
EOF
    echo "  hooked into /etc/firewall.user"
else
    echo "  already in /etc/firewall.user"
fi

# Self-contained reinstaller the hook calls.
cat > /usr/bin/doh-watch-install <<'EOS'
#!/bin/sh
CHAIN=DOH_WATCH
RESOLVERS="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 94.140.14.14 94.140.15.15 208.67.222.222 208.67.220.220 45.90.28.0 45.90.30.0"
iptables -w -N "$CHAIN" 2>/dev/null || iptables -w -F "$CHAIN"
for r in $RESOLVERS; do
    iptables -w -A "$CHAIN" -d "$r" -p tcp --dport 443 -m comment --comment "doh-watch $r" -j RETURN
done
for src in 192.168.1.0/24 192.168.2.0/24; do
    iptables -w -C FORWARD -s "$src" -p tcp --dport 443 -j "$CHAIN" 2>/dev/null \
        || iptables -w -I FORWARD 1 -s "$src" -p tcp --dport 443 -j "$CHAIN"
done
EOS
chmod +x /usr/bin/doh-watch-install
echo "  reinstaller written to /usr/bin/doh-watch-install"

echo
echo "--- verify: chain present and hooked ---"
iptables -w -L "$CHAIN" -v -n 2>/dev/null | head -4 | sed 's/^/  /'
printf "  hooks in FORWARD: "
iptables -w -S FORWARD 2>/dev/null | grep -c "$CHAIN"

echo
echo "--- survives a reload? ---"
/etc/init.d/firewall reload >/dev/null 2>&1
sleep 3
if iptables -w -S FORWARD 2>/dev/null | grep -q "$CHAIN"; then
    echo "  OK: still hooked after reload"
else
    echo "  FAIL: vanished on reload - firewall.user did not reapply it"
    exit 1
fi

echo
echo "=== done - counters start at zero and accumulate from now ==="
