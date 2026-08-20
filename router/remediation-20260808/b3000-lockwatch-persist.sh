#!/bin/sh
# ============================================================================
# b3000-lockwatch-persist.sh - make the lock's traffic counter permanent
#
# The LOCKWATCH chain was created by hand while chasing the fault and lives
# only in memory. The next firewall reload would delete it, and the monitor
# built on top would go blind - reporting "cannot observe" forever, which is
# exactly how the Tailscale forwarding check sat inert for weeks.
#
# Counting only, per protocol. Nothing is blocked: the point is to know
# whether bytes are moving, and a frozen counter on an ESTABLISHED socket is
# the signature of the wedged state.
# ============================================================================
set -e
LOCK=192.168.1.214
CHAIN=LOCKWATCH

echo "=== lockwatch persistence ==="
date

cat > /usr/bin/lockwatch-install <<'EOS'
#!/bin/sh
# Rebuild the per-protocol counters for the August lock. Called at boot and
# on every firewall reload. Idempotent.
LOCK=192.168.1.214
CHAIN=LOCKWATCH
iptables -w -N "$CHAIN" 2>/dev/null || iptables -w -F "$CHAIN"
iptables -w -A "$CHAIN" -p tcp --dport 443  -m comment --comment "lw https" -j RETURN
iptables -w -A "$CHAIN" -p tcp --dport 8883 -m comment --comment "lw mqtt"  -j RETURN
iptables -w -A "$CHAIN" -p udp --dport 53   -m comment --comment "lw dns"   -j RETURN
iptables -w -A "$CHAIN" -p tcp --dport 80   -m comment --comment "lw http"  -j RETURN
iptables -w -A "$CHAIN" -m comment --comment "lw other" -j RETURN
iptables -w -C FORWARD -s "$LOCK" -j "$CHAIN" 2>/dev/null \
    || iptables -w -I FORWARD 1 -s "$LOCK" -j "$CHAIN"
EOS
chmod +x /usr/bin/lockwatch-install
echo "  wrote /usr/bin/lockwatch-install"

if ! grep -q "lockwatch-install" /etc/firewall.user 2>/dev/null; then
    cat >> /etc/firewall.user <<'EOF'

# August lock traffic counters. Counting only - a frozen counter on an
# ESTABLISHED socket is how the wedged state is detected.
/usr/bin/lockwatch-install 2>/dev/null || true
EOF
    echo "  hooked into /etc/firewall.user"
else
    echo "  already hooked"
fi

/usr/bin/lockwatch-install
echo "  chain rebuilt"

echo
echo "--- survives a reload? ---"
/etc/init.d/firewall reload >/dev/null 2>&1
sleep 3
if iptables -w -S FORWARD 2>/dev/null | grep -q "$CHAIN"; then
    echo "  OK: still hooked after reload"
    iptables -w -L "$CHAIN" -v -n 2>/dev/null | head -3 | sed 's/^/    /'
else
    echo "  FAIL: vanished on reload"
    exit 1
fi

echo
echo "=== done ==="
