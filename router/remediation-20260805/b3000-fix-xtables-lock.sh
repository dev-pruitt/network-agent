#!/bin/sh
# ============================================================================
# xtables lock-contention fix - 2026-08-05
#
# PROBLEM
#   leak_chain_rules() in /usr/bin/leak-lock echoes -1 when `iptables -L`
#   exits non-zero. Without -w, iptables fails immediately if any other
#   process holds the global xtables lock. The shape gate then logs
#   "LEAK_WATCH has -1 rules - rebuild in flight, skipping cycle" and exits,
#   so detection coverage is intermittent.
#
#   The leak-lock mutex only serialises the leak-chain scripts against EACH
#   OTHER. It cannot stop router-leak-install (25 iptables calls, 0 with -w)
#   or a firewall reload from taking the kernel lock underneath a reader.
#
#   This is the same failure class documented in the leak-lock header for the
#   2026-08-01 incident: torn reads producing monitor_blind spam and false
#   Level 3 alerts. The mutex was half the fix; -w is the other half.
#
# FIX
#   Add -w (wait for xtables lock) to every non-comment iptables/ip6tables
#   invocation in the four leak-detection scripts. -w only changes failure
#   behaviour from "give up instantly" to "wait for the lock" - it cannot
#   alter any rule.
#
#   wg-lb-watchdog already uses -w on all 20 of its calls; it needs no change.
#
# Idempotent - re-running will not produce "-w -w".
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-xtables-lock.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
echo "### xtables lock fix  $TS"

FILES="/usr/bin/leak-lock /usr/bin/leak-watch-monitor /usr/bin/leak-watch-install /usr/bin/router-leak-install"

echo
echo "=== before ==="
for F in $FILES; do
    [ -f "$F" ] || { echo "  MISSING $F"; continue; }
    T=$(grep -c 'iptables ' "$F" 2>/dev/null || echo 0)
    W=$(grep -c 'iptables -w' "$F" 2>/dev/null || echo 0)
    echo "  $(basename $F): $W of $T calls guarded"
done

for F in $FILES; do
    [ -f "$F" ] || continue
    cp "$F" "$F.bak-xtlock-$TS"

    awk '{
        if ($0 ~ /^[[:space:]]*#/) { print; next }        # leave comments alone
        gsub(/iptables -w /,  "@@K4@@")                   # protect already-guarded
        gsub(/ip6tables -w /, "@@K6@@")
        gsub(/ip6tables /,    "ip6tables -w ")
        gsub(/iptables /,     "iptables -w ")
        gsub(/@@K4@@/,        "iptables -w ")
        gsub(/@@K6@@/,        "ip6tables -w ")
        print
    }' "$F" > /tmp/xtl.new || { echo "AWK FAILED on $F"; continue; }

    mv /tmp/xtl.new "$F"
    chmod 755 "$F"

    if sh -n "$F" 2>/dev/null; then
        echo "  patched OK: $(basename $F)"
    else
        echo "  SYNTAX ERROR in $(basename $F) - restoring backup"
        cp "$F.bak-xtlock-$TS" "$F"
    fi
done

echo
echo "=== after ==="
for F in $FILES; do
    [ -f "$F" ] || continue
    T=$(grep -c 'iptables ' "$F" 2>/dev/null || echo 0)
    W=$(grep -c 'iptables -w' "$F" 2>/dev/null || echo 0)
    echo "  $(basename $F): $W of $T calls guarded"
done

echo
echo "=== no double -w anywhere ==="
D=0
for F in $FILES; do
    [ -f "$F" ] || continue
    N=$(grep -c 'w -w' "$F" 2>/dev/null || echo 0)
    [ "$N" != "0" ] && { echo "  WARN $(basename $F) has $N double flags"; D=1; }
done
[ "$D" = "0" ] && echo "  clean"

echo
echo "=== live test: 5 back-to-back reads under contention ==="
. /usr/bin/leak-lock
i=1
while [ $i -le 5 ]; do
    echo "  read $i: LEAK_WATCH=$(leak_chain_rules LEAK_WATCH)  DNS_LEAK=$(leak_chain_rules DNS_LEAK)"
    i=$((i + 1))
done
echo "  (want 4 and 12 every time; any -1 means contention still wins)"

echo
echo "=== monitor cycle ==="
/usr/bin/leak-watch-monitor
sleep 1
logread | grep leak-watch | tail -3

echo
echo "### done. rollback: for f in $FILES; do cp \$f.bak-xtlock-$TS \$f; done"
