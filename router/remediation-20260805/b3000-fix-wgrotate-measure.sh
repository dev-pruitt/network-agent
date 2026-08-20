#!/bin/sh
# ============================================================================
# wg-rotate: measure candidates before committing - 2026-08-06
#
# PROBLEM
#   The candidate loop accepted any server that merely completed a handshake:
#
#       apply "$c_ip" "$c_key"
#       sleep 50
#       if healthy; then ... exit 0
#
#   "healthy" only means a handshake landed inside 60s. Latency was never
#   measured, so rotation was a coin flip. Observed result:
#
#       Aug 5 16:20  wgclient  28.3ms -> 76.8ms   (exit-NN -> exit-NN)
#       Aug 6 03:40  wg2       ~43ms  -> 50.1ms
#
#   Both tunnels ended up slower than before they rotated, and both rotated
#   off 203.0.113.10, the best server either of them had.
#
#   There is a ratchet in it too: the trigger is "worse than my own rolling
#   baseline", so every rotation onto a slower server raises the baseline and
#   the next trigger fires at a higher number. That is what produced four
#   rotations in eight hours on Aug 4 - the tunnel was fine, the policy was
#   chasing its own tail.
#
# FIX
#   Two modes, because "the server is dead" and "the server is slow" want
#   opposite behaviour:
#
#     RECOVER   current tunnel is not handshaking. Any candidate that works
#               is an improvement. First working peer wins, as before.
#     OPTIMISE  current tunnel is up but slow (the --force / latency path).
#               Probe up to MAX_TRY candidates, measure each, keep the best,
#               and only commit if it beats the incumbent by MARGIN. If none
#               does, revert to where we started and log why.
#
#   Latency is measured with the probe IP already pinned to each tunnel by a
#   scope-link route, so the ping cannot leak onto the other tunnel:
#       9.9.9.9         -> wgclient
#       149.112.112.112 -> wg2
#
# Everything above the candidate loop - the 6h cooldown, the "other tunnel
# must be healthy" rail, the WAN-gateway check, the endpoint pin maintenance
# in apply() - is preserved byte for byte.
#
# Run ON THE ROUTER:  ssh b3000 'sh -s' < b3000-fix-wgrotate-measure.sh
# ============================================================================
set -u
TS=$(date +%Y%m%d-%H%M%S)
F=/usr/bin/wg-rotate
echo "### wg-rotate candidate measurement  $TS"

[ -f "$F" ] || { echo "ABORT: $F not found"; exit 1; }
cp "$F" "$F.bak-measure-$TS"
echo "backup: $F.bak-measure-$TS"

if grep -q 'MEASURED CANDIDATE SELECTION' "$F"; then
    echo "already patched - nothing to do"
    exit 0
fi

# keep everything before the candidate loop
awk '/^tried=0$/ { exit } { print }' "$F" > /tmp/wgr.head
if [ ! -s /tmp/wgr.head ]; then echo "ABORT: could not split at 'tried=0'"; exit 1; fi

cat /tmp/wgr.head > /tmp/wgr.new
cat >> /tmp/wgr.new <<'TAILEOF'
# --- MEASURED CANDIDATE SELECTION (2026-08-06) -----------------------------
MAX_TRY=3
MARGIN=85          # a candidate must be <= 85% of the incumbent's RTT
BAD=99999

if [ "$T" = "wg2" ]; then PROBE=149.112.112.112; else PROBE=9.9.9.9; fi

# avg RTT in whole ms through THIS tunnel, or $BAD if unreachable.
measure() {
    _m=$(ping -c 3 -W 2 "$PROBE" 2>/dev/null | grep -o '= [0-9./]*' | head -1)
    [ -z "$_m" ] && { echo "$BAD"; return; }
    _avg=$(echo "$_m" | sed 's/^= //' | cut -d/ -f2 | cut -d. -f1)
    case "${_avg:-}" in ''|*[!0-9]*) echo "$BAD" ;; *) echo "$_avg" ;; esac
}

# Was the tunnel actually up before we touched it? $ths was captured earlier,
# before any apply(), so it still describes the incumbent server.
if [ -n "${ths:-}" ] && [ "${ths:-0}" -gt 0 ] && [ $((now - ths)) -lt 190 ]; then
    MODE=optimise
    BASE=$(measure)
else
    MODE=recover
    BASE=$BAD
fi
logger -t wg-rotate "$T: mode=$MODE incumbent=$CUR_IP baseline=${BASE}ms"

BEST_IP=""; BEST_KEY=""; BEST_NAME=""; BEST_RTT=$BAD
tried=0

while read -r c_name c_ip c_key; do
    [ "$tried" -ge "$MAX_TRY" ] && break
    tried=$((tried + 1))
    logger -t wg-rotate "$T: probing $c_name ($c_ip), attempt $tried"
    apply "$c_ip" "$c_key"
    sleep 50
    if ! healthy; then
        logger -t wg-rotate "$T: candidate $c_name failed to handshake"
        continue
    fi
    R=$(measure)
    logger -t wg-rotate "$T: candidate $c_name handshake OK, ${R}ms"
    if [ "$R" -lt "$BEST_RTT" ]; then
        BEST_RTT=$R; BEST_IP=$c_ip; BEST_KEY=$c_key; BEST_NAME=$c_name
    fi
    # a dead tunnel just needs something that works; do not keep probing
    [ "$MODE" = "recover" ] && break
done < /tmp/wg-rotate.cands

# ---- decide ---------------------------------------------------------------
COMMIT=no
if [ -n "$BEST_IP" ]; then
    if [ "$MODE" = "recover" ]; then
        COMMIT=yes
    elif [ "$BEST_RTT" -lt "$BAD" ] && [ "$BASE" -lt "$BAD" ] \
         && [ $((BEST_RTT * 100)) -le $((BASE * MARGIN)) ]; then
        COMMIT=yes
    fi
fi

if [ "$COMMIT" = "yes" ]; then
    # the loop may have moved past the winner; put it back
    CURRENT=$(wg show "$T" endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)
    if [ "$CURRENT" != "$BEST_IP" ]; then
        logger -t wg-rotate "$T: re-applying best candidate $BEST_NAME"
        apply "$BEST_IP" "$BEST_KEY"
        sleep 50
        healthy || {
            logger -t wg-rotate "$T: best candidate would not re-establish, reverting"
            apply "$CUR_IP" "$CUR_KEY"
            echo "$now" > "$CD_F"
            $ALERT alert "rotate_${T}_fail" "VPN Rotation FAILED" \
                "$T: best candidate $BEST_NAME did not re-establish. Reverted to $CUR_IP."
            exit 1
        }
    fi
    echo "$now" > "$CD_F"
    [ "$T" = "wg2" ]      && ip route del "$CUR_IP" via 192.168.12.1 2>/dev/null
    [ "$T" = "wgclient" ] && ip route del "$CUR_IP" via 10.0.0.1 2>/dev/null
    if [ "$MODE" = "recover" ]; then
        $ALERT send "VPN Server Rotated" \
            "$T recovered off dead server $CUR_IP to $BEST_NAME ($BEST_IP), ${BEST_RTT}ms. Re-add the old server to the pool if it recovers."
    else
        $ALERT send "VPN Server Rotated" \
            "$T moved $CUR_IP (${BASE}ms) -> $BEST_NAME ($BEST_IP, ${BEST_RTT}ms), $(( 100 - (BEST_RTT * 100 / BASE) ))% faster."
    fi
    logger -t wg-rotate "$T: committed $BEST_NAME at ${BEST_RTT}ms (was ${BASE}ms)"
    exit 0
fi

# ---- nothing was better: put the incumbent back ---------------------------
logger -t wg-rotate "$T: no candidate beat ${BASE}ms (best ${BEST_RTT}ms) - reverting to $CUR_IP"
apply "$CUR_IP" "$CUR_KEY"
sleep 50
echo "$now" > "$CD_F"
if [ "$MODE" = "optimise" ]; then
    # Not a failure. The incumbent was simply the best available, and saying
    # so is what stops the pointless churn this patch exists to prevent.
    $ALERT send "VPN Rotation Skipped" \
        "$T stayed on $CUR_IP (${BASE}ms). Probed $tried candidate(s), best was ${BEST_RTT}ms - not enough gain to justify the swap."
    logger -t wg-rotate "$T: kept incumbent, no candidate met the $MARGIN% margin"
    exit 0
fi
$ALERT alert "rotate_${T}_fail" "VPN Rotation FAILED" \
    "$T: tried $tried pool candidate(s), none completed a handshake. Reverted to $CUR_IP. Possible account/key issue - manual check needed."
exit 1
TAILEOF

mv /tmp/wgr.new "$F"
chmod 755 "$F"

echo
echo "=== syntax check ==="
if sh -n "$F"; then
    echo "OK"
else
    echo "SYNTAX ERROR - restoring backup"
    cp "$F.bak-measure-$TS" "$F"
    exit 1
fi

echo
echo "=== preserved rails still present ==="
for rail in '6h cooldown' 'other tunnel' 'WAN gateway' 'wg1pin.target' 'wg2pin.target'; do
    printf '  %-16s %s\n' "$rail" "$(grep -c "$rail" "$F")"
done

echo
echo "=== measure() sanity, both probes ==="
sed -n '/^measure()/,/^}/p' "$F"
for p in 9.9.9.9 149.112.112.112; do
    v=$(ping -c 3 -W 2 "$p" 2>/dev/null | grep -o '= [0-9./]*' | head -1 | sed 's/^= //' | cut -d/ -f2 | cut -d. -f1)
    echo "  $p -> ${v:-unreachable} ms"
done

echo
echo "### done. rollback: cp $F.bak-measure-$TS $F"
