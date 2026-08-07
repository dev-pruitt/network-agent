#!/bin/bash
# Induce the exact fault the probe exists to catch, and confirm it fires.
#
# A monitor that has never been observed to fire is an untested monitor. Half
# the defects in this project were checks that could not have detected the
# thing they claimed to watch - the mDNS test that could only ever be a false
# alarm, the leak counter reading the wrong rows. Watching this one trip is
# the difference between "written" and "works".
#
# Disables lan2wg2, runs two rounds (CONSECUTIVE_BAD=2), then restores.
# Restore runs on ANY exit path, including Ctrl-C, so the network cannot be
# left broken by this test.
set -u
R="ssh -o ConnectTimeout=10 -o BatchMode=yes b3000"
PY="$HOME/network-agent-backup/venv/bin/python3"
PROBE="$HOME/network-agent-backup/agent-pc/scripts/tunnel_reachability_probe.py"
STATE="$HOME/network-agent/logs/tunnel_probe_state.json"

restore() {
    echo
    echo "--- restoring lan2wg2 ---"
    $R "uci set firewall.lan2wg2.enabled=1 && uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1"
    sleep 4
    printf "  lan2wg2 enabled: "; $R "uci get firewall.lan2wg2.enabled"
}
trap restore EXIT INT TERM

echo "=== baseline (expect both healthy) ==="
"$PY" "$PROBE"

echo
echo "=== disabling lan2wg2 to recreate the fault ==="
$R "uci set firewall.lan2wg2.enabled=0 && uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1"
sleep 4

echo
echo "=== round 1 (should detect, but NOT alert - corroboration needed) ==="
"$PY" "$PROBE"

echo
echo "=== round 2 (should now raise a proposal) ==="
"$PY" "$PROBE"

echo
echo "=== proposal it produced ==="
tail -1 "$HOME/network-agent/logs/proposals.jsonl" 2>/dev/null | "$PY" -c "
import json,sys
try:
    p = json.loads(sys.stdin.read())
except Exception:
    print('  (none written)'); raise SystemExit
print('  id       :', p.get('proposal_id'))
print('  type     :', p.get('anomaly_type'))
print('  severity :', p.get('severity'))
print('  status   :', p.get('status'))
print()
print('  details  :', p.get('details'))
print()
print('  action   :', p.get('recommended_action'))
"

# restore fires here via trap, then verify recovery is detected
