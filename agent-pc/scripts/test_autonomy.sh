#!/bin/bash
# ============================================================================
# Autonomy end-to-end test - non-destructive
#
# Exercises the decline path, which is the new and most bug-prone logic:
# wg-rotate exits 0 without rotating, and the executor must notice via the
# endpoint comparison, log nothing, spend no budget, and leave the proposal
# pending. A false success here would silently drain all six daily slots.
#
# Deliberately does NOT force a real rotation. That path is simpler, and a
# test rotation would burn the real 6h wg-rotate cooldown, leaving the tunnel
# unable to rotate if a genuine fault appeared this evening.
#
# Restores every byte it touches: cooldown stamp, proposals log, action log.
# ============================================================================
set -u
BASE=/home/agent/network-agent
PROPS=$BASE/logs/proposals.jsonl
ACTIONS=$BASE/logs/actions.jsonl
PY=$BASE/venv/bin/python3
TEST_PID="TEST$(date +%m%d%H%M)WG-wgclient"

echo "### autonomy end-to-end test"
echo

# ---- capture pristine state ---------------------------------------------
cp "$PROPS" /tmp/props.pristine
cp "$ACTIONS" /tmp/actions.pristine 2>/dev/null || : > /tmp/actions.pristine
PROPS_BEFORE=$(wc -l < "$PROPS")
ACTIONS_BEFORE=$(wc -l < "$ACTIONS" 2>/dev/null || echo 0)
CD_BEFORE=$(ssh -o StrictHostKeyChecking=no b3000 'cat /etc/guest-security/wg-rotate-wgclient.last 2>/dev/null || echo 0')
EP_BEFORE=$(ssh -o StrictHostKeyChecking=no b3000 'wg show wgclient endpoints' | awk '{print $2}')
echo "baseline: proposals=$PROPS_BEFORE actions=$ACTIONS_BEFORE cooldown_stamp=$CD_BEFORE endpoint=$EP_BEFORE"

# ---- arm: put wg-rotate into its own 6h cooldown -------------------------
ssh -o StrictHostKeyChecking=no b3000 "date +%s > /etc/guest-security/wg-rotate-wgclient.last"
echo "armed: wg-rotate wgclient forced into 6h cooldown"

# ---- inject a fresh pending proposal ------------------------------------
$PY - "$PROPS" "$TEST_PID" <<'PYEOF'
import json, sys
from datetime import datetime
path, pid = sys.argv[1], sys.argv[2]
entry = {
    "proposal_id": pid,
    "timestamp": datetime.now().isoformat(),
    "anomaly_type": "performance_degradation",
    "component": "wgclient",
    "severity": 2,
    "details": "SYNTHETIC TEST PROPOSAL - autonomy dry test, safe to delete",
    "recommended_action": "Run wg-rotate wgclient --force",
    "status": "pending",
}
with open(path, "a") as f:
    f.write(json.dumps(entry) + "\n")
print(f"injected: {pid}")
PYEOF

# ---- run the executor for real ------------------------------------------
echo
echo "=== executor run (--autonomous --execute) ==="
cd "$BASE" && $PY scripts/execute_wireguard_rotation.py --autonomous --execute
echo

# ---- assertions ----------------------------------------------------------
echo "=== assertions ==="
FAIL=0

ACTIONS_AFTER=$(wc -l < "$ACTIONS" 2>/dev/null || echo 0)
if [ "$ACTIONS_AFTER" -eq "$ACTIONS_BEFORE" ]; then
    echo "  PASS  no action logged for a declined rotation"
else
    echo "  FAIL  action log grew $ACTIONS_BEFORE -> $ACTIONS_AFTER"; FAIL=1
fi

EP_AFTER=$(ssh -o StrictHostKeyChecking=no b3000 'wg show wgclient endpoints' | awk '{print $2}')
if [ "$EP_AFTER" = "$EP_BEFORE" ]; then
    echo "  PASS  tunnel endpoint untouched ($EP_AFTER)"
else
    echo "  FAIL  endpoint moved $EP_BEFORE -> $EP_AFTER"; FAIL=1
fi

# Match on the proposal_id FIELD, not a substring. A superseded proposal's
# execution_result embeds the superseding id, so a plain grep matches two
# lines and reads the wrong one.
STATUS=$($PY -c "
import json
for l in open('$PROPS'):
    l = l.strip()
    if not l: continue
    e = json.loads(l)
    if e.get('proposal_id') == '$TEST_PID':
        print(e.get('status')); break
" 2>/dev/null)
if [ "$STATUS" = "pending" ]; then
    echo "  PASS  proposal left pending for retry/escalation"
else
    echo "  FAIL  proposal status is '$STATUS', expected pending"; FAIL=1
fi

BUDGET=$($PY -c "
import json
from datetime import datetime, timedelta
c=0; cut=datetime.now()-timedelta(hours=24)
try:
    for l in open('$ACTIONS'):
        l=l.strip()
        if not l: continue
        e=json.loads(l)
        if e.get('action_type')=='tunnel_restart' and e.get('autonomous') and not e.get('synthetic'):
            if datetime.fromisoformat(e['timestamp'])>cut: c+=1
except FileNotFoundError: pass
print(c)")
if [ "$BUDGET" = "0" ]; then
    echo "  PASS  autonomy budget unspent (0/6)"
else
    echo "  FAIL  budget spent: $BUDGET/6"; FAIL=1
fi

# ---- restore -------------------------------------------------------------
echo
echo "=== restoring ==="
cp /tmp/props.pristine "$PROPS"
cp /tmp/actions.pristine "$ACTIONS"
ssh -o StrictHostKeyChecking=no b3000 "echo '$CD_BEFORE' > /etc/guest-security/wg-rotate-wgclient.last"
rm -f /tmp/props.pristine /tmp/actions.pristine

PROPS_AFTER=$(wc -l < "$PROPS")
CD_AFTER=$(ssh -o StrictHostKeyChecking=no b3000 'cat /etc/guest-security/wg-rotate-wgclient.last')
echo "  proposals restored: $PROPS_BEFORE -> $PROPS_AFTER"
echo "  cooldown restored:  $CD_BEFORE -> $CD_AFTER"
[ "$PROPS_AFTER" = "$PROPS_BEFORE" ] && [ "$CD_AFTER" = "$CD_BEFORE" ] \
    && echo "  PASS  state fully restored" || { echo "  FAIL  state drift"; FAIL=1; }

echo
[ "$FAIL" = "0" ] && echo "### ALL ASSERTIONS PASSED" || echo "### SOME ASSERTIONS FAILED"
exit $FAIL
