#!/bin/sh
# Watch for packets leaving a raw WAN sourced from the WireGuard inner address.
# Cron, every 10 min, ~9.5 min capture. Continuous coverage without a
# long-lived SSH session that dies with its parent shell.
#
# -e is required: the destination MAC is the proof. A packet carrying the ISP
# gateway's MAC genuinely reached the ISP wire rather than being a capture
# artifact.
#
# ENDPOINTS ARE DISCOVERED, NEVER HARDCODED.
# An earlier version pasted the peer IPs into the filter. Two problems: the
# literal reached the public repo because the sanitiser only knew about one of
# them, and wg-rotate swaps peers on server death, so the filter would have
# started reporting ordinary tunnel keepalives as leaks the moment a peer
# changed. Reading them live fixes both.
#
# Since the OUTPUT drop rules (2026-08-20) the findings log should stay empty.
# But empty is ambiguous - it reads the same whether nothing leaked or the
# watcher never ran - so the run itself is recorded separately.
LOG=/home/agent/leakwatch.log
BEAT=/home/agent/leakwatch-heartbeat.log
KEY=/home/agent/.ssh/id_rsa_router
ROUTER=root@192.168.1.1
SSHOPT="-o BatchMode=yes -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

echo "$(date '+%F %T') start" >> "$BEAT"

# Current peers, straight from the router. If this cannot be read, do NOT fall
# back to a bare filter: without the exclusions every keepalive looks like a
# leak, and a log full of false findings is worse than no log.
PEERS=$(ssh $SSHOPT -i "$KEY" "$ROUTER" \
        "wg show all endpoints 2>/dev/null | awk '{print \$3}' | cut -d: -f1 | sort -u")
if [ -z "$PEERS" ]; then
  echo "$(date '+%F %T') FAILED - could not read peers, not capturing" >> "$BEAT"
  exit 1
fi

EXCL=""
for ip in $PEERS; do
  EXCL="$EXCL and not host $ip"
done

FILTER="ip$EXCL and not net 10.0.0.0/24 and not net 192.168.12.0/24 and not port 67 and not port 68 and not net 224.0.0.0/4"

ssh $SSHOPT -i "$KEY" "$ROUTER" \
    "timeout 570 tcpdump -i eth1.1 -n -e -q -l '$FILTER' 2>/dev/null" >> "$LOG" 2>&1
rc=$?
# tcpdump killed by `timeout` exits 124; that is the normal healthy ending.
case "$rc" in
  0|124) echo "$(date '+%F %T') ok (rc=$rc, $(echo $PEERS | wc -w) peers excluded)" >> "$BEAT" ;;
  *)     echo "$(date '+%F %T') FAILED rc=$rc - watcher did not run" >> "$BEAT" ;;
esac
tail -n 500 "$BEAT" > "$BEAT.tmp" && mv "$BEAT.tmp" "$BEAT"
