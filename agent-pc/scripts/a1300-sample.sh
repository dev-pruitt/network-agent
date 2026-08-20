#!/bin/sh
# One observation of the laundry extender. Driven by cron so it outlives the
# ssh session that installed it - a background loop started over ssh dies with
# the session, which is how the first attempt collected nothing.
#
# Records ping AND association in the same sample, because they separate the
# two candidate faults:
#     ping fails, association GONE   -> the radio link drops (RF, power, deauth)
#     ping fails, still associated   -> the device is up, its IP stack stopped
# Those need completely different fixes, and a ping-only check cannot tell
# them apart - which is why the existing monitor can only ever say "offline".
IP=192.168.2.250
TAIL='83:c4:91:95:5c'
LOG=/tmp/a1300-watch.log

T=$(date '+%H:%M:%S')

if ping -c 1 -W 2 "$IP" >/dev/null 2>&1; then P=ok; else P=FAIL; fi

LINE=$(iwinfo wlan2 assoclist 2>/dev/null | grep -i "$TAIL" | head -1)
if [ -n "$LINE" ]; then
    A=assoc
    SIG=$(echo "$LINE" | grep -oE '\-[0-9]+ dBm' | head -1 | tr -d ' ')
    SNR=$(echo "$LINE" | grep -oE 'SNR [0-9]+' | head -1 | tr ' ' '=')
else
    A=GONE
    SIG=none
    SNR=none
fi

ARP=$(ip neigh show "$IP" 2>/dev/null | awk '{print $NF}')
[ -z "$ARP" ] && ARP=none

echo "$T ping=$P assoc=$A sig=${SIG:-none} ${SNR:-none} arp=$ARP" >> "$LOG"
