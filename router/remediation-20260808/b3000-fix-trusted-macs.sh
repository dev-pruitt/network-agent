#!/bin/sh
# ============================================================================
# b3000-fix-trusted-macs.sh - trust the MACs the extender actually uses
#
# THE FAULT
#   /etc/guest-security/trusted-macs.txt contains:
#       aa:bb:cc:dd:ee:ff
#       aa:bb:cc:dd:ee:ff
#   The A1300 extender actually presents:
#       aa:bb:cc:dd:ee:ff   in the bridge/ARP tables
#       aa:bb:cc:dd:ee:ff   in assoclist (WDS virtual interface)
#
#   Neither is trusted. The 5c entry is one bit off - 94 instead of 96 in the
#   first octet, the locally-administered bit that gets set on virtual
#   interfaces. Whoever wrote the list read the MAC off the wrong table.
#
#   a1300-monitor gets this right and says so in a comment: it matches the
#   last four octets precisely because the device presents both forms. So the
#   quirk was known when the monitor was written and lost when the trust list
#   was. One value, two places, only one of them correct.
#
# WHY IT MATTERS EVEN THOUGH NOTHING IS BROKEN TODAY
#   guest-reauth deauthenticates any openNDS-AUTHENTICATED client that is not
#   present and not trusted. openNDS currently reports zero clients, so there
#   is nothing to act on and no harm is occurring.
#
#   The moment a guest authenticates through that extender, the untrusted MAC
#   becomes eligible for deauth. The script's own header records this
#   happening before: "Without this, A1300 guests were deauthed every cycle
#   and lost connectivity." That fix addressed the guests behind the extender.
#   It did not fix the extender's own entry.
#
#   This is a trap being disarmed, not a symptom being treated. It is
#   deliberately NOT presented as the cause of the flapping - the flapping
#   stopped on its own at 10:12 and has not recurred in 27 minutes of
#   one-minute sampling. Claiming this fixed it would be inventing a story.
#
# Additive. Existing entries are left alone - they may belong to other
# devices, and removing a trust entry to tidy up is how you break something
# you were not looking at.
# ============================================================================
set -e

TRUST=/etc/guest-security/trusted-macs.txt
WANT="aa:bb:cc:dd:ee:ff aa:bb:cc:dd:ee:ff"

echo "=== trusted-macs fix ==="
date

mkdir -p "$(dirname "$TRUST")"
touch "$TRUST"
BK="${TRUST}.bak-$(date +%Y%m%d-%H%M%S)"
cp "$TRUST" "$BK"
echo "  backup: $BK"

echo
echo "--- before ---"
sed 's/^/    /' "$TRUST"

echo
echo "--- what the device actually presents right now ---"
printf "    assoclist: "
iwinfo wlan2 assoclist 2>/dev/null | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' \
    | grep -i '91:95' | head -1 | tr 'A-Z' 'a-z' || echo "(not associated)"
printf "    arp/neigh: "
ip neigh show 192.168.2.250 2>/dev/null | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' \
    | head -1 | tr 'A-Z' 'a-z' || echo "(no entry)"

echo
echo "--- adding ---"
added=0
for m in $WANT; do
    if grep -qi "^${m}\$" "$TRUST"; then
        echo "    $m already present"
    else
        echo "$m" >> "$TRUST"
        echo "    $m ADDED"
        added=$((added + 1))
    fi
done

echo
echo "--- after ---"
sed 's/^/    /' "$TRUST"

echo
echo "--- verify against the running device ---"
ok=1
for m in $WANT; do
    printf "    %s : " "$m"
    if grep -qi "^${m}\$" "$TRUST"; then
        echo "trusted"
    else
        echo "MISSING"
        ok=0
    fi
done

# guest-reauth lowercases before comparing, so a stray uppercase entry would
# never match. Check rather than assume the file is uniform.
if grep -qE '[A-F]' "$TRUST"; then
    echo
    echo "    WARNING: file contains uppercase hex. guest-reauth lowercases"
    echo "    the MAC before comparing, so those entries can never match."
    grep -nE '[A-F]' "$TRUST" | sed 's/^/      /'
fi

if [ "$ok" != "1" ]; then
    echo "  FAILED - restoring backup"
    cp "$BK" "$TRUST"
    exit 1
fi

echo
echo "=== done: $added entry(ies) added ==="
echo "No service restart needed - guest-reauth reads this file on each run."
