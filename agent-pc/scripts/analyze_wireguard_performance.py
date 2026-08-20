#!/usr/bin/env python3
import json, os
from datetime import datetime

TELEMETRY_FILE = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")
PROPOSALS_LOG = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
POOL_FILE = os.path.expanduser("~/network-agent/config/wg-server-pool.conf")

# A percentage alone is meaningless on a small number. wgclient's measured
# standard deviation is 9.0ms, so the old ">20%" rule fired at 4.4ms - below
# half the tunnel's own noise. Over 6.9 days of real telemetry that rule would
# have produced 20.2 alerts/day on wgclient and 9.9/day on wg2.
#
# Requiring BOTH a percentage AND an absolute margin, sustained across two
# consecutive samples, gives 1.0/day and 0.4/day against the same data while
# still catching the genuine events (wgclient +181%/40ms, wg2 +74%/27ms).
LATENCY_THRESHOLD_PCT = 30
LATENCY_THRESHOLD_MS = 20      # absolute floor - the fix that matters most
SUSTAIN_SAMPLES = 2            # one spike is weather, two is a trend
LOOKBACK_RECORDS = 100

def load_pool():
    pool = {}
    try:
        with open(POOL_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 3:
                        pool[parts[1]] = (parts[0], parts[2])
    except FileNotFoundError: pass
    return pool

def get_latest_records(n=LOOKBACK_RECORDS):
    if not os.path.exists(TELEMETRY_FILE): return []
    with open(TELEMETRY_FILE) as f:
        return [json.loads(l) for l in f.readlines()[-n:] if l.strip()]

def calc_baseline(records, tunnel, exclude_last=0):
    """Baseline EXCLUDING the samples being judged.

    The previous version included the current reading in the mean it was
    compared against, which drags the baseline toward the spike and understates
    every excursion. Small effect at 100 records, but it is the same class of
    bug as the rest of this file: a number that had to track something and did
    not.
    """
    vals = [r.get(tunnel+"_latency_ms") for r in records if r.get(tunnel+"_latency_ms")]
    if exclude_last:
        vals = vals[:-exclude_last]
    if len(vals) < 5: return None, None
    avg = sum(vals)/len(vals)
    var = sum((x-avg)**2 for x in vals)/len(vals)
    return avg, var**0.5

def analyze(records):
    proposals = []
    pool = load_pool()
    if not records: return proposals
    latest = records[-1]
    now = datetime.now()
    for tunnel in ["wgclient", "wg2"]:
        baseline, sigma = calc_baseline(records, tunnel,
                                        exclude_last=SUSTAIN_SAMPLES)
        if not baseline: continue
        recent = [r.get(tunnel+"_latency_ms")
                  for r in records[-SUSTAIN_SAMPLES:]
                  if r.get(tunnel+"_latency_ms")]
        if len(recent) < SUSTAIN_SAMPLES: continue
        current = latest.get(tunnel+"_latency_ms")
        if not current: continue

        def _bad(v):
            # Both tests must pass. The percentage catches proportional
            # degradation on a fast tunnel; the millisecond floor stops a
            # 5ms wobble on a 22ms tunnel from being called a 23% outage.
            return (v > baseline * (1 + LATENCY_THRESHOLD_PCT/100)
                    and (v - baseline) >= LATENCY_THRESHOLD_MS)

        if baseline > 0 and all(_bad(v) for v in recent):
            excess = ((current - baseline)/baseline)*100
            proposal_id = f"P{now.strftime('%m%d%H%M')}WG-{tunnel}"
            proposals.append({"proposal_id": proposal_id, "timestamp": now.isoformat(), "anomaly_type": "performance_degradation", "component": tunnel, "severity": 2, "details": f"{tunnel.upper()} latency elevated: {current:.1f}ms vs baseline {baseline:.1f}ms (+{excess:.0f}%)", "recommended_action": f"Run wg-rotate {tunnel} --force to switch to better peer", "status": "pending"})
    return proposals

def save_proposals(proposals):
    if not proposals: return
    with open(PROPOSALS_LOG, "a") as f:
        for p in proposals: f.write(json.dumps(p)+"\n")

def main():
    records = get_latest_records()
    if len(records) < LOOKBACK_RECORDS//2:
        print(f"[{datetime.now().isoformat()}] Insufficient data ({len(records)} records)")
        return
    proposals = analyze(records)
    save_proposals(proposals)
    if proposals:
        for p in proposals: print(f"[{p['timestamp']}] Proposal: {p['proposal_id']} - {p['details']}")
    else:
        print(f"[{datetime.now().isoformat()}] No performance issues detected.")

if __name__ == "__main__": main()
