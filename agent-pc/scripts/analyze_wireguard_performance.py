#!/usr/bin/env python3
import json, os
from datetime import datetime

TELEMETRY_FILE = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")
PROPOSALS_LOG = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
POOL_FILE = os.path.expanduser("~/network-agent/config/wg-server-pool.conf")

LATENCY_THRESHOLD_PCT = 20
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

def calc_baseline(records, tunnel):
    latencies = [r.get(tunnel+"_latency_ms") for r in records if r.get(tunnel+"_latency_ms")]
    if len(latencies) < 5: return None, None
    avg = sum(latencies)/len(latencies)
    var = sum((x-avg)**2 for x in latencies)/len(latencies)
    return avg, var**0.5

def analyze(records):
    proposals = []
    pool = load_pool()
    if not records: return proposals
    latest = records[-1]
    now = datetime.now()
    for tunnel in ["wgclient", "wg2"]:
        baseline, _ = calc_baseline(records, tunnel)
        if not baseline: continue
        current = latest.get(tunnel+"_latency_ms")
        if not current: continue
        if baseline > 0 and current > baseline * (1 + LATENCY_THRESHOLD_PCT/100):
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
