#!/usr/bin/env python3
"""Compare tunnel latency. Measure before changing the load balancer split.

Median and p90, not mean - one 2-second spike drags a mean and tells you
nothing about what a connection normally feels.

Splits all-time from last-24h because peers rotate: old samples describe
servers no longer in use.
"""
import json
import statistics as st
from datetime import datetime, timedelta

LOG = "/home/agent/network-agent/logs/router_telemetry.jsonl"
CUT = datetime.now() - timedelta(hours=24)
FIELDS = {"wg2": "wg2_latency_ms", "wgclient": "wgclient_latency_ms"}

alltime = {k: [] for k in FIELDS}
recent = {k: [] for k in FIELDS}
missing = {k: 0 for k in FIELDS}
missing_recent = {k: 0 for k in FIELDS}
total = 0

for line in open(LOG):
    try:
        d = json.loads(line)
        t = datetime.fromisoformat(d["timestamp"])
    except Exception:
        continue
    total += 1
    for k, f in FIELDS.items():
        v = d.get(f)
        if v is None:
            missing[k] += 1
            if t > CUT:
                missing_recent[k] += 1
            continue
        alltime[k].append(v)
        if t > CUT:
            recent[k].append(v)


def row(name, xs):
    if not xs:
        return f"  {name:9}  no data"
    q = sorted(xs)
    p = lambda f: q[max(0, int(len(q) * f) - 1)]
    return (f"  {name:9}  n={len(q):6}  median={st.median(q):6.1f}"
            f"  p90={p(0.90):6.1f}  p99={p(0.99):7.1f}")


print(f"total samples: {total}")
print()
print("ALL TIME")
for k in FIELDS:
    print(row(k, alltime[k]))
print()
print("LAST 24H")
for k in FIELDS:
    print(row(k, recent[k]))

print()
print("MISSING SAMPLES (ping returned nothing)")
for k in FIELDS:
    pct = 100.0 * missing[k] / total if total else 0
    rpct = (100.0 * missing_recent[k] / (len(recent[k]) + missing_recent[k])
            if (len(recent[k]) + missing_recent[k]) else 0)
    print(f"  {k:9}  all-time {missing[k]:5} ({pct:4.1f}%)"
          f"   last-24h {missing_recent[k]:4} ({rpct:4.1f}%)")

if recent["wg2"] and recent["wgclient"]:
    r = st.median(recent["wg2"]) / st.median(recent["wgclient"])
    print()
    print(f"  wg2 median is {r:.2f}x wgclient (last 24h)")
    print()
    # Cost of the current split, in expected added latency per connection.
    m1, m2 = st.median(recent["wgclient"]), st.median(recent["wg2"])
    for share in (0.0, 0.30, 0.50):
        blended = m1 * (1 - share) + m2 * share
        print(f"  {share:.0%} to wg2 -> blended median {blended:5.1f} ms"
              f"   ({blended - m1:+.1f} vs all-wgclient)")
