#!/usr/bin/env python3
"""Phase 2: Anomaly detection + LLM narrative analysis."""
import requests
import json
import os
import re
import time
from datetime import datetime

TELEMETRY_FILE = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")
ANALYSIS_LOG = os.path.expanduser("~/network-agent/logs/analyses.jsonl")
PROPOSALS_LOG = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"  # switched 2026-07-28 after benchmark: qwen2.5:1.5b reported a Unix timestamp as an IP address and raw seconds as "527578 days". See logs/model_bench.json

# Anomaly thresholds
TUNNEL_STALE_S = 180
TUNNEL_DOWN_S = 300


def get_latest_records(n=10):
    if not os.path.exists(TELEMETRY_FILE):
        return []
    with open(TELEMETRY_FILE, 'r') as f:
        lines = f.readlines()
    return [json.loads(line) for line in lines[-n:]]


def parse_tunnels(tunnels_str):
    """Parse 'wg2\t<pubkey>\t<epoch>' lines into structured data."""
    tunnels = []
    now = time.time()
    for line in tunnels_str.strip().split('\n'):
        if not line.strip() or line.startswith('ERROR'):
            continue
        parts = line.split('\t')
        if len(parts) >= 3:
            name = parts[0]
            try:
                last_hs = int(parts[2])
                age = int(now - last_hs)
            except ValueError:
                last_hs = 0
                age = 999999
            tunnels.append({"name": name, "last_handshake": last_hs, "age_seconds": age})
    return tunnels


def parse_wan_ip(raw):
    m = re.search(r'inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)', raw)
    return m.group(1) if m else raw.strip()


def safe_float(val, default=0):
    try:
        return float(val.split()[0])
    except (ValueError, IndexError, AttributeError):
        return default


def detect_anomalies(records):
    """Rule-based detection. Returns list of anomaly dicts."""
    anomalies = []
    if not records:
        return anomalies

    latest = records[-1]

    # 1 — Tunnel staleness / down (traffic-aware proposals)
    tunnels = parse_tunnels(latest.get('tunnels', ''))
    down_tunnels = [t for t in tunnels if t['age_seconds'] > TUNNEL_DOWN_S]
    active_tunnels = [t for t in tunnels if t['age_seconds'] <= TUNNEL_STALE_S]

    if down_tunnels and not active_tunnels:
        # All tunnels down — critical
        for t in down_tunnels:
            anomalies.append({
                "type": "tunnel_down",
                "severity": 3,
                "component": t['name'],
                "details": f"Tunnel {t['name']} down — no handshake in {t['age_seconds']}s ({t['age_seconds']//60} min). No alternate tunnels available.",
                "proposal_action": "Manual intervention required — all tunnels down, no redundancy available."
            })
    elif down_tunnels:
        # Some tunnels down, others active — traffic shift proposal
        active_names = ", ".join(t['name'] for t in active_tunnels)
        for t in down_tunnels:
            anomalies.append({
                "type": "tunnel_down",
                "severity": 2,
                "component": t['name'],
                "details": f"Tunnel {t['name']} down — no handshake in {t['age_seconds']}s ({t['age_seconds']//60} min). Alternate tunnels active: {active_names}",
                "proposal_action": f"Shift 100% traffic to {active_names} — {t['name']} is down, rely on redundancy"
            })

    for t in tunnels:
        if TUNNEL_STALE_S < t['age_seconds'] <= TUNNEL_DOWN_S:
            anomalies.append({
                "type": "tunnel_stale",
                "severity": 1,
                "component": t['name'],
                "details": f"Tunnel {t['name']} stale — last handshake {t['age_seconds']}s ago",
                "proposal_action": None
            })

    # 2 — WAN failover (IP changed between polls)
    if len(records) >= 2:
        cur_ip = parse_wan_ip(latest.get('wan1_ip', ''))
        for prev in reversed(records[:-1]):
            prev_ip = parse_wan_ip(prev.get('wan1_ip', ''))
            if prev_ip and prev_ip != cur_ip and 'ERROR' not in prev_ip:
                anomalies.append({
                    "type": "wan_failover",
                    "severity": 2,
                    "component": "wan1",
                    "details": f"WAN IP changed {prev_ip} → {cur_ip} — possible failover",
                    "proposal_action": "Verify primary WAN. Check if failover was expected."
                })
                break

    # 3 — Load balancer state change
    if len(records) >= 2:
        cur_lb = str(latest.get('lb_state', '')).strip()
        prev_lb = str(records[-2].get('lb_state', '')).strip()
        if cur_lb and prev_lb and cur_lb != prev_lb \
                and 'ERROR' not in cur_lb and 'ERROR' not in prev_lb \
                and 'FILE_NOT_FOUND' not in cur_lb:
            anomalies.append({
                "type": "lb_state_change",
                "severity": 1,
                "component": "load_balancer",
                "details": f"LB state {prev_lb} → {cur_lb}",
                "proposal_action": None
            })

    # 4 — Router reboot (uptime decreased)
    if len(records) >= 2:
        cur_up = safe_float(latest.get('uptime', '0'))
        prev_up = safe_float(records[-2].get('uptime', '0'))
        if cur_up < prev_up and prev_up > 0:
            anomalies.append({
                "type": "uptime_reset",
                "severity": 2,
                "component": "router",
                "details": f"Router rebooted — uptime {prev_up:.0f}s → {cur_up:.0f}s",
                "proposal_action": "Investigate reboot cause. Check router logs. Verify service recovery."
            })

    # 5 — Router unreachable (all SSH commands errored)
    fields = [latest.get('wan1_ip', ''), latest.get('tunnels', ''), latest.get('lb_state', '')]
    if all('ERROR' in str(f) for f in fields):
        anomalies.append({
            "type": "router_unreachable",
            "severity": 3,
            "component": "router",
            "details": "Router unreachable — all SSH commands returned errors",
            "proposal_action": "Physical inspection required. Check power, cables, router status."
        })

    return anomalies


def generate_proposals(anomalies):
    """Create proposals for Level 2+ anomalies."""
    proposals = []
    ts = datetime.now()
    for i, a in enumerate(anomalies, 1):
        if a['severity'] >= 2 and a.get('proposal_action'):
            proposals.append({
                "proposal_id": f"P{ts.strftime('%m%d%H%M')}{i}",
                "timestamp": ts.isoformat(),
                "anomaly_type": a['type'],
                "component": a['component'],
                "severity": a['severity'],
                "details": a['details'],
                "recommended_action": a['proposal_action'],
                "status": "pending"
            })
    return proposals


def save_proposals(proposals):
    if not proposals:
        return
    with open(PROPOSALS_LOG, 'a') as f:
        for p in proposals:
            f.write(json.dumps(p) + '\n')


def dedupe(text):
    text = re.sub(r'\b(\w+)\s+\1\b', r'\1', text)
    text = re.sub(r'\b(\w{2,})\s+(\w+)\b',
                 lambda m: m.group(2) if m.group(2).startswith(m.group(1)) else m.group(0), text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def decode_lb_state(raw):
    """Translate the wg-lb state code into prose.

    The watchdog writes one digit per tunnel: position 1 = wgclient,
    position 2 = wg2; 1 = up, 0 = down. Passing the bare code to an LLM
    invites it to read "11" as a quantity, which is exactly what happened.
    """
    v = str(raw).strip()
    names = ["wgclient", "wg2"]
    if len(v) == 2 and all(c in "01" for c in v):
        parts = ["%s=%s" % (n, "UP" if c == "1" else "DOWN")
                 for n, c in zip(names, v)]
        both = "both tunnels UP" if v == "11" else (
               "BOTH TUNNELS DOWN" if v == "00" else "one tunnel DOWN")
        return "%s (%s)" % (both, ", ".join(parts))
    return "unknown state code %r" % v


def format_context(anomalies, data):
    ctx = f"""Router Telemetry:
- WAN IP: {data['wan_ip']}
- WireGuard tunnels: {data['tunnel_count']} active
- Load balancer: {decode_lb_state(data['lb_state'])}
- Uptime: {data['uptime_human']}

Anomaly Detection:
"""
    if anomalies:
        for a in anomalies:
            label = {1: "LOW", 2: "MODERATE", 3: "CRITICAL"}[a['severity']]
            ctx += f"- [{label}] {a['component']}: {a['details']}\n"
    else:
        ctx += "- No anomalies. All systems nominal.\n"
    return ctx


def ask_ollama(context):
    prompt = f"""You are a network monitoring agent. Based on these findings, write a brief summary.

GROUND RULES (do not violate):
- This router has EXACTLY TWO WireGuard interfaces: wgclient and wg2. Never name any other interface.
- Uptime is time since last boot. An uptime under 1 hour means the router recently rebooted, which is noteworthy.
- Do not invent numbers, units, or rates. Use only values given above. Byte counters are cumulative totals, NOT per-second rates.
- If a value is not present above, say so rather than estimating.

{context}

Respond in this exact format:
STATUS: <HEALTHY or WARNING or CRITICAL>
SUMMARY: <2-3 sentences>
ACTION: <recommended action or "No action needed">
"""
    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "repeat_penalty": 1.15}
        }, timeout=120)
        return dedupe(resp.json().get('response', ''))
    except Exception as e:
        return f"LLM unavailable: {e}"


def main():
    records = get_latest_records(10)
    if not records:
        print(f"[{datetime.now().isoformat()}] No telemetry data.")
        return

    latest = records[-1]
    wan_ip = parse_wan_ip(latest.get('wan1_ip', 'N/A'))
    tunnels = parse_tunnels(latest.get('tunnels', ''))
    lb_state = str(latest.get('lb_state', 'N/A')).strip()
    uptime_s = safe_float(latest.get('uptime', '0'))

    data = {
        "wan_ip": wan_ip,
        "tunnel_count": len(tunnels),
        "lb_state": lb_state,
        "uptime_human": f"{uptime_s/86400:.1f} days" if uptime_s else "N/A"
    }

    anomalies = detect_anomalies(records)
    proposals = generate_proposals(anomalies)
    save_proposals(proposals)

    context = format_context(anomalies, data)
    llm_analysis = ask_ollama(context)

    if any(a['severity'] == 3 for a in anomalies):
        status = "CRITICAL"
    elif any(a['severity'] >= 2 for a in anomalies):
        status = "WARNING"
    else:
        status = "HEALTHY"

    record = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": status,
        "anomalies": anomalies,
        "proposals_generated": [p['proposal_id'] for p in proposals],
        "llm_analysis": llm_analysis,
        "telemetry_summary": data
    }

    with open(ANALYSIS_LOG, 'a') as f:
        f.write(json.dumps(record) + '\n')

    print(f"[{record['timestamp']}] Analysis logged — Status: {status}")
    if anomalies:
        for a in anomalies:
            print(f"  [{a['severity']}] {a['type']}: {a['details']}")
    if proposals:
        print(f"  Proposals: {len(proposals)} written to proposals.jsonl")


if __name__ == "__main__":
    main()
