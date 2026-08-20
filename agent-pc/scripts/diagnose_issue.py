#!/usr/bin/env python3
"""Phase 3: Diagnose router issues and map to remediation playbooks."""
import json
import os
from datetime import datetime

TELEMETRY_FILE = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")
DIAGNOSTICS_LOG = os.path.expanduser("~/network-agent/logs/diagnostics.jsonl")

HANDSHAKE_WARNING_SEC = 190
HANDSHAKE_CRITICAL_SEC = 3600

def get_latest_record():
    if not os.path.exists(TELEMETRY_FILE):
        return None
    with open(TELEMETRY_FILE, 'r') as f:
        lines = f.readlines()
    if not lines:
        return None
    return json.loads(lines[-1])

def parse_tunnel_handshakes(tunnels_text):
    result = {}
    if not tunnels_text or 'ERROR' in str(tunnels_text):
        return result
    for line in str(tunnels_text).strip().split('\n'):
        if '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 3:
                try:
                    result[parts[0]] = int(parts[2])
                except (ValueError, IndexError):
                    pass
    return result

def diagnose(record):
    issues = []
    if not record:
        return {
            'issues': [], 'summary': 'No telemetry data available',
            'requires_action': False, 'escalation_level': 3,
            'recommended_action': 'Check telemetry collection pipeline'
        }
    current_time = int(datetime.now().timestamp())
    tunnel_handshakes = parse_tunnel_handshakes(record.get('tunnels', ''))
    for tunnel_name, handshake_ts in tunnel_handshakes.items():
        handshake_age = current_time - handshake_ts
        if handshake_age > HANDSHAKE_CRITICAL_SEC:
            issues.append({
                'issue_type': 'tunnel_down', 'severity': 'critical',
                'evidence': f"Tunnel {tunnel_name} no handshake in {handshake_age}s ({handshake_age//60} min)",
                'playbook_id': 'PB-WG-002', 'escalation_level': 3,
                'parameters': {'tunnel_name': tunnel_name, 'handshake_age_sec': handshake_age}
            })
        elif handshake_age > HANDSHAKE_WARNING_SEC:
            issues.append({
                'issue_type': 'tunnel_down', 'severity': 'warning',
                'evidence': f"Tunnel {tunnel_name} no handshake in {handshake_age}s ({handshake_age//60} min)",
                'playbook_id': 'PB-WG-001', 'escalation_level': 2,
                'parameters': {'tunnel_name': tunnel_name, 'handshake_age_sec': handshake_age}
            })
    lb_state = record.get('lb_state', '')
    if lb_state not in ['11', '10', '0'] and lb_state != 'FILE_NOT_FOUND':
        issues.append({
            'issue_type': 'lb_degraded', 'severity': 'warning',
            'evidence': f"Load balancer unexpected state: {lb_state}",
            'playbook_id': 'PB-LB-001', 'escalation_level': 2,
            'parameters': {'current_state': lb_state}
        })
    max_escalation = max([i['escalation_level'] for i in issues]) if issues else 0
    if not issues:
        summary = 'All systems operational'
        requires_action = False
        recommended_action = 'Continue monitoring'
    else:
        cc = len([i for i in issues if i['severity'] == 'critical'])
        wc = len([i for i in issues if i['severity'] == 'warning'])
        summary = f"{len(issues)} anomalies ({cc} critical, {wc} warning)"
        requires_action = True
        if max_escalation == 3:
            recommended_action = 'Manual intervention required'
        elif max_escalation == 2:
            recommended_action = 'Approval required before remediation'
        else:
            recommended_action = 'Safe for autonomous execution'
    diagnosis = {
        'timestamp': datetime.now().isoformat(), 'issues': issues,
        'summary': summary, 'requires_action': requires_action,
        'escalation_level': max_escalation,
        'recommended_action': recommended_action,
        'telemetry_snapshot': {
            'wan1_ip': record.get('wan1_ip', 'N/A'),
            'tunnel_count': len(tunnel_handshakes),
            'lb_state': record.get('lb_state', 'N/A')
        }
    }
    with open(DIAGNOSTICS_LOG, 'a') as f:
        f.write(json.dumps(diagnosis) + '\n')
    return diagnosis

def main():
    record = get_latest_record()
    diagnosis = diagnose(record)
    print(f"[{diagnosis['timestamp']}] Diagnosis: {diagnosis['summary']}")
    print(f"  Escalation: {diagnosis['escalation_level']} | Action: {diagnosis['requires_action']}")
    for issue in diagnosis['issues']:
        print(f"  [{issue['severity'].upper()}] {issue['issue_type']}: {issue['evidence']}")

if __name__ == "__main__":
    main()
