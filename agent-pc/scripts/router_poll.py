#!/usr/bin/env python3
import subprocess, json, os, re
from datetime import datetime

LOG_FILE = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")

def ssh_command(cmd):
    """Execute command via SSH key (using existing b3000 host config)."""
    result = subprocess.run(["ssh", "b3000", cmd], capture_output=True, text=True, timeout=15)
    return result.stdout.strip() if result.returncode == 0 else f"ERROR: {result.stderr.strip()}"

def parse_ping_rtt(output):
    m = re.search(r"round-trip.*?(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)", output)
    return float(m.group(2)) if m else None

def parse_uptime(raw):
    """Parse /proc/uptime, which is '<uptime_seconds> <idle_seconds>'.

    Storing the raw two-number string caused the analysis model to read it
    as "X days and Y hours" and broke reboot detection. Return explicit,
    separately-named fields so neither a human nor a model has to guess.
    """
    try:
        parts = str(raw).split()
        up = float(parts[0])
        idle = float(parts[1]) if len(parts) > 1 else None
    except (ValueError, IndexError, TypeError):
        return None, None, None
    total = int(up)
    d, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    return up, idle, "%dd %dh %dm" % (d, h, m)


def collect_telemetry():
    timestamp = datetime.now().isoformat()
    wan1_ip = ssh_command("ifconfig eth1.1 | grep 'inet '")
    tunnels = ssh_command("wg show all latest-handshakes")
    lb_state = ssh_command("cat /tmp/wg-lb-state 2>/dev/null || echo 'FILE_NOT_FOUND'")
    wan_monitor_last = ssh_command("tail -1 /tmp/wan-monitor.csv 2>/dev/null || echo 'FILE_NOT_FOUND'")
    uptime_raw = ssh_command("cat /proc/uptime")
    uptime_seconds, idle_seconds, uptime_human = parse_uptime(uptime_raw)
    wgclient_latency_raw = ssh_command("ping -c 3 -W 2 9.9.9.9 2>/dev/null | grep 'round-trip'")
    wg2_latency_raw = ssh_command("ping -c 3 -W 2 149.112.112.112 2>/dev/null | grep 'round-trip'")
    wgclient_transfer = ssh_command("wg show wgclient transfer")
    wg2_transfer = ssh_command("wg show wg2 transfer")
    wgclient_endpoint = ssh_command("wg show wgclient endpoints")
    wg2_endpoint = ssh_command("wg show wg2 endpoints")
    return {"timestamp": timestamp, "wan1_ip": wan1_ip, "tunnels": tunnels, "lb_state": lb_state, "wan_monitor_last": wan_monitor_last, "uptime": uptime_raw, "uptime_seconds": uptime_seconds, "idle_seconds": idle_seconds, "uptime_human": uptime_human, "wgclient_latency_ms": parse_ping_rtt(wgclient_latency_raw), "wg2_latency_ms": parse_ping_rtt(wg2_latency_raw), "wgclient_transfer": wgclient_transfer, "wg2_transfer": wg2_transfer, "wgclient_endpoint": wgclient_endpoint, "wg2_endpoint": wg2_endpoint}

def main():
    telemetry = collect_telemetry()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(telemetry) + "\n")
    print(f"[{telemetry['timestamp']}] Telemetry logged.")

if __name__ == "__main__": main()
