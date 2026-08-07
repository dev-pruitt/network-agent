#!/usr/bin/env python3
"""Network Agent Dashboard API - Phase 3"""
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from functools import wraps
import json
import subprocess
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime, timedelta

app = Flask(__name__, template_folder='templates', static_folder='static')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

LOGS = Path('/home/agent/network-agent/logs')
CONFIG = Path('/home/agent/network-agent/config')

# ---------------------------------------------------------------------------
# Credentials. Never literals in source - this file is published.
#
# A fixed secret_key is the sharp edge: it lets anyone holding it forge a
# signed session cookie and bypass the login form completely. So this loads
# fail closed. Missing file, missing key, or a leftover default value all
# abort at import rather than silently falling back to something known.
# ---------------------------------------------------------------------------
_CONF = Path(__file__).resolve().parent.parent / 'config' / 'dashboard.conf'
# 'admin' is a perfectly normal USERNAME - the same bug this project keeps
# finding elsewhere: a check applied uniformly to fields that do not mean the
# same thing. Username only needs to be non-empty. Password and secret_key
# are the fields that must not be a known/default value.
_WEAK_SECRETS = {'changeme', 'password', 'admin', 'dashboard-secret-key-change-this', ''}


def _load_credentials(path):
    if not path.exists():
        sys.exit(f"FATAL: {path} missing. Run fix_dashboard_auth.py.")
    conf = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, _, v = line.partition('=')
            conf[k.strip()] = v.strip()
    if not conf.get('username', '').strip():
        sys.exit(f"FATAL: {path} has a blank 'username'. Refusing to start.")
    for key in ('password', 'secret_key'):
        val = conf.get(key, '')
        if val.lower() in _WEAK_SECRETS:
            sys.exit(f"FATAL: {path} has a default/blank '{key}'. Refusing to start.")
    return conf


_CREDS = _load_credentials(_CONF)
app.secret_key = _CREDS['secret_key']
USERNAME = _CREDS['username']
PASSWORD = _CREDS['password']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def read_jsonl(path, last_n=10):
    if not path.exists():
        return []
    lines = path.read_text().strip().splitlines()
    return [json.loads(l) for l in lines[-last_n:] if l.strip()]

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials'), 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/logs')
@login_required
def logs_view():
    return render_template('logs.html')

@app.route('/proposals')
@login_required
def proposals_view():
    return render_template('proposals.html')

@app.route('/wireguard')
@login_required
def wireguard_view():
    return render_template('wireguard.html')

@app.route('/servers')
@login_required
def servers_view():
    return render_template('servers.html')

@app.route('/health')
@login_required
def health_view():
    return render_template('health.html')


@app.route('/api/telemetry/history')
def telemetry_history():
    """Return last 200 telemetry entries with latency data for charting."""
    history = []
    try:
        logfile = os.path.expanduser('~/network-agent/logs/router_telemetry.jsonl')
        with open(logfile) as f:
            lines = f.readlines()[-200:]
        for line in lines:
            d = json.loads(line.strip())
            if d.get('wgclient_latency_ms') or d.get('wg2_latency_ms'):
                history.append({
                    'timestamp': d['timestamp'],
                    'wgclient_latency_ms': d.get('wgclient_latency_ms'),
                    'wg2_latency_ms': d.get('wg2_latency_ms')
                })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify(history)

@app.route('/api/telemetry/latest')
@login_required
def telemetry_latest():
    return jsonify(read_jsonl(LOGS / 'router_telemetry.jsonl', 10))

@app.route('/api/diagnostics/latest')
@login_required
def diagnostics_latest():
    data = read_jsonl(LOGS / 'diagnostics.jsonl', 1)
    return jsonify(data[0] if data else {})

@app.route('/api/actions/history')
@login_required
def actions_history():
    return jsonify(read_jsonl(LOGS / 'actions.jsonl', 50))

@app.route('/api/proposals/pending')
@login_required
def proposals_pending():
    return jsonify(read_jsonl(LOGS / 'proposals.jsonl', 50))

@app.route('/api/proposals/decide')
@login_required
def proposals_decide():
    pid = request.args.get('pid')
    decision = request.args.get('decision')
    if not pid or decision not in ('approved', 'denied'):
        return jsonify({'error': 'Invalid parameters'}), 400
    proposals_path = LOGS / 'proposals.jsonl'
    if not proposals_path.exists():
        return jsonify({'error': 'Proposals file not found'}), 404
    lines = proposals_path.read_text().strip().splitlines()
    updated = False
    for i, line in enumerate(lines):
        entry = json.loads(line)
        if entry.get('proposal_id') == pid:
            entry['status'] = decision
            lines[i] = json.dumps(entry)
            updated = True
            break
    if updated:
        proposals_path.write_text('\n'.join(lines) + '\n')
        approval_entry = {
            'timestamp': datetime.now().isoformat(),
            'proposal_id': pid,
            'decision': decision,
            'channel': 'dashboard',
            'approver': 'admin'
        }
        with open(LOGS / 'approvals.jsonl', 'a') as f:
            f.write(json.dumps(approval_entry) + '\n')
        return jsonify({'status': 'success', 'pid': pid, 'decision': decision})
    return jsonify({'error': 'Proposal not found'}), 404

@app.route('/api/tcl/status')
@login_required
def tcl_status():
    data = read_jsonl(LOGS / 'tcl_monitor.jsonl', 1)
    return jsonify(data[0] if data else {})

@app.route('/api/wireguard/status')
@login_required
def wireguard_status():
    try:
        result = subprocess.run(['ssh', 'b3000', 'wg show'], capture_output=True, text=True, timeout=5)
        return jsonify({'raw': result.stdout, 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/server-pool/list')
@login_required
def server_pool_list():
    pool_path = CONFIG / 'wg-server-pool.conf'
    if not pool_path.exists():
        return jsonify([])
    servers = []
    for line in pool_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 3:
            servers.append({'name': parts[0], 'endpoint': parts[1], 'pubkey': parts[2]})
    return jsonify(servers)

@app.route('/api/system/health')
@login_required
def system_health():
    try:
        # CPU usage
        with open('/proc/stat', 'r') as f:
            cpu_line1 = f.readline()
        import time
        time.sleep(0.1)
        with open('/proc/stat', 'r') as f:
            cpu_line2 = f.readline()

        def parse_cpu(line):
            parts = line.split()[1:]
            return [int(x) for x in parts[:4]]

        c1 = parse_cpu(cpu_line1)
        c2 = parse_cpu(cpu_line2)
        total1 = sum(c1)
        total2 = sum(c2)
        idle1 = c1[3]
        idle2 = c2[3]
        cpu_percent = round(((total2 - total1) - (idle2 - idle1)) / (total2 - total1) * 100, 1) if total2 > total1 else 0

        # Memory
        mem_info = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = int(parts[1].strip().split()[0])
                    mem_info[key] = val

        mem_total = mem_info.get('MemTotal', 0)
        mem_available = mem_info.get('MemAvailable', 0)
        mem_used = mem_total - mem_available
        mem_percent = round(mem_used / mem_total * 100, 1) if mem_total > 0 else 0

        # Disk
        disk = shutil.disk_usage('/')
        disk_percent = round(disk.used / disk.total * 100, 1)

        # Uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])

        # Systemd timers status
        timers_result = subprocess.run(
            ['systemctl', 'list-timers', '--all', '--no-pager', '--output=json'],
            capture_output=True, text=True, timeout=5
        )
        timers = []
        try:
            raw_timers = json.loads(timers_result.stdout)
            for t in raw_timers:
                if 'network' in t.get('activates', '').lower():
                    timers.append({
                        'name': t.get('activates', ''),
                        'next_run': t.get('next_elapse', ''),
                        'last_run': t.get('last_activation', '')
                    })
        except Exception:
            pass

        # Ollama status
        ollama_ok = False
        try:
            r = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 'http://localhost:11434/api/tags'],
                             capture_output=True, text=True, timeout=3)
            ollama_ok = r.stdout.strip() == '200'
        except Exception:
            pass

        return jsonify({
            'cpu_percent': cpu_percent,
            'mem_total_mb': round(mem_total / 1024),
            'mem_used_mb': round(mem_used / 1024),
            'mem_percent': mem_percent,
            'disk_total_gb': round(disk.total / (1024**3), 1),
            'disk_used_gb': round(disk.used / (1024**3), 1),
            'disk_percent': disk_percent,
            'uptime_seconds': round(uptime_seconds),
            'uptime_human': str(timedelta(seconds=int(uptime_seconds))),
            'timers': timers,
            'ollama_status': 'online' if ollama_ok else 'offline',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actions/rotate')
@login_required
def action_rotate():
    tunnel = request.args.get('tunnel', 'wgclient')
    try:
        subprocess.run(['ssh', 'b3000', 'wg-rotate', tunnel, '--force'], timeout=30)
        return jsonify({'status': 'success', 'tunnel': tunnel})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actions/select-server')
@login_required
def action_select_server():
    server_name = request.args.get('server')
    if not server_name:
        return jsonify({'error': 'Server name required'}), 400
    try:
        pool_path = CONFIG / 'wg-server-pool.conf'
        if not pool_path.exists():
            return jsonify({'error': 'Pool file not found'}), 404
        servers = []
        for line in pool_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 3:
                servers.append({'name': parts[0], 'endpoint': parts[1], 'pubkey': parts[2]})
        target_idx = None
        for idx, srv in enumerate(servers):
            if srv['name'] == server_name:
                target_idx = idx
                break
        if target_idx is None:
            return jsonify({'error': 'Server not found'}), 404
        subprocess.run(['ssh', 'b3000', 'wg-rotate', 'wgclient', '--index', str(target_idx)], timeout=30)
        return jsonify({'status': 'success', 'server': server_name, 'index': target_idx})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actions/reboot')
@login_required
def action_reboot():
    confirm = request.args.get('confirm')
    if confirm != 'yes-i-sure':
        return jsonify({'error': 'Confirmation required'}), 400
    try:
        subprocess.run(['ssh', 'b3000', 'sudo', 'reboot'], timeout=5)
        return jsonify({'status': 'rebooting'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


import threading
import time as _time

def telemetry_watcher():
    """Background thread: push real-time updates to connected clients."""
    while True:
        try:
            latest = {}
            logfile = os.path.expanduser('~/network-agent/logs/router_telemetry.jsonl')
            with open(logfile) as f:
                lines = f.readlines()
            if lines:
                latest = json.loads(lines[-1].strip())
            socketio.emit('telemetry_update', {
                'wgclient_latency_ms': latest.get('wgclient_latency_ms'),
                'wg2_latency_ms': latest.get('wg2_latency_ms'),
                'timestamp': latest.get('timestamp'),
                'probe_ok': latest.get('probe_ok'),
                'uptime_human': latest.get('uptime_human')
            })
        except Exception:
            pass
        _time.sleep(30)

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'live'})

# Start background thread on first request
_watcher_started = False
@socketio.on('connect')
def start_watcher():
    global _watcher_started
    if not _watcher_started:
        t = threading.Thread(target=telemetry_watcher, daemon=True)
        t.start()
        _watcher_started = True


@app.route('/actions')
@login_required
def actions_view():
    return render_template('actions.html')


@app.route('/api/actions/overnight')
@login_required
def actions_overnight():
    """Actions inside a rolling window, plus current autonomy budget.

    Synthetic entries are excluded - actions.jsonl still carries one test row
    from 2026-07-26 that a prior audit annotated. It is not a real action and
    must never appear in a report or count against the budget.
    """
    try:
        hours = int(request.args.get('hours', 24))
    except (TypeError, ValueError):
        hours = 24
    hours = max(1, min(hours, 24 * 90))

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)
    day_cutoff = now - timedelta(hours=24)

    actions = []
    budget_used = 0
    path = LOGS / 'actions.jsonl'
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get('synthetic'):
                continue
            try:
                ts = datetime.fromisoformat(e['timestamp'])
            except (KeyError, ValueError):
                continue
            if ts > cutoff:
                actions.append(e)
            if (e.get('action_type') == 'tunnel_restart'
                    and e.get('autonomous') and ts > day_cutoff):
                budget_used += 1

    actions.sort(key=lambda a: a.get('timestamp', ''), reverse=True)
    return jsonify({
        'actions': actions,
        'hours': hours,
        'budget_used': budget_used,
        'budget_cap': 6,
    })


@app.route('/api/tailscale/status')
@login_required
def tailscale_status():
    """Remote-access state: local daemon plus the tailnet view from the API.

    Two sources deliberately. The local daemon knows whether the tunnel is up
    right now; only the API knows whether routes are approved and when keys
    expire. Reporting one without the other is how a node can look healthy
    while its route is unapproved - which is exactly what happened during the
    migration.
    """
    out = {'daemon': None, 'tailnet': None, 'error': None}

    try:
        r = subprocess.run(['tailscale', 'status', '--json'],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout:
            d = json.loads(r.stdout)
            s = d.get('Self', {})
            peers = [{
                'name': p.get('HostName'),
                'os': p.get('OS'),
                'online': p.get('Online'),
                'ip': (p.get('TailscaleIPs') or [None])[0],
                'rx': p.get('RxBytes', 0),
                'tx': p.get('TxBytes', 0),
            } for p in (d.get('Peer') or {}).values()]
            out['daemon'] = {
                'state': d.get('BackendState'),
                'ip': (s.get('TailscaleIPs') or [None])[0],
                'routes': s.get('PrimaryRoutes') or [],
                'exit_node': bool(s.get('ExitNodeOption')),
                'peers': peers,
            }
    except Exception as e:
        out['error'] = f'daemon: {type(e).__name__}'

    # Written by tailscale_poll.py. Absent or stale is reported as such rather
    # than silently rendering an empty panel.
    p = LOGS / 'tailscale_state.json'
    if p.exists():
        try:
            out['tailnet'] = json.loads(p.read_text())
        except Exception:
            out['tailnet'] = None

    return jsonify(out)


@app.route('/api/tunnels/reachability')
@login_required
def tunnel_reachability():
    """Last result from tunnel_reachability_probe.py.

    Returns age_seconds so the UI can say how old this is. The probe runs on a
    15-minute timer; rendering a stale result as current would be the same
    kind of lie this project keeps finding - a value that stopped tracking
    reality while everything downstream trusted it.
    """
    p = LOGS / 'tunnel_probe.jsonl'
    if not p.exists():
        return jsonify({'ok': False, 'error': 'probe has not run yet'})
    last = None
    try:
        for line in p.read_text().splitlines():
            if line.strip():
                last = line
        rec = json.loads(last) if last else None
    except Exception as e:
        return jsonify({'ok': False, 'error': f'{type(e).__name__}'})
    if not rec:
        return jsonify({'ok': False, 'error': 'no samples'})

    age = None
    try:
        age = int((datetime.now()
                   - datetime.fromisoformat(rec['timestamp'])).total_seconds())
    except Exception:
        pass
    rec['age_seconds'] = age
    rec['ok'] = True
    return jsonify(rec)


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
