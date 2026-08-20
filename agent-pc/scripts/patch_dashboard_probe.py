#!/usr/bin/env python3
"""Surface the tunnel reachability probe on the dashboard. Idempotent.

WHY IT NEEDS ITS OWN PANEL
  The Tunnels panel already shows handshake age and transfer. Both of those
  were healthy for the entire time wg2 was unusable - that is exactly how the
  fault survived. Showing this next to them without distinguishing it would
  repeat the mistake.

  So the panel states what it proves: packets crossed from the LAN into this
  tunnel. And when it fails it shows WHY, from the router reject counter -
  refused by the firewall, or lost in transit. Those need different fixes.

  Staleness is shown, not hidden. The probe runs every 15 minutes; a panel
  quietly rendering a two-hour-old result as current is the same class of lie
  as a hardcoded value that stopped tracking reality.
"""
import os
import shutil
from datetime import datetime

DASH = os.path.expanduser("~/network-agent-backup/dashboard")
API = os.path.join(DASH, "api.py")
IDX = os.path.join(DASH, "templates/index.html")
TS = datetime.now().strftime("%Y%m%d-%H%M%S")

ENDPOINT = '''
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

'''

PANEL_HTML = '''
<section>
  <div class="sec-head"><h2>Tunnel reachability</h2><span class="count" id="rp-sub"></span></div>
  <div class="panel" id="rp-panel"><div class="panel-pad dim">Loading&hellip;</div></div>
</section>
'''

PANEL_JS = '''
async function loadReach() {
  const host = document.getElementById('rp-panel');
  const sub = document.getElementById('rp-sub');
  if (!host) return;
  const d = await NA.get('/api/tunnels/reachability');

  if (!d || !d.ok) {
    sub.textContent = '';
    host.innerHTML = '<div class="empty"><div class="big">No probe result</div>' +
      '<div class="sm">' + NA.esc((d && d.error) || 'unavailable') + '</div></div>';
    return;
  }

  /* Say how old this is. The probe runs every 15 min; anything much past that
     means the timer stopped, and a panel that hides that is worse than blank. */
  const age = d.age_seconds;
  let stale = '';
  if (age !== null && age !== undefined) {
    const m = Math.round(age / 60);
    sub.textContent = m < 1 ? 'just now' : m + ' min ago';
    if (age > 2400) stale = '<div class="panel-pad" style="border-top:1px solid var(--border-soft);' +
      'color:var(--warn);font-size:13px">Last result is ' + m + ' min old &mdash; ' +
      'the probe runs every 15 min, so the timer may have stopped.</div>';
  }

  const r = d.results || {};
  const names = Object.keys(r).sort();
  if (!names.length) {
    host.innerHTML = '<div class="empty"><div class="big">No tunnels probed</div></div>';
    return;
  }

  let html = '<table class="data"><thead><tr><th>Tunnel</th><th>Probe target</th>' +
             '<th class="hide-sm">Result</th><th style="text-align:right">LAN reachable</th>' +
             '</tr></thead><tbody>';

  names.forEach(function (n) {
    const t = r[n];
    const pct = Math.round((t.rate || 0) * 100);
    const cls = pct === 0 ? 'crit' : (pct < 60 ? 'warn' : 'ok');
    const label = pct === 0 ? 'BLOCKED' : (pct < 60 ? 'DEGRADED' : 'YES');
    let detail = t.ok + '/' + (t.ok + t.refused + t.other) + ' connected';
    if (t.refused) detail += ', ' + t.refused + ' refused';
    if (t.other) detail += ', ' + t.other + ' timed out';
    html += '<tr><td>' + NA.esc(n) + '</td>' +
            '<td class="mono dim">' + NA.esc(t.target || '\\u2014') + '</td>' +
            '<td class="dim hide-sm">' + NA.esc(detail) + '</td>' +
            '<td style="text-align:right"><span class="badge ' + cls + '">' +
            label + ' ' + pct + '%</span></td></tr>';
  });
  html += '</tbody></table>';

  /* Attribution. A blocked tunnel and a dead tunnel look identical from the
     LAN; the router reject counter is what separates them, and they need
     different fixes. */
  const rd = d.forward_reject_delta;
  const anyBad = names.some(function (n) { return (r[n].rate || 0) < 0.6; });
  if (anyBad) {
    html += '<div class="panel-pad" style="border-top:1px solid var(--border-soft);font-size:13px">';
    if (rd && rd > 0) {
      html += '<span style="color:var(--warn)">Router rejected ' + rd +
              ' packet(s) during this probe &mdash; the firewall is refusing these, ' +
              'not the network dropping them. Check for a missing lan&rarr;tunnel forwarding rule.</span>';
    } else {
      html += '<span style="color:var(--warn)">Router reject counter did not move &mdash; ' +
              'packets left and nothing came back. Points at the tunnel peer or route, ' +
              'not the firewall.</span>';
    }
    html += '</div>';
  }

  if ((d.unpinned || []).length) {
    html += '<div class="panel-pad" style="border-top:1px solid var(--border-soft);' +
            'color:var(--dim);font-size:13px">Not covered by the probe: ' +
            NA.esc(d.unpinned.join(', ')) + ' (no pinned test destination)</div>';
  }

  host.innerHTML = html + stale;
}
'''


def patch_api():
    src = open(API).read()
    if '/api/tunnels/reachability' in src:
        print("  api.py: already patched")
        return
    shutil.copy(API, f"{API}.bak-probe-{TS}")
    marker = "if __name__ == '__main__':"
    if marker not in src:
        marker = 'if __name__ == "__main__":'
    head, sep, tail = src.partition(marker)
    open(API, "w").write(head.rstrip("\n") + "\n\n" + ENDPOINT + "\n" + sep + tail)
    print(f"  api.py: endpoint added (backup .bak-probe-{TS})")


def patch_index():
    src = open(IDX).read()
    if 'rp-panel' in src:
        print("  index.html: already patched")
        return
    shutil.copy(IDX, f"{IDX}.bak-probe-{TS}")

    # Sit directly above the Tunnels section: this answers "does traffic get
    # through", which is the question the handshake numbers below cannot.
    anchor = None
    for cand in ('<section>\n  <div class="sec-head"><h2>Remote access</h2>',
                 '<section>\n  <div class="sec-head"><h2>Server pool</h2>'):
        if cand in src:
            anchor = cand
            break
    if not anchor:
        raise SystemExit("FATAL: no anchor found in index.html; nothing changed.")
    src = src.replace(anchor, PANEL_HTML.strip() + "\n\n" + anchor, 1)

    hooked = False
    for cand in ("NA.poll(loadTailscale, 30000);", "NA.poll(load, 10000);"):
        if cand in src:
            src = src.replace(cand, PANEL_JS + "\n" + cand +
                              "\nNA.poll(loadReach, 60000);", 1)
            hooked = True
            break
    if not hooked:
        raise SystemExit("FATAL: no poll hook found; nothing changed.")

    open(IDX, "w").write(src)
    print(f"  index.html: panel added (backup .bak-probe-{TS})")


if __name__ == "__main__":
    print("=== dashboard reachability panel ===")
    patch_api()
    patch_index()
    import py_compile
    py_compile.compile(API, doraise=True)
    print("  api.py compiles OK")
