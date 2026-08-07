/* ==========================================================================
   Network Agent - shared client helpers.

   Consolidates logic that was previously copy-pasted (and diverging) across
   templates: the WireGuard parser existed only in wireguard.html, the theme
   toggle only in index.html, and every page reimplemented fetch + render.
   ========================================================================== */
(function () {
  'use strict';

  // ---- theme ------------------------------------------------------------
  // Applied in <head> before first paint, otherwise navigating between pages
  // flashes the default theme. See the inline boot script in _base.html.
  const NA = window.NA = window.NA || {};

  NA.setTheme = function (t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('na-theme', t); } catch (e) {}
    const b = document.getElementById('theme-btn');
    if (b) b.textContent = t === 'light' ? '◑' : '◐';
  };
  NA.toggleTheme = function () {
    const cur = document.documentElement.getAttribute('data-theme');
    NA.setTheme(cur === 'light' ? 'dark' : 'light');
  };

  // ---- escaping ---------------------------------------------------------
  NA.esc = function (s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  };

  // ---- time -------------------------------------------------------------
  NA.when = function (iso) {
    const d = new Date(iso);
    if (isNaN(d)) return NA.esc(iso);
    return d.toLocaleString(undefined,
      { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  NA.ago = function (iso) {
    const d = new Date(iso);
    if (isNaN(d)) return '';
    const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (s < 60)    return Math.round(s) + 's ago';
    if (s < 3600)  return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  };

  // ---- fetch ------------------------------------------------------------
  NA.get = function (url) {
    return fetch(url, { credentials: 'same-origin' })
      .then(function (r) {
        if (r.status === 401 || r.redirected && /\/login/.test(r.url)) {
          location.href = '/login'; throw new Error('auth');
        }
        return r.json();
      })
      .catch(function (e) { return { error: e.message || 'request failed' }; });
  };

  // ---- WireGuard parser -------------------------------------------------
  // `wg show` emits an interface block then its peer block. Splitting on blank
  // lines treats those as separate tunnels, which is why an early version of
  // the tunnels page reported four. Parse line by line and group instead.
  NA.parseWg = function (raw) {
    const out = [];
    let cur = null, inPeer = false;
    (raw || '').trim().split('\n').forEach(function (line) {
      if (line.startsWith('interface:')) {
        if (cur) out.push(cur);
        cur = { name: line.split(':')[1].trim(), port: '', endpoint: '',
                handshake: '', handshakeSec: null, rx: '', tx: '' };
        inPeer = false;
      } else if (line.startsWith('peer:')) {
        inPeer = true;
      } else if (cur) {
        if (line.includes('listening port:') && !inPeer)
          cur.port = line.split('port:')[1].trim();
        else if (line.includes('endpoint:'))
          cur.endpoint = line.split('endpoint:')[1].trim();
        else if (line.includes('latest handshake:')) {
          cur.handshake = line.split('handshake:')[1].trim();
          cur.handshakeSec = NA.handshakeSeconds(cur.handshake);
        } else if (line.includes('transfer:')) {
          const p = line.split('transfer:')[1].split(',');
          cur.rx = (p[0] || '').replace('received', '').trim();
          cur.tx = (p[1] || '').replace('sent', '').trim();
        }
      }
    });
    if (cur) out.push(cur);
    return out;
  };

  // "1 minute, 13 seconds ago" -> 73
  NA.handshakeSeconds = function (txt) {
    if (!txt || !/ago/.test(txt)) return null;
    let s = 0;
    const m = txt.match(/(\d+)\s*(day|hour|minute|second)/g) || [];
    m.forEach(function (part) {
      const n = parseInt(part, 10);
      if (/day/.test(part))    s += n * 86400;
      if (/hour/.test(part))   s += n * 3600;
      if (/minute/.test(part)) s += n * 60;
      if (/second/.test(part)) s += n;
    });
    return s;
  };

  // A tunnel is UP only if it actually handshook recently. The old dashboard
  // used `wg.raw ? '2/2 UP' : 'ERROR'`, which reported 2/2 UP whenever the
  // endpoint returned any text at all - both tunnels could be dead and it
  // would still show green. 190s matches wg-rotate's own health threshold.
  NA.HANDSHAKE_STALE_SEC = 190;
  NA.tunnelUp = function (t) {
    return t.handshakeSec !== null && t.handshakeSec < NA.HANDSHAKE_STALE_SEC;
  };

  // ---- status mapping ---------------------------------------------------
  NA.level = function (kind, v) {
    switch (kind) {
      case 'tunnels': return v.up === v.total && v.total > 0 ? 'ok'
                           : v.up === 0 ? 'crit' : 'warn';
      case 'pct':     return v < 60 ? 'ok' : v < 85 ? 'warn' : 'crit';
      case 'count0':  return v === 0 ? 'ok' : 'warn';   /* 0 is the good number */
      case 'sev':     return v >= 3 ? 'crit' : v === 2 ? 'warn' : 'ok';
      default:        return '';
    }
  };

  // ---- toasts (replaces alert(JSON.stringify(d))) -----------------------
  NA.toast = function (title, body, kind) {
    let host = document.getElementById('toasts');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toasts';
      document.body.appendChild(host);
    }
    const el = document.createElement('div');
    el.className = 'toast ' + (kind || '');
    el.innerHTML = '<div class="t-title">' + NA.esc(title) + '</div>' +
                   (body ? '<div class="t-body">' + NA.esc(body) + '</div>' : '');
    host.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity .3s'; el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 320);
    }, kind === 'crit' ? 9000 : 5200);
  };

  // ---- confirm + act ----------------------------------------------------
  NA.action = function (opts) {
    if (!confirm(opts.confirm)) return Promise.resolve(null);
    if (opts.confirm2 && !confirm(opts.confirm2)) return Promise.resolve(null);
    NA.toast(opts.pending || 'Working...', '', 'info');
    return NA.get(opts.url).then(function (d) {
      if (d.error) NA.toast(opts.failTitle || 'Failed', d.error, 'crit');
      else         NA.toast(opts.okTitle || 'Done', opts.okBody ? opts.okBody(d) : '', 'ok');
      if (opts.after) opts.after(d);
      return d;
    });
  };

  // ---- system-wide state pill ------------------------------------------
  NA.setSysState = function (level, text) {
    const el = document.getElementById('sysstate');
    if (!el) return;
    el.className = 'sysstate live ' + (level === 'ok' ? '' : level);
    el.innerHTML = '<i class="dot"></i>' + NA.esc(text);
  };

  // ---- poll helper ------------------------------------------------------
  NA.poll = function (fn, ms) {
    fn();
    const id = setInterval(function () {
      if (!document.hidden) fn();      // don't hammer the agent on a background tab
    }, ms);
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) fn();
    });
    return id;
  };

  // ---- nav active state -------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    const p = location.pathname.replace(/\/$/, '') || '/';
    document.querySelectorAll('nav.nav a').forEach(function (a) {
      const h = a.getAttribute('href').replace(/\/$/, '') || '/';
      if (h === p) a.classList.add('active');
    });
    const b = document.getElementById('theme-btn');
    if (b) b.addEventListener('click', NA.toggleTheme);
  });
})();
