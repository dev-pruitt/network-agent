#!/usr/bin/env python3
"""Capture dashboard screenshots, optionally with the live data redacted.

Headless Chromium via Playwright, installed into ~/.cache/ms-playwright so it
needs no root. Logs in once, then captures each page after its async fetches
have settled - these pages render empty and fill in from /api/*, so a naive
screenshot catches skeletons.

WHY --redact EXISTS
  These screenshots ship in the public repo, and they are the one artefact a
  secret scanner cannot read. Every other published file is text and gets
  grepped; a PNG of the dashboard showing tunnel endpoints, LAN addresses,
  tailnet peer names and the device inventory sails straight past it.

  So redaction happens in the DOM before the shutter, not after.

TWO THINGS THIS FILE GETS RIGHT ON PURPOSE

  1. ONE definition of "is this an address worth hiding".
     The first version had classify() in JS and a second, hand-maintained
     allowlist in the Python verifier. They disagreed: the redactor skips
     255.x as a subnet mask, the verifier had never heard of that, and
     reported ten leaks that were all 255.255.255.0. A verifier that
     disagrees with what it verifies is worse than no verifier - it either
     blocks good output or, the other way round, blesses bad output. Both
     passes now share CLASSIFY_JS. There is one definition.

  2. The substitution map SURVIVES page navigation.
     It used to live in window.__redactMap, which a page load wipes. So the
     same address became 192.168.1.1 on one page and 192.168.1.4 on the next,
     and the screenshots quietly stopped describing one coherent system. The
     map is now owned by Python, passed in and read back out per page.

  Both were the same bug this whole project keeps turning up: a value that
  had to track something, and didn't.

Usage:  capture_screenshots.py            live data, for local reference
        capture_screenshots.py --redact   sanitised, for the public repo
"""
import json
import os
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

BASE = "http://localhost:8080"
CONF = os.path.expanduser("~/network-agent-backup/config/dashboard.conf")
OUT = os.path.expanduser("~/network-agent-backup/docs/screenshots")

# Names that are not addresses and so cannot be caught by pattern. Anything
# here is replaced wherever it appears, case-insensitively.
EXTRA_NAMES = ["ISP", "Carrier", "b3000", "GL-B3000"]

PAGES = [
    ("overview",  "/",           "Overview - live tunnel, DNS and pending state"),
    ("tunnels",   "/wireguard",  "Tunnels - per-tunnel health and transfer"),
    ("servers",   "/servers",    "Server pool - active vs spare, click to rotate"),
    ("actions",   "/actions",    "Actions - what the agent did unattended"),
    ("proposals", "/proposals",  "Proposals - anything awaiting a human"),
    ("health",    "/health",     "System health - resources, services, timers"),
    ("logs",      "/logs",       "Logs - raw agent output"),
]

# ---------------------------------------------------------------------------
# Shared by the redactor and the verifier. Edit this and both change together
# - that is the entire point of it being one string.
#
# Returns null for anything that is not a host address worth hiding:
#   0.x, 127.x        loopback / unspecified
#   255.x             subnet masks - 255.255.255.0 is not a location
#   any octet > 255   a version number or a decimal that merely looks like one
# ---------------------------------------------------------------------------
CLASSIFY_JS = r"""
  const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const MAC  = /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g;
  const WGK  = /\b[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}\b/g;

  // VPN exit names, e.g. exit-NN. Not an address, but the ACTIVE ones are
  // whichever is nearest - people pick exits for latency - so publishing them
  // is publishing a rough location. Redacted for the same reason as an IP.
  const SRV  = /\b[A-Z]{2}(?:-[A-Z]{2,})?#\d+\b/g;

  const classify = (ip) => {
    const o = ip.split('.').map(Number);
    if (o.some(n => n > 255)) return null;
    if (o[0] === 127 || o[0] === 0 || o[0] === 255) return null;
    if (o[0] === 10 || (o[0] === 192 && o[1] === 168) ||
        (o[0] === 172 && o[1] >= 16 && o[1] <= 31)) return 'priv';
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return 'cg';
    return 'pub';
  };

  const isPlaceholder = (s) =>
    /^(203\.0\.113\.|192\.168\.1\.|100\.100\.100\.)/.test(s) ||
    /^aa:bb:cc:00:00:/.test(s) ||
    /^REDACTED-PUBKEY-/.test(s) ||
    /^device-\d+$/.test(s) ||
    /^exit-\d+$/.test(s);

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
"""

# Rewrites the DOM. Takes the map built so far and returns the updated one, so
# a value keeps the same placeholder across every page in the run.
REDACT_JS = r"""
([names, seedMap, seedSeq]) => {
""" + CLASSIFY_JS + r"""
  const M = Object.assign({}, seedMap);
  const S = Object.assign({pub:0, priv:0, cg:0, mac:0, key:0, name:0, srv:0}, seedSeq);

  const alloc = (raw, kind) => {
    if (M[raw]) return M[raw];
    let v;
    if      (kind === 'pub')  v = '203.0.113.' + (++S.pub);          // RFC 5737
    else if (kind === 'priv') v = '192.168.1.' + (++S.priv);
    else if (kind === 'cg')   v = '100.100.100.' + (++S.cg);
    else if (kind === 'mac')  v = 'aa:bb:cc:00:00:' + String(++S.mac).padStart(2,'0');
    else if (kind === 'key')  v = 'REDACTED-PUBKEY-' + (++S.key);
    else if (kind === 'srv')  v = 'exit-' + String(++S.srv).padStart(2,'0');
    else                      v = 'device-' + (++S.name);
    M[raw] = v;
    return v;
  };

  const scrub = (s) => {
    if (!s) return s;
    s = s.replace(WGK, m => isPlaceholder(m) ? m : alloc(m, 'key'));
    s = s.replace(MAC, m => isPlaceholder(m) ? m : alloc(m, 'mac'));
    s = s.replace(SRV, m => isPlaceholder(m) ? m : alloc(m, 'srv'));
    s = s.replace(IPV4, m => {
      if (isPlaceholder(m)) return m;
      const k = classify(m);
      return k ? alloc(m, k) : m;
    });
    for (const n of names) {
      if (!n) continue;
      s = s.replace(new RegExp(escapeRe(n), 'gi'), () => alloc(n.toLowerCase(), 'name'));
    }
    return s;
  };

  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walk.nextNode()) nodes.push(walk.currentNode);
  nodes.forEach(n => { const v = scrub(n.nodeValue); if (v !== n.nodeValue) n.nodeValue = v; });

  document.querySelectorAll('input,textarea').forEach(el => {
    if (el.value) el.value = scrub(el.value);
    if (el.placeholder) el.placeholder = scrub(el.placeholder);
  });
  document.title = scrub(document.title);

  return {map: M, seq: S, mapped: Object.keys(M).length - Object.keys(seedMap).length};
}
"""

# Same classifier, so it can only flag things the redactor was supposed to hide.
VERIFY_JS = r"""
(names) => {
""" + CLASSIFY_JS + r"""
  const text = document.body.innerText;
  const bad = new Set();

  (text.match(IPV4) || []).forEach(ip => {
    if (!isPlaceholder(ip) && classify(ip)) bad.add(ip);
  });
  (text.match(MAC) || []).forEach(m => { if (!isPlaceholder(m)) bad.add(m); });
  (text.match(SRV) || []).forEach(m => { if (!isPlaceholder(m)) bad.add(m); });
  names.forEach(n => {
    if (n && new RegExp(escapeRe(n), 'i').test(text)) bad.add(n);
  });
  return Array.from(bad);
}
"""


def read_credentials():
    """Credentials live in config, never in source - this file is published."""
    if not os.path.exists(CONF):
        sys.exit(f"FATAL: {CONF} missing. Run fix_dashboard_auth.py.")
    conf = {}
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            conf[k.strip()] = v.strip()
    return conf.get("username", "admin"), conf.get("password", "")


def tailnet_names():
    """Hostnames to redact, read from the live tailnet.

    Hardcoding this list is exactly the mistake catalogued elsewhere in this
    project - a device list that stops tracking reality. Discover it instead,
    and fail soft: if tailscale is not answering, the pattern rules still
    apply and only the names are missed.
    """
    names = []
    try:
        r = subprocess.run(["tailscale", "status", "--json"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            d = json.loads(r.stdout)
            for node in [d.get("Self") or {}] + list((d.get("Peer") or {}).values()):
                for field in ("HostName", "DNSName"):
                    v = (node.get(field) or "").split(".")[0]
                    if v and len(v) > 2:
                        names.append(v)
    except Exception as e:
        print(f"  note: tailnet names unavailable ({type(e).__name__}); "
              f"pattern rules still applied")
    # longest first, so 'agent-pc' is consumed before a bare 'agent'
    return sorted(set(names + EXTRA_NAMES), key=len, reverse=True)


def settle(page):
    """These pages paint from /api/* after load; don't photograph a skeleton."""
    time.sleep(2.5)
    try:
        page.wait_for_function(
            "!document.body.innerText.includes('Loading…')", timeout=6000)
    except Exception:
        pass          # some panels legitimately stay empty


def main():
    redact = "--redact" in sys.argv
    os.makedirs(OUT, exist_ok=True)
    user, password = read_credentials()
    names = tailnet_names() if redact else []

    print(f"=== screenshots ({'REDACTED' if redact else 'live data'}) ===")
    if redact:
        print(f"  redacting {len(names)} name(s) plus IPv4, MAC and pubkey patterns")

    # Owned here, not in the page, so navigation cannot wipe it.
    rmap, rseq = {}, {}
    written = []

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 900},
                                device_scale_factor=2)

        # login page first - worth showing, and it establishes the session
        page.goto(f"{BASE}/login", wait_until="networkidle")
        page.screenshot(path=os.path.join(OUT, "login.png"))
        written.append("login.png")

        page.fill('input[name="username"]', user)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")

        if "/login" in page.url:
            print("FAILED: still on /login after submitting credentials")
            browser.close()
            return 1

        for name, path, _desc in PAGES:
            page.goto(BASE + path, wait_until="networkidle")
            settle(page)

            note = ""
            if redact:
                res = page.evaluate(REDACT_JS, [names, rmap, rseq])
                rmap, rseq = res["map"], res["seq"]
                note = f"  (+{res['mapped']} new, {len(rmap)} mapped so far)"

            page.screenshot(path=os.path.join(OUT, f"{name}.png"))
            written.append(f"{name}.png")
            print(f"  captured {name}.png{note}")

        # Verify rather than assume. A redaction pass that silently missed a
        # page is worse than none, because it is trusted.
        if redact:
            print("\n=== post-redaction check ===")
            leaked = 0
            for name, path, _d in PAGES:
                page.goto(BASE + path, wait_until="networkidle")
                settle(page)
                page.evaluate(REDACT_JS, [names, rmap, rseq])
                bad = page.evaluate(VERIFY_JS, names)
                if bad:
                    leaked += len(bad)
                    print(f"  {name}: {len(bad)} unredacted -> {sorted(bad)[:6]}")
            if leaked:
                print(f"  {leaked} leak(s) - do NOT publish")
                browser.close()
                return 1
            print(f"  clean - {len(rmap)} value(s) mapped across {len(PAGES)} pages")

        # Written only after the verification above passed. publish-public.sh
        # refuses to stage screenshots unless this marker exists AND is newer
        # than every PNG - so a later recapture without --redact fails the
        # publish rather than quietly shipping live data.
        if redact:
            mark = os.path.join(OUT, ".redacted")
            with open(mark, "w") as f:
                f.write(f"redacted {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"{len(written)} screenshots, {len(rmap)} values mapped\n")
            print(f"  marker written -> {mark}")

        browser.close()

    print(f"\n{len(written)} screenshots -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
