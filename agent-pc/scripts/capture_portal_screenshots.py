#!/usr/bin/env python3
"""Screenshot the camera portal for the public repo, safely.

The dashboard capture script cannot be reused as-is. The portal leaks a
different class of thing, and one of them is not textual at all.

1. THE VIDEO IS THE BIGGEST LEAK, AND NO REGEX WILL CATCH IT
   The viewer renders a live feed of a real parking lot: vehicles, licence
   plates, the building, people. A text redactor scans the DOM and would call
   that page clean while publishing a photograph of a specific address. So
   the video is replaced with a neutral placeholder before any screenshot is
   taken, and the run refuses to continue if the replacement did not land.

   This is the same failure the project keeps meeting: a check that verifies
   the thing it knows how to verify and reports "clean" about everything else.

2. RESIDENT PII THE DASHBOARD NEVER HAD
   Emails and apartment numbers appear on /admin and /account. Neither is an
   IP, MAC, pubkey or hostname, so the dashboard's classifier ignores both.
   Added here, allocating stable placeholders the same way.

3. networkidle NEVER FIRES ON THE VIEWER
   A live HLS stream means requests never stop. Waiting for networkidle hangs
   until timeout - a bug already hit once in this project. Every navigation
   uses "load" plus an explicit settle.

Run with --redact to produce publishable images. Without it, nothing is
written to the published directory.
"""
import json
import os
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8081"
CONF = os.path.expanduser("~/network-agent-backup/config/portal.conf")
OUT = os.path.expanduser("~/network-agent-backup/docs/screenshots/portal")

PAGES = [
    ("portal-login",    "/login",          "Sign in"),
    ("portal-signup",   "/signup",         "Request access - goes to approval"),
    ("portal-viewer",   "/",               "Viewer - live plus recorded timeline"),
    ("portal-admin",    "/admin",          "Admin - approve or deny requests"),
    ("portal-settings", "/admin/settings", "Camera settings - quality, audio"),
    ("portal-account",  "/account",        "Account - password, audio preference"),
]

# ---------------------------------------------------------------------------
# Portal-specific redaction. Emails and apartments are the PII here.
# ---------------------------------------------------------------------------
PORTAL_JS = r"""
  const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  // "Apartment 4B", "Apt 12", "Unit 3" - the label is what makes it PII.
  const APT   = /\b(Apartment|Apt\.?|Unit)\s+([0-9]{1,4}[A-Za-z]?)\b/gi;

  const isPortalPlaceholder = (s) =>
    /^resident\d+@example\.com$/.test(s) ||
    /^(Apartment|Apt|Unit)\s+\d+$/i.test(s);
"""

REDACT_JS = r"""
([seedMap, seedSeq]) => {
""" + PORTAL_JS + r"""
  const M = Object.assign({}, seedMap);
  const S = Object.assign({email:0, apt:0}, seedSeq);

  const alloc = (raw, kind) => {
    if (M[raw]) return M[raw];
    const v = (kind === 'email')
      ? 'resident' + (++S.email) + '@example.com'
      : 'Apartment ' + (++S.apt);
    M[raw] = v;
    return v;
  };

  const scrub = (s) => {
    if (!s) return s;
    s = s.replace(EMAIL, m => isPortalPlaceholder(m) ? m : alloc(m.toLowerCase(), 'email'));
    s = s.replace(APT, (m) => isPortalPlaceholder(m) ? m : alloc(m.toLowerCase(), 'apt'));
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

  // STRUCTURAL PASS - the text pass cannot do this job.
  //
  // In a table the apartment is a bare cell ("4B") under an APT header. The
  // label that makes it identifiable is in the column heading, not next to
  // the value, so a pattern needing "Apartment 4B" never fires. The verifier
  // used the same pattern and therefore agreed it was clean: a shared
  // classifier guarantees the two halves agree, not that either is right.
  // Real apartment numbers reached a screenshot that passed every check.
  //
  // So find the column by its header and redact every cell in it, whatever
  // the value looks like.
  let cells = 0;
  document.querySelectorAll('table').forEach(tbl => {
    const heads = Array.from(tbl.querySelectorAll('tr')).shift();
    if (!heads) return;
    const cols = Array.from(heads.children).map(
      c => (c.textContent || '').trim().toLowerCase());
    const targets = [];
    cols.forEach((h, i) => {
      if (/^(apt|apartment|unit|apt\.)$/.test(h)) targets.push(i);
    });
    if (!targets.length) return;
    Array.from(tbl.querySelectorAll('tr')).slice(1).forEach(row => {
      targets.forEach(i => {
        const cell = row.children[i];
        if (!cell) return;
        const raw = (cell.textContent || '').trim();
        if (!raw || isPortalPlaceholder(raw)) return;
        cell.textContent = alloc('apt:' + raw.toLowerCase(), 'apt')
                             .replace('Apartment ', '');
        cells++;
      });
    });
  });

  return {map: M, seq: S, cells: cells,
          mapped: Object.keys(M).length - Object.keys(seedMap).length};
}
"""

VERIFY_JS = r"""
() => {
""" + PORTAL_JS + r"""
  const text = document.body.innerText;
  const bad = new Set();
  (text.match(EMAIL) || []).forEach(m => { if (!isPortalPlaceholder(m)) bad.add(m); });
  let m2;
  const re = new RegExp(APT.source, 'gi');
  while ((m2 = re.exec(text)) !== null) {
    if (!isPortalPlaceholder(m2[0])) bad.add(m2[0]);
  }

  // Check the column STRUCTURALLY, by a rule the redactor does not share.
  // The text rules above already agreed with the redactor once and were
  // wrong together. An independent check is the only kind worth having:
  // after redaction every apartment cell must be a plain sequence number,
  // so anything else - "4B", "12", "B4" - is a value that survived.
  document.querySelectorAll('table').forEach(tbl => {
    const heads = Array.from(tbl.querySelectorAll('tr')).shift();
    if (!heads) return;
    const cols = Array.from(heads.children).map(
      c => (c.textContent || '').trim().toLowerCase());
    cols.forEach((h, i) => {
      if (!/^(apt|apartment|unit|apt\.)$/.test(h)) return;
      Array.from(tbl.querySelectorAll('tr')).slice(1).forEach(row => {
        const cell = row.children[i];
        if (!cell) return;
        const raw = (cell.textContent || '').trim();
        if (raw && !/^\d+$/.test(raw)) bad.add('APT-CELL:' + raw);
      });
    });
  });
  return Array.from(bad);
}
"""

# Replace the feed with a placeholder. Returns what it did so the caller can
# refuse to photograph a page where this silently failed.
BLANK_VIDEO_JS = r"""
() => {
  const vids = Array.from(document.querySelectorAll('video'));
  vids.forEach(v => {
    try { v.pause(); } catch (e) {}
    const box = v.getBoundingClientRect();
    const ph = document.createElement('div');
    ph.setAttribute('data-placeholder', '1');
    ph.style.cssText =
      'width:100%;height:' + Math.max(box.height, 380) + 'px;' +
      'background:repeating-linear-gradient(45deg,#1b1b1f 0 18px,#232329 18px 36px);' +
      'display:flex;align-items:center;justify-content:center;' +
      'color:#8a8a94;font:600 17px/1.5 Georgia,serif;text-align:center;' +
      'border-radius:8px;letter-spacing:.3px;';
    ph.textContent = 'Live camera view (hidden in published screenshots)';
    v.replaceWith(ph);
  });
  // Poster images can carry a frame too.
  document.querySelectorAll('img[src*="snap"],img[src*="preview"],canvas')
          .forEach(el => el.remove());
  return {replaced: vids.length,
          remaining: document.querySelectorAll('video,canvas').length};
}
"""


def creds():
    if not os.path.exists(CONF):
        sys.exit(f"FATAL: {CONF} missing.")
    c = {}
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            c[k.strip()] = v.strip()
    return c["username"], c["password"]


def settle(page, secs=3.0):
    """The viewer streams forever, so networkidle never fires. Wait explicitly."""
    time.sleep(secs)
    try:
        page.wait_for_function(
            "!document.body.innerText.includes('Loading\\u2026')", timeout=5000)
    except Exception:
        pass


def main():
    redact = "--redact" in sys.argv
    if not redact:
        print("Refusing to write without --redact.")
        print("These pages contain resident emails, apartment numbers and a")
        print("live view of a real parking lot.")
        return 2

    os.makedirs(OUT, exist_ok=True)
    user, pw = creds()
    rmap, rseq = {}, {}
    written = []

    print("=== camera portal screenshots (REDACTED) ===")
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        page = b.new_page(viewport={"width": 1440, "height": 900},
                          device_scale_factor=2)

        page.goto(f"{BASE}/login", wait_until="load")
        settle(page, 1.5)
        page.fill("#email", user)
        page.fill("#password", pw)
        page.click("button[type=submit]")
        page.wait_for_load_state("load")
        if "/login" in page.url:
            print("FAILED: still on /login after submitting credentials")
            b.close()
            return 1
        print(f"  signed in, landed on {page.url.split('8081')[-1]}")

        for name, path, desc in PAGES:
            page.goto(BASE + path, wait_until="load")
            settle(page)

            vid = page.evaluate(BLANK_VIDEO_JS)
            if vid["remaining"]:
                print(f"  ABORT on {name}: {vid['remaining']} video/canvas element(s) "
                      f"still present after blanking - refusing to photograph a live feed")
                b.close()
                return 1

            res = page.evaluate(REDACT_JS, [rmap, rseq])
            rmap, rseq = res["map"], res["seq"]

            page.screenshot(path=os.path.join(OUT, f"{name}.png"), full_page=True)
            written.append(f"{name}.png")
            bits = []
            if vid["replaced"]:
                bits.append("video hidden")
            # Report the structural pass separately from the text pass. An
            # earlier revision printed 0 here while redacting three cells,
            # because the key was built wrong - a counter that under-reports
            # its own work is how a silent regression stays silent.
            if res.get("cells"):
                bits.append(f"{res['cells']} apt cell(s)")
            v = ("" if not bits else ", " + ", ".join(bits))
            print(f"  captured {name}.png  (+{res['mapped']} redacted{v})  - {desc}")

        print("\n=== post-redaction check ===")
        leaked = 0
        for name, path, _d in PAGES:
            page.goto(BASE + path, wait_until="load")
            settle(page)
            page.evaluate(BLANK_VIDEO_JS)
            page.evaluate(REDACT_JS, [rmap, rseq])
            bad = page.evaluate(VERIFY_JS)
            if bad:
                leaked += len(bad)
                print(f"  {name}: {len(bad)} unredacted -> {sorted(bad)[:5]}")
        if leaked:
            print(f"  {leaked} leak(s) - do NOT publish")
            b.close()
            return 1
        print(f"  clean - {len(rmap)} value(s) mapped across {len(PAGES)} pages")

        with open(os.path.join(OUT, ".redacted"), "w") as f:
            f.write(f"redacted {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"{len(written)} screenshots, {len(rmap)} values mapped\n"
                    f"video elements replaced with a placeholder\n")
        b.close()

    print(f"\n{len(written)} screenshots -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
