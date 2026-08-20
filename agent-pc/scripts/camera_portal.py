#!/usr/bin/env python3
"""Resident camera portal: sign-up, approval, live view, recorded playback.

THE ONE RULE THIS FILE ENFORCES
  MediaMTX binds to loopback and knows nothing about users. Every byte of
  video passes through this process, and every route that touches it sits
  behind @login_required - playlist, segments, recordings index, all of it.
  Serving the HLS port directly would be simpler and would hand the feed to
  anyone who guessed the URL, because the stream carries no auth of its own.

ACCESS MODEL
  Residents sign up and are approved immediately (2026-08-19, per agent) -
  there is no human review step left. No shared secret is involved: the
  earlier design verified against the building's door entry code, which
  would have meant storing a physical access code for a residential building
  on an internet-facing service, in exchange for verification it could not
  actually provide. Auto-approval means that verification gap is now wider,
  not narrower - the apartment number on sign-up is free text, never checked
  against a roster. Anyone who reaches /signup gets live view and 30 days of
  recorded footage with no one in the loop. /admin still lists every account
  and can revoke one after the fact; that is the only backstop now.

LOGIN THROTTLING
  See login_throttle.py. Both the admin account and resident accounts share
  the same per-IP lockout, checked before either credential path runs.

TWO SEPARATE LOGINS
  Residents live in users.db. The operator uses config/portal.conf and gets
  the admin screen. Deliberately different stores: a resident account can
  never become an admin by editing a row.

DELIVERY IS HLS
  WebRTC needs UDP for ICE; Cloudflare Tunnel carries HTTP. WebRTC would have
  worked on the LAN and failed for every public viewer - broken in the way
  that passes local testing.
"""
import hashlib
import json
import re
import threading
import os
import sys
import time
from functools import wraps

import requests
from flask import (Flask, Response, jsonify, make_response, redirect,
                   send_file,
                   render_template_string, request, session,
                   stream_with_context, url_for)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import camera_settings                                          # noqa: E402
import login_throttle                                           # noqa: E402
import portal_users as users                                    # noqa: E402
from portal_theme import CSS                                    # noqa: E402

CONF_REL = os.path.join("config", "portal.conf")


def _find_conf(start):
    """Walk up for config/portal.conf - the file, not the folder.

    Two earlier attempts were wrong. Counting '..' landed on agent-pc instead
    of the repo root. Then searching for a directory named 'config' stopped at
    agent-pc/config, which also exists, and produced the identical error - an
    ambiguous marker fails while looking like it succeeded. The file is unique.
    """
    d = os.path.dirname(os.path.abspath(start))
    for _ in range(6):
        cand = os.path.join(d, CONF_REL)
        if os.path.isfile(cand):
            return d, cand
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    sys.exit(f"FATAL: {CONF_REL} not found above {start}. Run setup_camera_portal.py.")


BASE, CONF = _find_conf(__file__)
MTX_HLS = "http://127.0.0.1:8888"
MTX_API = "http://127.0.0.1:9997"
MTX_PLAYBACK = "http://127.0.0.1:9996"

STREAMS = {"sd": ("720p", "Balanced"),
           "hd": ("1080p", "Full detail"),
           "mobile": ("360p", "Cellular")}
DEFAULT_STREAM = "sd"
RECORD_PATH = "sd"

app = Flask(__name__)
_WEAK = {"changeme", "password", "admin", "guest", "portal", ""}


def _load():
    c = {}
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            c[k.strip()] = v.strip()
    if not c.get("username", "").strip():
        sys.exit(f"FATAL: blank username in {CONF}")
    for k in ("password", "secret_key"):
        if c.get(k, "").lower() in _WEAK:
            sys.exit(f"FATAL: default or blank '{k}' in {CONF}. Refusing to start.")
    return c


_C = _load()
app.secret_key = _C["secret_key"]
ADMIN_USER, ADMIN_PASS = _C["username"], _C["password"]
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12
# Do NOT re-send Set-Cookie on every response. Permanent sessions refresh the
# cookie by default, which is harmless for one request at a time and harmful
# for byte-range playback: WebKit opens several connections at once, each
# response rewrites the cookie jar, and an in-flight request can carry a
# cookie that has just been superseded. It then arrives unauthenticated and
# gets redirected to /login - which Safari renders inside the video element
# as a blank frame. Observed: 3 x 206 and 1 x 302 for the same URL in 2s.
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
# Explicit rather than relying on per-browser defaults. Lax is correct for a
# same-site media fetch. SECURE is intentionally omitted: it would be right
# for cam.example.com and would break every http:// LAN and loopback client.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def _denied(msg="unauthenticated"):
    if request.path.startswith(("/hls/", "/api/")):
        return jsonify({"error": msg}), 401
    return redirect(url_for("login"))


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not (session.get("resident") or session.get("admin")):
            return _denied()
        # Re-check the store on every request. A session cookie lives 12h, so
        # trusting it alone means a revoked resident keeps watching until it
        # lapses - revocation that arrives tomorrow is not revocation. One
        # indexed read against a local SQLite file per request.
        who = session.get("resident")
        if who:
            st = users.status_of(who)
            if st == "unknown":
                # Could not read the store. That is not evidence of revocation,
                # so do not manufacture one; the request proceeds and the
                # failure is visible in the log rather than silently denying
                # every resident because of a transient disk error.
                app.logger.warning("status_of failed for %s; allowing request", who)
            elif st != "approved":
                session.clear()
                return _denied("access revoked")
        return f(*a, **kw)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w


PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{{ title }}</title><style>""" + CSS + """{{ extra_css|safe }}</style>
<div class="card {{ 'wide' if wide else '' }}">{{ body|safe }}</div>"""


def page(title, body, wide=False, extra_css=""):
    return render_template_string(PAGE, title=title, body=body, wide=wide,
                                  extra_css=extra_css)


# ---------------------------------------------------------------------------
def client_ip():
    """The real visitor address, not cloudflared's local connection to us.

    Cloudflare's edge sets Cf-Connecting-Ip to what IT observed and this app
    is only reachable through the tunnel (camera-portal.service binds
    loopback), so the client cannot forge this header - the tunnel replaces
    whatever the client sent with the edge's own value before it ever
    reaches Flask. X-Forwarded-For and remote_addr are fallbacks only, for
    the case of testing directly against localhost.
    """
    return (request.headers.get("Cf-Connecting-Ip")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or "unknown")


def _lockout_message(retry_after_sec):
    mins = max(1, retry_after_sec // 60)
    return (f"Too many failed attempts. Try again in about "
            f"{mins} minute{'s' if mins != 1 else ''}.")


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    status = 200
    if request.method == "POST":
        ip = client_ip()
        locked, retry_after = login_throttle.check(ip)
        if locked:
            err = _lockout_message(retry_after)
            status = 429
        else:
            email = request.form.get("email", "")
            pw = request.form.get("password", "")
            if email.strip().lower() == ADMIN_USER.lower() and pw == ADMIN_PASS:
                login_throttle.record_success(ip)
                session.permanent = True
                session["admin"] = True
                return redirect(url_for("admin"))
            row, why = users.authenticate(email, pw)
            if row:
                login_throttle.record_success(ip)
                session.permanent = True
                session["resident"] = row["email"]
                session["apartment"] = row["apartment"]
                return redirect(url_for("index"))
            now_locked, retry_after = login_throttle.record_failure(ip)
            time.sleep(1)          # blunt online guessing, kept alongside the lockout
            if now_locked:
                err = _lockout_message(retry_after)
                status = 429
            else:
                err = why
                status = 401

    body = f"""
      <h1>Broadway Market</h1>
      <div class=sub>Parking Lot Camera</div>
      <div class=lead>Sign in to view</div>
      {'<div class=err>' + err + '</div>' if err else ''}
      <form method=post>
        <label class=lbl for=email>Email</label>
        <!-- type=text, not type=email. Residents sign in with an address, but
             the building manager account is a plain username, and type=email
             makes the BROWSER refuse to submit it - the form never reaches the
             server. curl passed this because it does not run HTML validation,
             which is exactly how the bug survived its first test. The server
             validates either way. -->
        <input id=email name=email type=text inputmode=email
               autocomplete=username autofocus required>
        <label class=lbl for=password>Password</label>
        <input id=password name=password type=password autocomplete=current-password required>
        <button class=btn type=submit>Sign in</button>
      </form>
      <div class=alt>No account yet? <a href="/signup">Request access</a></div>
      <div class=foot>Residents only. Sign-up requests are approved automatically.</div>
    """
    return page("Sign in", body), (status if err else 200)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    err = ok = ""
    if request.method == "POST":
        good, msg = users.create(request.form.get("email", ""),
                                 request.form.get("password", ""),
                                 request.form.get("apartment", ""))
        if not good:
            err = msg
        else:
            # Same wording whether or not the address already exists, so this
            # page cannot be used to discover which residents are registered.
            ok = ("Access granted. You'll get an email with a sign-in link "
                  "in the next minute or two.")

    if ok:
        body = f"""
          <h1>Broadway Market</h1><div class=sub>Parking Lot Camera</div>
          <div class=ok>{ok}</div>
          <div class=note>Your access is already active. An email with a
          sign-in link is on its way now - it usually arrives within a
          minute.<br><br>
          <b>Don't see it?</b> Check your spam folder. Mark it &ldquo;Not
          Spam&rdquo; or add the sender to your contacts so future messages
          reach your inbox.</div>
          <a class=btn href="/login">Sign in now</a>"""
        return page("Request received", body)

    body = f"""
      <h1>Request Access</h1>
      <div class=sub>Parking Lot Camera</div>
      {'<div class=err>' + err + '</div>' if err else ''}
      <form method=post>
        <label class=lbl for=email>Email &mdash; this is your username</label>
        <input id=email name=email type=email autocomplete=email required
               value="{request.form.get('email','')}">
        <label class=lbl for=password>Choose a password</label>
        <input id=password name=password type=password minlength=10
               autocomplete=new-password required>
        <label class=lbl for=apartment>Apartment number</label>
        <input id=apartment name=apartment required maxlength=16
               value="{request.form.get('apartment','')}">
        <button class=btn type=submit>Send request</button>
      </form>
      <div class=note>Access is granted automatically. You will receive an
      email at the address above with a sign-in link right away. Your
      password is stored scrambled and can never be read or emailed back
      to you.</div>
      <div class=alt>Already approved? <a href="/login">Sign in</a></div>
    """
    return page("Request access", body), (400 if err else 200)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
ADMIN_CSS = """
.pill.revoked{background:#6d5636;color:#f6ecd6}
.btn.sm.danger{border-color:#7a2e19;color:#7a2e19}
.btn.sm.danger:hover{background:#7a2e19;color:#f6ecd6}
td.act{white-space:nowrap}
"""


def _act(uid, action, label, cls="btn sm", confirm=""):
    """One action button. Delete carries a browser confirm because it is the
    only irreversible control on the page."""
    guard = (f" onsubmit=\"return confirm('{confirm}')\"" if confirm else "")
    return (f"<form method=post action='/admin/access' style='display:inline'{guard}>"
            f"<input type=hidden name=id value='{uid}'>"
            f"<button class='{cls}' name=action value={action}>{label}</button>"
            f"</form>")


@app.route("/admin")
@admin_required
def admin():
    rows = users.list_users()
    trs = []
    for u in rows:
        pill = f"<span class='pill {u['status']}'>{u['status']}</span>"
        mail = u.get("mail_status") or ""
        mail_html = (f"<span style='color:#7a2e19;font-weight:700'>{mail}</span>"
                     if mail.startswith("FAILED") else
                     f"<span style='color:#6d5636'>{mail}</span>")
        uid, st = u["id"], u["status"]
        wipe = _act(uid, "delete", "Delete", "btn sm danger",
                    f"Permanently delete {u['email']}? This cannot be undone. "
                    f"Recorded footage is not affected.")
        if st == "pending":
            actions = (f"<form method=post action='/admin/decide' style='display:inline'>"
                       f"<input type=hidden name=id value='{uid}'>"
                       f"<button class='btn sm' name=action value=approve>Approve</button>"
                       f"<button class='btn sm ghost' name=action value=deny>Deny</button>"
                       f"</form>")
        elif st == "approved":
            actions = _act(uid, "revoke", "Revoke", "btn sm ghost",
                           f"Revoke access for {u['email']}? They are signed out "
                           f"immediately and cannot sign back in. Reversible.") + wipe
        elif st == "revoked":
            actions = _act(uid, "restore", "Restore") + wipe
        else:
            actions = wipe
        trs.append(
            f"<tr><td>{u['email']}</td><td>{u['apartment']}</td><td>{pill}</td>"
            f"<td>{u['created_at'][:16].replace('T',' ')}</td>"
            f"<td>{mail_html}</td><td class=act>{actions}</td></tr>")

    pending = users.count_pending()
    active = sum(1 for u in rows if u["status"] == "approved")
    body = f"""
      <h1>Access Requests</h1>
      <div class=sub>{pending} awaiting review &middot; {active} with access</div>
      <hr>
      <table><thead><tr><th>Email</th><th>Apt</th><th>Status</th>
      <th>Requested</th><th>Email sent</th><th>Actions</th></tr></thead>
      <tbody>{''.join(trs) or '<tr><td colspan=6>No requests yet.</td></tr>'}</tbody></table>
      <div class=note><b>Revoke</b> switches access off but keeps the record,
      so you can see who had access and when. The resident is signed out at
      once and cannot sign back in. It can be undone with Restore.<br><br>
      <b>Delete</b> erases the account entirely and frees the email address to
      sign up again. Neither one touches recorded footage.</div>
      <div class=note><b>If "Email sent" shows FAILED</b>, the account is still
      approved &mdash; only the notification failed. Tell the resident directly,
      or check the mail relay.</div>
      <div class=alt><a href="/">View camera</a> &nbsp;&middot;&nbsp;
      <a href="/admin/settings">Camera settings</a> &nbsp;&middot;&nbsp;
      <a href="/logout">Sign out</a></div>
    """
    return page("Access requests", body, wide=True, extra_css=ADMIN_CSS)


@app.route("/admin/decide", methods=["POST"])
@admin_required
def admin_decide():
    uid = request.form.get("id")
    approve = request.form.get("action") == "approve"
    try:
        users.decide(int(uid), approve)
    except (TypeError, ValueError):
        pass
    return redirect(url_for("admin"))


@app.route("/admin/access", methods=["POST"])
@admin_required
def admin_access():
    """Revoke, restore or delete one account.

    Separate from /admin/decide on purpose: that route answers a request that
    has not been decided yet, this one changes access that already exists.
    Folding them together would mean one handler where 'deny' and 'delete'
    differ by a string, which is how the wrong row gets erased.
    """
    action = request.form.get("action", "")
    try:
        uid = int(request.form.get("id", ""))
    except (TypeError, ValueError):
        return redirect(url_for("admin"))

    if action == "revoke":
        users.revoke(uid)
    elif action == "restore":
        users.restore(uid)
    elif action == "delete":
        users.remove(uid)
    return redirect(url_for("admin"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    msg = err = ""
    if request.method == "POST":
        want = request.form.get("record_audio") == "on"
        ok, detail = camera_settings.set_record_audio(want)
        (msg := detail) if ok else (err := detail)

    on = camera_settings.record_audio()
    tracks, terr = camera_settings.current_tracks()
    live_audio = any("audio" in t.lower() for t in tracks)

    # Show the SETTING and what the stream is ACTUALLY doing, separately. If
    # they disagree the operator needs to know, not be shown a tidy toggle
    # that describes an intention rather than reality.
    actual = ("could not read the stream (" + terr + ")" if terr else
              ("audio present" if live_audio else "no audio track"))
    agree = (not terr) and (live_audio == on)

    body = f"""
      <h1>Camera Settings</h1>
      <div class=sub>Recording options</div>
      {'<div class=ok>' + msg + '</div>' if msg else ''}
      {'<div class=err>' + err + '</div>' if err else ''}
      <hr>
      <form method=post>
        <label class=lbl>Record audio</label>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <input type=checkbox id=ra name=record_audio {'checked' if on else ''}
                 style="width:auto;transform:scale(1.4)">
          <label for=ra style="font-family:Arial,sans-serif;font-size:15px">
            Capture the microphone along with video</label>
        </div>
        <button class=btn type=submit>Save and restart recording</button>
      </form>
      <div class=note>
        <b>Setting:</b> audio recording is <b>{'ON' if on else 'OFF'}</b><br>
        <b>Live stream right now:</b> {actual}
        {'' if agree else '<br><b style="color:#7a2e19">These disagree. '
         'The camera may still be reconnecting - reload in a minute. If it '
         'persists, check docker logs mediamtx.</b>'}
      </div>
      <div class=note>
        Turning audio off stops it being recorded from that moment. Footage
        already on disk keeps the audio it was recorded with &mdash; this does
        not reach back through the archive.<br><br>
        Audio is treated differently from video under most state recording
        laws, and usually more strictly. Worth knowing before leaving it on
        for a shared parking area.
      </div>
      <div class=alt><a href="/admin">Access requests</a> &nbsp;&middot;&nbsp;
      <a href="/">View camera</a></div>
    """
    return page("Camera settings", body)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    msg = err = ""
    is_admin = bool(session.get("admin"))
    who = ADMIN_USER if is_admin else session.get("resident", "")

    if request.method == "POST":
        cur = request.form.get("current", "")
        new = request.form.get("new", "")
        again = request.form.get("again", "")
        if new != again:
            err = "The two new passwords do not match."
        elif is_admin:
            if cur != ADMIN_PASS:
                err = "Current password is incorrect."
            elif len(new) < 10:
                err = "New password must be at least 10 characters."
            elif new.lower() in _WEAK:
                err = "That password is on the refused list."
            else:
                ok, detail = _rewrite_admin_password(new)
                (msg := detail) if ok else (err := detail)
        else:
            ok, detail = users.change_password(who, cur, new)
            (msg := detail) if ok else (err := detail)

    body = f"""
      <h1>Your Account</h1>
      <div class=sub>{who}</div>
      {'<div class=ok>' + msg + '</div>' if msg else ''}
      {'<div class=err>' + err + '</div>' if err else ''}
      <hr>
      <form method=post>
        <label class=lbl for=current>Current password</label>
        <input id=current name=current type=password autocomplete=current-password required>
        <label class=lbl for=new>New password</label>
        <input id=new name=new type=password minlength=10 autocomplete=new-password required>
        <label class=lbl for=again>New password again</label>
        <input id=again name=again type=password minlength=10 autocomplete=new-password required>
        <button class=btn type=submit>Change password</button>
      </form>
      <div class=note>The current password is required even though you are
      already signed in &mdash; otherwise an unattended browser could be used
      to lock you out of your own account.</div>
      <div class=alt><a href="/">View camera</a>
      {'&nbsp;&middot;&nbsp; <a href="/admin">Access requests</a>' if is_admin else ''}
      &nbsp;&middot;&nbsp; <a href="/logout">Sign out</a></div>
    """
    body = _dayexport.inject_settings(body, MTX_PLAYBACK, RECORD_PATH)
    return page("Your account", body), (400 if err else 200)


def _rewrite_admin_password(new):
    """Rewrite portal.conf in place, preserving comments and other keys.

    Written to a temp file and moved, so an interrupted write cannot leave a
    truncated credentials file that stops the service starting.
    """
    global ADMIN_PASS
    try:
        lines = open(CONF).read().splitlines(True)
        out = []
        for line in lines:
            if line.strip().startswith("password"):
                out.append(f"password = {new}\n")
            else:
                out.append(line)
        tmp = CONF + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.writelines(out)
        os.replace(tmp, CONF)
        ADMIN_PASS = new
        return True, "Password changed."
    except Exception as e:
        return False, f"Could not save: {type(e).__name__}"


# ---------------------------------------------------------------------------
VIEW_CSS = """
.wrap{display:grid;grid-template-columns:1fr 320px;gap:18px}
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
video{width:100%;background:#1a0e08;border-radius:10px;aspect-ratio:16/9;
border:3px solid #b8893b}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
.live{display:inline-flex;align-items:center;gap:6px;color:#7a2e19;
font-family:Arial,sans-serif;font-size:13px;font-weight:700}
.dot{width:8px;height:8px;border-radius:50%;background:#a33b1c;animation:p 2s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.25}}
.q{font-family:Arial,sans-serif;font-size:13px;padding:7px 14px;border-radius:999px;
border:1.5px solid #b8893b;background:transparent;color:#7a2e19;cursor:pointer;font-weight:700}
.q.on{background:#7a2e19;color:#f6ecd6;border-color:#7a2e19}
#msg{margin-top:10px;padding:10px 12px;border-radius:8px;background:#7a2e19;
color:#f6ecd6;font-family:Arial,sans-serif;font-size:13px;display:none}
.cal{background:#fffaf0;border:1px solid #cbb384;border-radius:10px;padding:12px}
.calhead{display:flex;align-items:center;justify-content:space-between;
font-family:Arial,sans-serif;font-size:14px;font-weight:700;color:#7a2e19;margin-bottom:8px}
.calhead button{background:none;border:0;color:#7a2e19;font-size:19px;cursor:pointer;padding:0 8px}
.grid{display:grid;grid-template-columns:repeat(7,1fr);gap:3px;
font-family:Arial,sans-serif;font-size:12.5px}
.grid .dow{color:#8a6a3a;text-align:center;font-size:10.5px;letter-spacing:1px;padding:3px 0}
.day{aspect-ratio:1;display:flex;align-items:center;justify-content:center;
border-radius:6px;color:#b3a189;cursor:default}
.day.has{background:#efe0c2;color:#3a2214;cursor:pointer;font-weight:700}
.day.has:hover{background:#e2cfa5}
.day.sel{background:#7a2e19;color:#f6ecd6}
.tl{margin-top:14px}
.tlhead{display:flex;justify-content:space-between;font-family:Arial,sans-serif;
font-size:12px;color:#8a6a3a;margin-bottom:5px}
.track{position:relative;height:44px;background:#e8dcc0;border:1px solid #cbb384;
border-radius:7px;overflow:hidden;cursor:crosshair}
.seg{position:absolute;top:0;bottom:0;background:#a8562f}
.seg:hover{background:#7a2e19}
.cursor{position:absolute;top:0;bottom:0;width:2px;background:#2a1c10;pointer-events:none}
.ticks{display:flex;justify-content:space-between;font-family:Arial,sans-serif;
font-size:10px;color:#8a6a3a;margin-top:3px}
.hint{font-family:Arial,sans-serif;font-size:12px;color:#6d5636;margin-top:7px}
.exportrow{display:flex;gap:8px;align-items:center;margin-top:10px}
.exportrow select{width:auto;flex:0 0 auto;font-size:13px;padding:7px 9px}
.heatwrap{position:relative;height:14px;margin-top:3px;border:1px solid #cbb384;
border-top:none;border-radius:0 0 7px 7px;background:#efe6cf;overflow:hidden}
.heatbar{position:absolute;top:0;bottom:0;width:1px}
.heatnone{position:absolute;inset:0;display:flex;align-items:center;
justify-content:center;font-family:Arial,sans-serif;font-size:10px;color:#a8926a}
.jump{width:auto;flex:0 0 auto;font-size:12px;padding:3px 9px;line-height:1.3}
.evcount{font-family:Arial,sans-serif;font-size:11px;color:#8a6a3a}
#track{cursor:default}
#track .seg{position:absolute;top:0;bottom:0;background:#a8562f;z-index:1}
#track .dim{position:absolute;top:0;bottom:0;background:rgba(58,38,22,.42);z-index:2;pointer-events:none}
.selwin{position:absolute;top:0;bottom:0;border-left:2px solid #b8893b;border-right:2px solid #b8893b;background:rgba(184,137,59,.14);box-sizing:border-box;z-index:3}
.hbody{position:absolute;inset:0;cursor:grab}
.hnd{position:absolute;top:0;bottom:0;width:14px;background:#b8893b;cursor:ew-resize}
.hnd.hL{left:-8px;border-radius:5px 0 0 5px}.hnd.hR{right:-8px;border-radius:0 5px 5px 0}
.zoomrow{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:9px;font-family:Arial,sans-serif;font-size:12px;color:#6d5636}
.zbtn{width:auto;flex:0 0 auto;font-size:15px;padding:2px 11px;line-height:1.2}
.zlabel{color:#8a6a3a}
.exporturl{font-family:monospace;font-size:11px;color:#8a6a3a;margin-top:9px;word-break:break-all}
.btn.sm[aria-disabled=true]{opacity:.45;pointer-events:none}
.clipbox{margin-top:14px;border:1px solid #cbb384;border-radius:10px;background:#fffaf0;padding:12px;display:flex;flex-direction:column;gap:8px}
.nowplay{font-family:Arial,sans-serif;font-size:13px;font-weight:700;color:#7a2e19}
.rangebox{margin-top:10px;padding-top:10px;border-top:1px dashed #e0cfa8}
.rlabel{font-family:Arial,sans-serif;font-size:12px;font-weight:700;color:#7a2e19;margin-bottom:6px}
.rrow{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.rrow input[type=time]{width:auto;flex:0 0 auto;font-size:12px;padding:5px 6px;font-family:Arial,sans-serif}
.rhint{font-family:Arial,sans-serif;font-size:11px;color:#6d5636;margin-top:5px}
.dlbtn{display:block;box-sizing:border-box;width:100%;text-align:center;padding:9px 12px;border-radius:999px;background:#7a2e19;color:#f6ecd6;font-family:Arial,sans-serif;font-size:13px;font-weight:700;text-decoration:none;cursor:pointer}
.dlbtn[aria-disabled=true]{opacity:.4;pointer-events:none}
.feedhint{font-family:Arial,sans-serif;font-size:11.5px;color:#6d5636}
.feed{margin-top:18px;border:1px solid #cbb384;border-radius:10px;background:#fffaf0;overflow:hidden}
.feedhead{display:flex;align-items:baseline;gap:10px;padding:10px 14px;border-bottom:1px solid #e6d6b3;font-family:Arial,sans-serif}
.feedhead .ft{font-size:13px;font-weight:700;color:#7a2e19}
.feedhead .fd{font-size:12px;color:#8a6a3a;margin-left:auto}
.feedstrip{display:flex;gap:10px;overflow-x:auto;padding:12px 14px}
.feedstrip::-webkit-scrollbar{height:8px}
.feedstrip::-webkit-scrollbar-thumb{background:#d9c49a;border-radius:4px}
.evchip{flex:0 0 auto;min-width:118px;padding:10px 12px;border:1px solid #d9c49a;border-radius:10px;background:#fffdf8;cursor:pointer;font-family:Arial,sans-serif}
.evchip:hover{background:#f3e7cc}
.evchip.sel{background:#7a2e19;border-color:#7a2e19}
.evchip.sel .evtime,.evchip.sel .evdur{color:#f6ecd6}
.evtime{font-size:14px;font-weight:700;color:#3a2214;white-space:nowrap}
.evdur{display:flex;align-items:center;gap:6px;font-size:12px;color:#8a6a3a;margin-top:3px}
.evdot{width:9px;height:9px;border-radius:50%;background:#a8562f;flex:0 0 auto}
.evdot.p{background:#2f6f9f}
.feedempty{padding:16px 14px;font-family:Arial,sans-serif;font-size:12.5px;color:#a8926a}
"""

VIEW_BODY = """
  <h1 style="font-size:26px">Parking Lot</h1>
  <div class=sub>{who}</div>
  <hr>
  <div class=wrap>
    <div>
      <video id=v controls autoplay muted playsinline></video>
      <div class=bar>
        <span class=live id=badge><span class=dot></span>LIVE</span>
        {qbtns}
        <span style="flex:1"></span>
        <button class="q" id=golive>Back to live</button>
      </div>
      <div id=msg></div>
    </div>
    <div>
      <div class=cal>
        <div class=calhead>
          <button id=prev>&#8249;</button><span id=mlabel></span><button id=next>&#8250;</button>
        </div>
        <div class=grid id=cal></div>
      </div>
      <div class=clipbox>
        <span class=nowplay id=nowplay>Live view</span>
        <a class=dlbtn id=dl href="#" aria-disabled="true" download>Download this clip</a>
        <span class=feedhint id=dlhint>Select an event below to watch or download it.</span>
        <div class=rangebox>
          <div class=rlabel>Or clip a custom range</div>
          <div class=rrow><input type=time step=1 id=rstart> <span style="font-family:Arial,sans-serif;font-size:12px;color:#6d5636">to</span> <input type=time step=1 id=rend></div>
          <div class=rrow style="margin-top:6px"><button class="btn sm" id=rwatch type=button>Watch</button><button class="btn sm" id=rdl type=button>Download range</button></div>
          <div class=rhint id=rhint>Pick a day, then a start and end time.</div>
        </div>
      </div>
    </div>
  </div>
  <div class=feed>
    <div class=feedhead><span class=ft>Recorded activity</span><span class=fd id=feeddate>Select a day</span></div>
    <div class=feedstrip id=feedlist><div class=feedempty>Pick a highlighted day on the calendar to see its recorded events.</div></div>
  </div>
  <div class=alt>{adminlink}<a href="/account">Your account</a>
  &nbsp;&middot;&nbsp; <a href="/logout">Sign out</a></div>
"""

VIEW_JS = """
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js"></script>
<script>
const v=document.getElementById('v'), msg=document.getElementById('msg'),
      badge=document.getElementById('badge'), calEl=document.getElementById('cal'),
      mlabel=document.getElementById('mlabel'),
      feedlist=document.getElementById('feedlist'), feeddate=document.getElementById('feeddate'),
      nowplay=document.getElementById('nowplay'), dl=document.getElementById('dl'),
      dlhint=document.getElementById('dlhint');
let hls=null, stream='sd', segs=[], byDay={}, view=new Date(), selDay=null;
let events=[], bins=[], curEv=null, scanned=false, clipStart=null;
const CHUNK=60;

function say(t){msg.textContent=t;msg.style.display=t?'block':'none';}
const pad=n=>String(n).padStart(2,'0');
const dayKey=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate());
function clk(s){s=Math.round(s);return pad(Math.floor(s/3600))+':'+pad(Math.floor(s%3600/60))+':'+pad(s%60);}
function durTxt(s){s=Math.max(1,Math.round(s));var m=Math.floor(s/60),x=s%60;return m>0?m+'m '+pad(x)+'s':x+'s';}

function loadLive(url){
  if(hls){hls.destroy();hls=null;}
  v.removeAttribute('src'); v.load();
  badge.style.display='inline-flex';
  say('');
  if(window.Hls&&Hls.isSupported()){
    hls=new Hls({lowLatencyMode:false,backBufferLength:10});
    hls.loadSource(url); hls.attachMedia(v);
    hls.on(Hls.Events.MANIFEST_PARSED,function(){v.play().catch(function(){});});
    hls.on(Hls.Events.FRAG_BUFFERED,function(){say('');});
    hls.on(Hls.Events.ERROR,function(e,d){
      if(!d.fatal)return;
      say(d.type===Hls.ErrorTypes.NETWORK_ERROR
        ? 'Cannot reach the stream. The camera may be offline. Retrying.'
        : 'Playback problem ('+d.details+'). Retrying.');
      setTimeout(function(){loadLive(url);},4000);
    });
  } else if(v.canPlayType('application/vnd.apple.mpegurl')){ v.src=url; v.play().catch(function(){}); }
  else { say('This browser cannot play HLS.'); }
}
function loadClip(startISO){
  if(hls){hls.destroy();hls=null;}
  badge.style.display='none';
  clipStart=new Date(startISO);
  say('Loading footage...');
  v.src='/clip?start='+encodeURIComponent(startISO)+'&duration='+CHUNK;
  v.load(); v.play().catch(function(){});
}
v.addEventListener('loadeddata',function(){say('');});
v.addEventListener('playing',function(){say('');});
v.addEventListener('error',function(){
  if(!clipStart) return;
  var e=v.error;
  say(e && e.code===4 ? 'That footage could not be decoded by this browser.'
      : 'Could not load that footage. If this persists, reload the page.');
});
v.addEventListener('ended',function(){
  if(!clipStart) return;
  loadClip(new Date(clipStart.getTime()+CHUNK*1000).toISOString());
});
function live(s){stream=s||stream;clipStart=null;curEv=null;markSel();nowplay.textContent='Live view';resetDl();loadLive('/hls/'+stream+'/index.m3u8');}
document.querySelectorAll('.q[data-s]').forEach(function(b){b.onclick=function(){
  document.querySelectorAll('.q[data-s]').forEach(function(x){x.classList.remove('on');});
  b.classList.add('on'); live(b.dataset.s);
};});
document.getElementById('golive').onclick=function(){live();};

function renderCal(){
  var y=view.getFullYear(), m=view.getMonth();
  mlabel.textContent=view.toLocaleString(undefined,{month:'long',year:'numeric'});
  var first=new Date(y,m,1), start=first.getDay(), days=new Date(y,m+1,0).getDate();
  var h='';
  ['S','M','T','W','T','F','S'].forEach(function(d){h+='<div class=dow>'+d+'</div>';});
  for(var i=0;i<start;i++) h+='<div></div>';
  for(var d=1;d<=days;d++){
    var k=y+'-'+pad(m+1)+'-'+pad(d);
    var has=byDay[k]?' has':'', sel=(k===selDay)?' sel':'';
    h+='<div class="day'+has+sel+'" data-k="'+k+'">'+d+'</div>';
  }
  calEl.innerHTML=h;
  calEl.querySelectorAll('.day.has').forEach(function(el){el.onclick=function(){pickDay(el.dataset.k);};});
}
document.getElementById('prev').onclick=function(){view.setMonth(view.getMonth()-1);renderCal();};
document.getElementById('next').onclick=function(){view.setMonth(view.getMonth()+1);renderCal();};

/* ---- HomeKit-style event feed (horizontal strip) ---- */
function fmtTime(ep){return new Date(ep*1000).toLocaleTimeString([],{hour:'numeric',minute:'2-digit',second:'2-digit'});}
function evStartISO(ev){return new Date(ev.start*1000).toISOString();}
function evIntensity(ev){return ev.peak||0;}
function markSel(){feedlist.querySelectorAll('.evchip').forEach(function(r){r.classList.toggle('sel', curEv!==null && (+r.dataset.i)===curEv);});}
function renderFeed(){
  feedlist.innerHTML='';
  if(!selDay){feedlist.innerHTML='<div class=feedempty>Pick a highlighted day on the calendar to see its recorded events.</div>';return;}
  if(!events.length){var em=document.createElement('div');em.className='feedempty';em.textContent=scanned?'No motion events on this day. The full day is still recorded.':'No activity index for this day yet.';feedlist.appendChild(em);return;}
  events.forEach(function(ev,i){
    var chip=document.createElement('div');chip.className='evchip';chip.dataset.i=i;
    var inten=evIntensity(ev);
    var op=(0.30+0.70*inten).toFixed(2), sc=(0.8+0.6*inten).toFixed(2);
    var lab=ev.label?ev.label.charAt(0).toUpperCase()+ev.label.slice(1):'Motion';var kind=(ev.label==='person')?'p':'v';chip.innerHTML='<div class=evtime>'+fmtTime(ev.start)+'</div><div class=evdur><span class="evdot '+kind+'" style="opacity:'+op+';transform:scale('+sc+')"></span>'+lab+' · '+durTxt(ev.end-ev.start)+'</div>';
    chip.onclick=function(){playEvent(i);};
    feedlist.appendChild(chip);
  });
  markSel();
}
function playEvent(i){
  curEv=i;markSel();
  var ev=events[i];
  nowplay.textContent='Playing '+fmtTime(ev.start);
  var secs=Math.max(5,Math.min(3600,Math.round((ev.end-ev.start)+4)));
  var iso=evStartISO(ev);
  dl.removeAttribute('aria-disabled');
  dl.href='/export?start='+encodeURIComponent(iso)+'&duration='+secs;
  dlhint.textContent='Downloads '+durTxt(secs)+' from '+fmtTime(ev.start)+'.';
  loadClip(iso);
}
function resetDl(){dl.setAttribute('aria-disabled','true');dl.href='#';dlhint.textContent='Select an event below to watch or download it.';}
function loadActivity(day){
  events=[];bins=[];scanned=false;curEv=null;nowplay.textContent='Live view';resetDl();renderFeed();
  fetch('/api/activity?day='+encodeURIComponent(day)).then(function(r){return r.json();}).then(function(d){
    scanned=!!d.scanned;events=d.events||[];
    var np=events.filter(function(e){return e.label==='person';}).length;var nv=events.length-np;var pr=[];if(nv)pr.push(nv+' vehicle'+(nv===1?'':'s'));if(np)pr.push(np+(np===1?' person':' people'));feeddate.textContent=events.length?(fmtDay(day)+' — '+pr.join(' · ')):fmtDay(day);
    renderFeed();
  }).catch(function(){scanned=false;renderFeed();});
}
function fmtDay(k){var d=new Date(k+'T12:00:00');return d.toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});}
function pickDay(k){selDay=k;renderCal();feeddate.textContent=fmtDay(k);loadActivity(k);}

fetch('/api/recordings').then(function(r){return r.json();}).then(function(d){
  segs=d.segments||[];byDay={};
  segs.forEach(function(s){var k=dayKey(new Date(s.start));(byDay[k]=byDay[k]||[]).push(s);});
  var keys=Object.keys(byDay).sort();
  if(keys.length){view=new Date(keys[keys.length-1]+'T12:00:00');}
  renderCal();
}).catch(function(){renderCal();});
(function(){
  var rs=document.getElementById('rstart'),ren=document.getElementById('rend'),rw=document.getElementById('rwatch'),rd=document.getElementById('rdl'),rh=document.getElementById('rhint');
  function rdate(inp){ if(!selDay||!inp.value)return null; var v=inp.value.length===5?inp.value+':00':inp.value; return new Date(selDay+'T'+v); }
  rw.onclick=function(){ var a=rdate(rs); if(!a){rh.textContent='Pick a day and a start time.';return;} curEv=null; markSel(); nowplay.textContent='Playing '+rs.value+' (range)'; loadClip(a.toISOString()); rh.textContent='Playing from '+rs.value+'. Rolls forward automatically.'; };
  rd.onclick=function(){ var a=rdate(rs),b=rdate(ren); if(!a||!b){rh.textContent='Pick a day, start and end.';return;} var dur=Math.round((b-a)/1000); if(dur<=0){rh.textContent='End must be after start.';return;} if(dur>3600){rh.textContent='Over 1 hour - use Download a full day on Your account.';return;} rh.textContent='Downloading '+durTxt(dur)+'...'; window.location='/export?start='+encodeURIComponent(a.toISOString())+'&duration='+dur; };
})();
live('sd');
</script>
"""


@app.route("/")
@login_required
def index():
    who = session.get("apartment") and f"Apartment {session['apartment']}" or "Building management"
    qbtns = "".join(
        f"<button class='q {'on' if k == DEFAULT_STREAM else ''}' data-s='{k}' "
        f"title='{d}'>{lbl}</button>" for k, (lbl, d) in STREAMS.items())
    adminlink = ('<a href="/admin">Access requests</a> &nbsp;&middot;&nbsp; '
                 '<a href="/admin/settings">Camera settings</a> &nbsp;&middot;&nbsp; '
                 if session.get("admin") else "")
    body = VIEW_BODY.format(who=who, qbtns=qbtns, adminlink=adminlink) + VIEW_JS
    html = page("Parking Lot Camera", body, wide=True, extra_css=VIEW_CSS)
    # The app JS is inlined here, so a cached page means cached CODE. After a
    # deploy that leaves the browser running the old script against the new
    # server - which looks exactly like the fix not working.
    resp = make_response(html)
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


# ---------------------------------------------------------------------------
@app.route("/hls/<stream>/<path:rest>")
@login_required
def hls(stream, rest):
    if stream not in STREAMS:
        return jsonify({"error": "unknown stream"}), 404
    # request.args MUST be forwarded. MediaMTX issues a ?session= token in the
    # master playlist and rejects segment requests that arrive without it -
    # "authentication error", from mediamtx, not from us. Dropping the query
    # string meant the playlist loaded and then every segment 401'd, so the
    # player sat on a spinner forever with no error anyone would see.
    return _proxy(f"{MTX_HLS}/{stream}/{rest}",
                  rewrite_prefix=f"/hls/{stream}/", params=request.args)


# Recorded playback. Deliberately NOT under /hls/ - it is a plain MP4 file,
# not a stream, and the old name encouraged the mistake of feeding it to
# hls.js (which parses playlists and silently failed on an MP4).
# Chunks are now buffered to disk before the first byte is sent (ranges need a
# known length), so chunk size is a latency cost, not just a bandwidth one.
# 60s ~= 3 MB and generates fast; 300s made the viewer wait with a blank frame.
PLAYBACK_CHUNK_SEC = 60
CLIP_CACHE = os.path.expanduser("~/network-agent/cache/clips")
CLIP_CACHE_MB = 1500            # ~8 hours of 720p at 3 MB/min
os.makedirs(CLIP_CACHE, exist_ok=True)

_clip_locks_guard = threading.Lock()
_clip_locks = {}


def _clip_lock(key):
    """One lock per clip key, created once."""
    with _clip_locks_guard:
        lk = _clip_locks.get(key)
        if lk is None:
            lk = _clip_locks[key] = threading.Lock()
    return lk


def _prune_clip_cache():
    """Keep the cache bounded. Oldest-accessed goes first."""
    try:
        files = []
        for n in os.listdir(CLIP_CACHE):
            if not n.endswith(".mp4"):
                continue
            p = os.path.join(CLIP_CACHE, n)
            try:
                st = os.stat(p)
            except FileNotFoundError:
                continue
            files.append((st.st_atime, st.st_size, p))
        total = sum(f[1] for f in files)
        limit = CLIP_CACHE_MB * 1024 * 1024
        if total <= limit:
            return
        for _, size, p in sorted(files):
            try:
                os.unlink(p)
                total -= size
            except OSError:
                pass
            if total <= limit * 0.8:
                break
    except Exception:
        pass            # a full cache must never break playback


def _clip_diag(tag):
    """Temporary: record the shape of each /clip request. See patch_clip_diag."""
    try:
        ck = request.headers.get("Cookie") or ""
        line = (f"{time.strftime('%H:%M:%S')} {tag} "
                f"cookie={'yes' if ck else 'NO'} "
                f"session_keys={sorted(session.keys()) if session else '[]'} "
                f"range={request.headers.get('Range') or '-'} "
                f"ua={(request.headers.get('User-Agent') or '?')[:60]}\n")
        with open(os.path.expanduser("~/network-agent/logs/clip_diag.log"), "a") as fh:
            fh.write(line)
    except Exception:
        pass            # diagnostics must never break playback


@app.route("/clip")
def clip():
    # Log BEFORE the auth gate, so the request that gets redirected is
    # recorded too - that is the whole point, and @login_required would
    # bounce it before anything could be written.
    # Truthiness, not key presence - must match login_required exactly. A
    # falsy value is not a session. The check is inline only so the DENIED
    # case can be logged; the decorator would bounce it first.
    if not (session.get("resident") or session.get("admin")):
        _clip_diag("DENIED")
        return redirect(url_for("login"))
    _clip_diag("ok")
    """One time-addressed MP4 chunk.

    mediamtx reports Accept-Ranges: none, so a browser cannot byte-seek inside
    the response. Seeking is therefore done by TIME - the page asks for a new
    chunk at a new start - and chunks are kept short so the first frame
    arrives quickly instead of after an hour of video downloads.
    """
    start = request.args.get("start", "")
    if not start:
        return jsonify({"error": "start required"}), 400
    try:
        dur = int(request.args.get("duration", PLAYBACK_CHUNK_SEC))
    except ValueError:
        dur = PLAYBACK_CHUNK_SEC
    dur = max(15, min(dur, 900))

    try:
        r = requests.get(f"{MTX_PLAYBACK}/get", stream=True, timeout=(5, 60),
                         params={"path": RECORD_PATH, "start": start,
                                 "duration": dur, "format": "mp4"})
    except requests.RequestException as e:
        return jsonify({"error": f"upstream unreachable: {type(e).__name__}"}), 502
    if r.status_code != 200:
        return jsonify({"error": "no footage at that time",
                        "upstream": r.status_code}), 404

    # Materialise the chunk, then serve it as a file.
    #
    # Streaming it through with Accept-Ranges: none is what broke Safari:
    # WebKit opens every progressive MP4 with 'Range: bytes=0-1' and needs
    # 206 Partial Content back. A 200 is a hard refusal - SRC_NOT_SUPPORTED -
    # and no amount of correct video fixes it. Ranges require a known length,
    # which requires a file. send_file(conditional=True) then handles 206,
    # Content-Range, ETag and If-Range for us.
    key = hashlib.sha1(f"{RECORD_PATH}|{start}|{dur}".encode()).hexdigest()[:20]
    dest = os.path.join(CLIP_CACHE, f"{key}.mp4")

    if not os.path.exists(dest):
        # One writer per clip. Two viewers clicking the same minute should not
        # both pull it, and a reader must never see a half-written file.
        with _clip_lock(key):
            if not os.path.exists(dest):
                part = f"{dest}.part-{os.getpid()}"
                try:
                    total = 0
                    with open(part, "wb") as fh:
                        for blk in r.iter_content(chunk_size=256 * 1024):
                            if blk:
                                fh.write(blk)
                                total += len(blk)
                    if total == 0:
                        os.unlink(part)
                        return jsonify({"error": "no footage at that time"}), 404
                    os.replace(part, dest)        # atomic: readers see all or nothing
                except Exception as e:
                    if os.path.exists(part):
                        os.unlink(part)
                    return jsonify({"error": f"clip fetch failed: {type(e).__name__}"}), 502
    else:
        r.close()

    _prune_clip_cache()
    resp = send_file(dest, mimetype="video/mp4", conditional=True)
    # The URL already names path+start+duration, so the bytes are immutable.
    # Let the browser keep them; re-seeking within a chunk should not refetch.
    resp.headers["Cache-Control"] = "private, max-age=3600"
    return resp


def _proxy(url, rewrite_prefix=None, params=None):
    try:
        r = requests.get(url, stream=True, timeout=(5, 30), params=params)
    except requests.RequestException as e:
        return jsonify({"error": f"upstream unreachable: {type(e).__name__}"}), 502
    ctype = r.headers.get("Content-Type", "application/octet-stream")

    # Playlists carry relative URLs that would point at the bare HLS port,
    # which is loopback-only and unauthenticated. Rewrite them back through here.
    # The rewrite must PRESERVE each line's own query string - that is where
    # the mediamtx session token lives.
    is_playlist = ("mpegurl" in ctype.lower() or ".m3u8" in url)
    if rewrite_prefix and is_playlist:
        out = []
        for line in r.text.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith(("http://", "https://", "/")):
                out.append(rewrite_prefix + s)
            elif s.startswith('#EXT-X-MAP:URI="'):
                out.append(s.replace('URI="', f'URI="{rewrite_prefix}'))
            else:
                out.append(line)
        return Response("\n".join(out) + "\n", status=r.status_code,
                        content_type=ctype, headers={"Cache-Control": "no-store"})

    return Response(stream_with_context(r.iter_content(chunk_size=64 * 1024)),
                    status=r.status_code, content_type=ctype,
                    headers={"Cache-Control": "no-store"})


@app.route("/export")
@login_required
def export():
    """Download a clip as a real MP4.

    format=mp4 rather than fmp4: fragmented MP4 is what the browser plays but
    a plain MP4 is what opens in everything else, which is the point of a
    download. Verified to come back as h264+aac.

    Duration is capped. An unbounded value would have mediamtx assemble hours
    of footage into one response while the request sits open - trivial to do
    by accident, and it would look like the portal had hung.
    """
    start = request.args.get("start", "")
    try:
        duration = int(request.args.get("duration", "300"))
    except ValueError:
        duration = 300
    duration = max(5, min(duration, 3600))
    if not start:
        return jsonify({"error": "start required"}), 400

    safe = start.replace(":", "-").replace(".", "-").split("+")[0]
    fname = f"parking-lot-{safe}-{duration}s.mp4"

    try:
        r = requests.get(f"{MTX_PLAYBACK}/get", stream=True, timeout=(5, 120),
                         params={"path": RECORD_PATH, "start": start,
                                 "duration": duration, "format": "mp4"})
    except requests.RequestException as e:
        return jsonify({"error": f"upstream unreachable: {type(e).__name__}"}), 502
    if r.status_code != 200:
        return jsonify({"error": "no footage for that range",
                        "upstream": r.status_code}), 404

    return Response(stream_with_context(r.iter_content(chunk_size=256 * 1024)),
                    content_type="video/mp4",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"',
                             "Cache-Control": "no-store"})


ACTIVITY_DIR = os.path.expanduser("~/network-agent/logs/activity")
# Percent-of-frame changed. Empty lot peaks ~0.6; occupied hours reach 1.4-1.7.
ACTIVITY_THRESHOLD = 1.0
# Two bursts closer together than this read as one arrival, not two.
ACTIVITY_MERGE_GAP = 20        # seconds
# Ignore a single twitchy frame - a bird, a raindrop, one sensor glitch.
ACTIVITY_MIN_LEN = 3           # seconds
ACTIVITY_BINS = 1440           # one bin per minute of the day


@app.route("/api/activity")
@login_required
def api_activity():
    """Confirmed car/person events for one LOCAL day, absolute epoch seconds.

    Prefers the detection index (per-UTC-date .det.json from detect_scan, with
    shadows/headlights discarded and each event labelled); falls back to the raw
    motion index for any UTC date not yet detect-scanned. Times are absolute.
    """
    from datetime import datetime, timezone, timedelta
    day = request.args.get("day", "")
    try:
        datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "bad day"}), 400
    local0 = datetime.fromisoformat(day + "T00:00:00").astimezone()
    w0 = local0.timestamp(); w1 = (local0 + timedelta(days=1)).timestamp()
    uds = sorted({datetime.fromtimestamp(w0, timezone.utc).strftime("%Y-%m-%d"),
                  datetime.fromtimestamp(w1 - 1, timezone.utc).strftime("%Y-%m-%d")})
    raw = []
    scanned = False
    for ud in uds:
        base0 = datetime.fromisoformat(ud + "T00:00:00+00:00").timestamp()
        detp = os.path.join(ACTIVITY_DIR, ud + ".det.json")
        motp = os.path.join(ACTIVITY_DIR, ud + ".json")
        if os.path.exists(detp):
            try:
                data = json.load(open(detp)); scanned = True
            except (OSError, ValueError):
                data = None
            if data is not None:
                for name, seg in (data.get("segments") or {}).items():
                    b = base0 + seg.get("start", 0)
                    for ev in seg.get("events") or []:
                        es = b + ev.get("s", 0); ee = b + ev.get("e", 0)
                        if ee < w0 or es >= w1:
                            continue
                        raw.append((max(es, w0), min(ee, w1),
                                    ev.get("l", "object"), float(ev.get("c", 0.5))))
                continue
        if os.path.exists(motp):
            try:
                data = json.load(open(motp)); scanned = True
            except (OSError, ValueError):
                continue
            hits = []; peakraw = 0.0
            for name, seg in (data.get("segments") or {}).items():
                b = base0 + seg.get("start", 0)
                for i, sc in enumerate(seg.get("scores") or []):
                    ep = b + i
                    if ep < w0 or ep >= w1:
                        continue
                    if sc > peakraw: peakraw = sc
                    if sc >= ACTIVITY_THRESHOLD: hits.append((ep, sc))
            hits.sort()
            if hits:
                hs = hp = hits[0][0]; pk = hits[0][1]
                for ep, sc in hits[1:]:
                    if ep - hp <= ACTIVITY_MERGE_GAP:
                        hp = ep; pk = max(pk, sc); continue
                    if hp - hs >= ACTIVITY_MIN_LEN:
                        raw.append((hs, hp, None, pk / peakraw if peakraw else 0.0))
                    hs = hp = ep; pk = sc
                if hp - hs >= ACTIVITY_MIN_LEN:
                    raw.append((hs, hp, None, pk / peakraw if peakraw else 0.0))
    raw.sort(key=lambda x: x[0])
    events = []
    for es, ee, lab, pk in raw:
        if events and lab == events[-1]["_l"] and es - events[-1]["end"] <= ACTIVITY_MERGE_GAP:
            events[-1]["end"] = max(events[-1]["end"], int(ee))
            events[-1]["peak"] = round(max(events[-1]["peak"], pk), 3)
        else:
            events.append({"start": int(es), "end": int(ee), "label": lab,
                           "peak": round(pk, 3), "_l": lab})
    for ev in events:
        ev.pop("_l", None)
    return jsonify({"day": day, "scanned": scanned, "count": len(events),
                    "events": events})

@app.route("/api/recordings")
@login_required
def recordings():
    try:
        r = requests.get(f"{MTX_PLAYBACK}/list", params={"path": RECORD_PATH}, timeout=10)
        r.raise_for_status()
        items = r.json()
    except Exception as e:
        return jsonify({"segments": [], "error": type(e).__name__}), 200
    segs = [{"start": it.get("start", ""), "duration": it.get("duration", 0)}
            for it in items if it.get("start")]
    segs.sort(key=lambda s: s["start"], reverse=True)
    return jsonify({"segments": segs[:2000]})


@app.route("/api/health")
def health():
    """Unauthenticated on purpose: exposes no video and no detail, only whether
    the pieces are talking. The agent polls this."""
    out = {"portal": "ok", "mediamtx": None, "streams": {},
           "pending_signups": None}
    try:
        out["pending_signups"] = users.count_pending()
    except Exception:
        pass
    try:
        r = requests.get(f"{MTX_API}/v3/paths/list", timeout=5)
        r.raise_for_status()
        out["mediamtx"] = "ok"
        for p in r.json().get("items", []):
            if p["name"] in STREAMS:
                out["streams"][p["name"]] = bool(p.get("ready"))
    except Exception as e:
        out["mediamtx"] = f"unreachable: {type(e).__name__}"
    return jsonify(out)


import day_export as _dayexport
_dayexport.register(app, login_required, os.path.expanduser("~/camera-recordings/sd"), MTX_PLAYBACK, RECORD_PATH)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081, threaded=True)
