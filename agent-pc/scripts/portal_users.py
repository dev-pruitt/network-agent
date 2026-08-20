"""Resident accounts: SQLite store, password hashing, approval workflow, email.

AUTO-APPROVAL (2026-08-19, per agent)
  New sign-ups are approved the moment they submit the form - create() writes
  status='approved' directly and sends the welcome email immediately. There
  is no more human review step. This removes the one piece of verification
  the system had (a person judging whether a request looked real), and the
  apartment number was always free text with nothing to check it against, so
  there is nothing else standing between a stranger and 30 days of footage.
  The admin screen, revoke, and the Discord heads-up notification still work
  exactly as before - revoke is the only backstop left.

WHY THERE IS NO DOOR CODE IN HERE
  The original design verified sign-ups against the building's door entry
  code. Verifying it means storing it, a 4-6 digit code survives hashing for
  about a second under brute force, and it identifies nobody - every resident,
  ex-resident and delivery driver knows it. It would have put physical access
  to a residential building on an internet-facing box in exchange for no real
  verification. Approval by a human does the job with no secret at all.

PASSWORDS
  werkzeug's generate_password_hash (scrypt). Never stored, never logged,
  never emailed. That last one is why the approval email does not carry
  credentials: the resident chose the password, and the only way to send it
  back would be to have kept it in plaintext.

APPROVAL EMAIL
  Reuses the SMTP relay already configured for router alerts. Sending is
  best-effort and NEVER blocks approval - a mail outage must not silently
  leave a resident un-approved in the database while the operator believes
  they approved them. Failures are recorded and shown in the admin screen.
"""
import json
import os
import re
import smtplib
import sqlite3
import ssl
from datetime import datetime
from email.message import EmailMessage

from werkzeug.security import check_password_hash, generate_password_hash

DB_DIR = os.path.expanduser("~/network-agent-backup/camera")
DB = os.path.join(DB_DIR, "users.db")
MAIL_CONF = os.path.expanduser("~/network-agent-backup/agent-pc/config/mail.conf")
PORTAL_URL = "https://cam.example.com"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
def connect():
    os.makedirs(DB_DIR, exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with connect() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                apartment     TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                note          TEXT,
                created_at    TEXT NOT NULL,
                decided_at    TEXT,
                last_login    TEXT,
                mail_status   TEXT
            )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_status ON users(status)")
    os.chmod(DB, 0o600)


# ---------------------------------------------------------------------------
def validate(email, password, apartment):
    """Returns an error string, or None when acceptable."""
    email = (email or "").strip().lower()
    apartment = (apartment or "").strip()
    if not EMAIL_RE.match(email):
        return "That does not look like an email address."
    if len(password or "") < 10:
        return "Password must be at least 10 characters."
    if not apartment:
        return "Apartment number is required."
    if len(apartment) > 16:
        return "Apartment number looks too long."
    return None


PROPOSALS = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
SETTINGS = os.path.expanduser("~/network-agent-backup/config/camera-settings.conf")


def _mask_email_enabled():
    """Whether to mask the address before it leaves the network.

    A sign-up notice sent to Discord puts a resident's email and apartment on
    a third-party service. The operator needs enough to judge whether the
    request is genuine, so the default shows both - but this makes that a
    decision rather than an accident.
    """
    if not os.path.exists(SETTINGS):
        return False
    for line in open(SETTINGS):
        line = line.strip()
        if line.startswith("mask_signup_email"):
            return line.partition("=")[2].strip().lower() in ("yes", "true", "1", "on")
    return False


def mask_email(addr):
    name, _, dom = addr.partition("@")
    keep = name[:2] if len(name) > 2 else name[:1]
    return f"{keep}{'*' * max(len(name) - len(keep), 1)}@{dom}"


def _emit_signup_proposal(user_id, email, apartment):
    """Raise the sign-up as a proposal so the existing Discord relay posts it.

    Reuses the approval path already in place rather than adding a second one:
    the relay posts pending proposals, seeds the two reactions, and only counts
    a reaction from DISCORD_APPROVER_ID. Two mechanisms that can both grant
    access is one more than anybody can keep straight.
    """
    shown = mask_email(email) if _mask_email_enabled() else email
    rec = {
        "proposal_id": f"S{datetime.now():%m%d%H%M%S}-signup{user_id}",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anomaly_type": "resident_signup",
        "component": "camera-portal",
        "severity": 2,
        "details": (f"Camera access AUTO-APPROVED for {shown}, apartment "
                    f"{apartment}. Already active - this is a heads-up, "
                    f"not a request."),
        "recommended_action": ("Nothing required. Reactions here no longer do "
                               "anything - revoke from /admin if this should "
                               "not have access."),
        "playbook_id": "PB-SIGNUP-001",
        "source": "camera_portal",
        "status": "pending",
        "signup_user_id": user_id,
    }
    try:
        os.makedirs(os.path.dirname(PROPOSALS), exist_ok=True)
        with open(PROPOSALS, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        # A notification that cannot be written must not fail the sign-up.
        # The request is already in the database and visible in the portal.
        pass


def create(email, password, apartment):
    """Returns (ok, message). Duplicate emails are reported without saying
    whether that address already has an account - that would let anyone test
    which residents are registered.

    Auto-approves on insert (see module docstring) - status is written as
    'approved', not 'pending', and the welcome email goes out immediately
    the same way decide() sends it for a manual approval. Mail is still
    best-effort and never undoes the approval: a resident approved but
    un-emailed is recoverable from /admin, one approved-and-emailed-twice by
    a retry here would not be.
    """
    email = email.strip().lower()
    err = validate(email, password, apartment)
    if err:
        return False, err
    apartment = apartment.strip()
    now = datetime.now().isoformat(timespec="seconds")
    try:
        with connect() as c:
            cur = c.execute(
                "INSERT INTO users "
                "(email,password_hash,apartment,status,created_at,decided_at)"
                " VALUES (?,?,?,'approved',?,?)",
                (email, generate_password_hash(password), apartment, now, now))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return True, "request-received"      # deliberately indistinguishable

    mail_ok, mail_detail = send_approval_email(email, apartment)
    mail_status = "sent" if mail_ok else f"FAILED: {mail_detail}"
    with connect() as c:
        c.execute("UPDATE users SET mail_status=? WHERE id=?", (mail_status, uid))

    _emit_signup_proposal(uid, email, apartment)
    return True, "request-received"


def authenticate(email, password):
    """Returns (user_row, reason). reason explains a refusal for the UI."""
    email = (email or "").strip().lower()
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password or ""):
        return None, "Email or password is incorrect."
    if row["status"] == "pending":
        return None, "Your account is waiting for approval by the building manager."
    if row["status"] != "approved":
        return None, "This account does not have access."
    with connect() as c:
        c.execute("UPDATE users SET last_login=? WHERE id=?",
                  (datetime.now().isoformat(timespec="seconds"), row["id"]))
    return row, ""


def change_password(email, current, new):
    """Requires the CURRENT password. Returns (ok, message).

    Verifying the old password matters even though the session is already
    authenticated: it stops an unattended logged-in browser from being used
    to lock the real owner out of their own account.
    """
    email = (email or "").strip().lower()
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], current or ""):
        return False, "Current password is incorrect."
    if len(new or "") < 10:
        return False, "New password must be at least 10 characters."
    if new == current:
        return False, "That is the password you already have."
    with connect() as c:
        c.execute("UPDATE users SET password_hash=? WHERE id=?",
                  (generate_password_hash(new), row["id"]))
    return True, "Password changed."


def list_users(status=None):
    q = "SELECT * FROM users"
    args = ()
    if status:
        q += " WHERE status=?"
        args = (status,)
    q += " ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC"
    with connect() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def count_pending():
    with connect() as c:
        return c.execute("SELECT COUNT(*) FROM users WHERE status='pending'").fetchone()[0]


def decide(user_id, approved, note=""):
    """Approve or deny, then TRY to email. Mail never blocks the decision."""
    status = "approved" if approved else "denied"
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return False, "no such user"
        c.execute("UPDATE users SET status=?, note=?, decided_at=? WHERE id=?",
                  (status, note or None,
                   datetime.now().isoformat(timespec="seconds"), user_id))

    mail_status = "not sent (denied)"
    if approved:
        ok, detail = send_approval_email(row["email"], row["apartment"])
        mail_status = "sent" if ok else f"FAILED: {detail}"
    with connect() as c:
        c.execute("UPDATE users SET mail_status=? WHERE id=?", (mail_status, user_id))
    return True, mail_status



# ---------------------------------------------------------------------------
# Access removal.
#
# Two different actions, deliberately kept apart:
#   revoke  - reversible. The row stays, so the audit trail (when they signed
#             up, when they were approved, last login) survives. authenticate()
#             already refuses any status that is not 'approved', so this alone
#             stops a future sign-in.
#   remove  - permanent. Use for a mistaken sign-up or a request to erase the
#             record. Frees the email so the address can sign up again.
#
# Neither touches recorded footage.

VALID_STATUSES = ("pending", "approved", "denied", "revoked")


def status_of(email):
    """Current status for an email, or None if unknown.

    Read on every authenticated request so a revoke takes effect at once
    rather than whenever the session cookie happens to expire. It is a single
    indexed lookup against a local SQLite file - cheap enough for the HLS
    segment rate.
    """
    email = (email or "").strip().lower()
    if not email:
        return None
    try:
        with connect() as c:
            row = c.execute("SELECT status FROM users WHERE email=?",
                            (email,)).fetchone()
    except sqlite3.Error:
        # Cannot observe is not the same as observed-revoked. Report the
        # inability instead of inventing a status; the caller decides.
        return "unknown"
    return row["status"] if row else None


def set_status(user_id, status, note=""):
    """Move a user to any valid status. Returns (ok, message)."""
    if status not in VALID_STATUSES:
        return False, f"refusing unknown status {status!r}"
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            return False, "no such user"
        c.execute("UPDATE users SET status=?, note=?, decided_at=? WHERE id=?",
                  (status, note or row["note"],
                   datetime.now().isoformat(timespec="seconds"), user_id))
    return True, f"{row['email']} is now {status}"


def revoke(user_id, note="revoked by building management"):
    """Turn off access, keep the record. Reversible with restore()."""
    return set_status(user_id, "revoked", note)


def restore(user_id, note="access restored"):
    """Turn access back on.

    No approval email is re-sent: the resident already has their password,
    and a second 'you are approved' message to someone who was quietly
    revoked and un-revoked invites a question nobody wants to answer twice.
    """
    return set_status(user_id, "approved", note)


def remove(user_id):
    """Delete the row outright. Returns (ok, message)."""
    with connect() as c:
        row = c.execute("SELECT email FROM users WHERE id=?",
                        (user_id,)).fetchone()
        if not row:
            return False, "no such user"
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
    return True, f"{row['email']} deleted"

# ---------------------------------------------------------------------------
def _mail_conf():
    if not os.path.exists(MAIL_CONF):
        return None
    c = {}
    for line in open(MAIL_CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            c[k.strip()] = v.strip().strip('"').strip("'")
    return c if c.get("MAIL_ADDR") and c.get("MAIL_PASS") else None


BODY_TEXT = """Hello,

Your request to view the parking lot camera for apartment {apt} has been
approved by building management.

You can sign in here:
{url}

Sign in with the email address you used to sign up ({email}) and the password
you chose at that time. Passwords are stored scrambled and are never sent by
email, so if you have forgotten yours, just reply to this message.

Once signed in you can see the live view and recorded footage from the last
30 days.

Building management
"""

BODY_HTML = """<!doctype html>
<html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;
color:#2a2018;line-height:1.5;max-width:520px">
<p>Hello,</p>
<p>Your request to view the parking lot camera for <b>apartment {apt}</b> has
been approved by building management.</p>
<p><a href="{url}"
   style="display:inline-block;background:#7a2e19;color:#f6ecd6;
   text-decoration:none;padding:11px 20px;border-radius:8px;font-weight:600">
   Sign in to the camera</a></p>
<p>Sign in with the email you used to sign up ({email}) and the password you
chose then. Passwords are stored scrambled and are never sent by email &mdash;
if you have forgotten yours, just reply to this message.</p>
<p>Once signed in you can see the live view and recorded footage from the last
30 days.</p>
<p style="color:#8a6a3a">Building management</p>
</body></html>
"""


def send_approval_email(to_addr, apartment):
    """Best effort. Returns (ok, detail). Detail never contains the password."""
    import email.utils
    conf = _mail_conf()
    if not conf:
        return False, "no mail config"

    url = conf.get("SMTP_URL", "smtp.mail.me.com:587")
    host, _, port = url.replace("smtp://", "").partition(":")
    try:
        port = int(port or 587)
    except ValueError:
        port = 587

    sender = conf["MAIL_ADDR"]
    domain = sender.split("@")[-1] if "@" in sender else "icloud.com"

    msg = EmailMessage()
    msg["Subject"] = "Your parking lot camera access is ready"
    # A real display name reads less like bulk mail than a bare address.
    msg["From"] = email.utils.formataddr(("Broadway Market", sender))
    msg["To"] = to_addr
    msg["Reply-To"] = sender
    # Date and Message-ID are NOT added automatically and their absence is a
    # spam signal. Set both, Message-ID scoped to the sending domain.
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=domain)

    # Plain first, HTML as the alternative. Carrying both scores more
    # legitimate than either alone.
    msg.set_content(BODY_TEXT.format(apt=apartment, url=PORTAL_URL, email=to_addr))
    msg.add_alternative(
        BODY_HTML.format(apt=apartment, url=PORTAL_URL, email=to_addr),
        subtype="html")

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=ctx)
            s.login(sender, conf["MAIL_PASS"])
            s.send_message(msg)
        return True, "ok"
    except Exception as e:
        # Type only. An SMTP error string can echo the address and sometimes
        # part of the credential back into a log.
        return False, type(e).__name__


init_db()
