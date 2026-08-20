"""Login brute-force throttle for the camera portal.

WHY THIS EXISTS
  The login route already sleeps 1s on a wrong password ("blunt online
  guessing", see the comment next to it) but that only slows a SINGLE
  connection. Nothing capped the total number of guesses an attacker could
  make with several connections at once, against either the resident login
  or the admin account - the highest-value target on this box, since admin
  reaches the settings screen and every resident's data, not just one
  apartment's camera feed.

WHO THIS PROTECTS AND HOW
  Cloudflare Tunnel is the only way to reach this app (camera-portal.service
  binds loopback only). Cloudflare's edge always sets Cf-Connecting-Ip to the
  real visitor's address before forwarding through the tunnel - the client
  cannot forge it, because the tunnel replaces whatever header the client
  sent with what the edge itself observed. That is the identity this module
  locks on, via client_ip() in camera_portal.py.

RULES
  5 failed attempts from one IP inside a 10-minute window locks that IP out.
  Lockout starts at 15 minutes and DOUBLES each time the IP fails again
  during or right after a lockout, capped at 24h - a resident who mistypes
  a password five times running should not lose a whole day, but a script
  that keeps trying past every lockout should.
  A single successful login clears the IP's record entirely.

FAILS OPEN ON A BROKEN STATE FILE, NOT ON THE MECHANISM
  If the state file cannot be read, this treats it as "nobody is currently
  locked out" - it does NOT lock every resident out over one corrupt JSON
  file, and it does NOT stop counting failures going forward (that would
  silently disable the whole point of the module, the same class of bug as
  the DoH fingerprint that truncated at 240 chars and silently dropped the
  one detail that mattered). A read failure loses history, never protection.
"""
import json
import os
import time

STATE_DIR = os.path.expanduser("~/network-agent-backup/camera")
STATE = os.path.join(STATE_DIR, "login_throttle.json")

MAX_FAILS = 5
WINDOW_SEC = 10 * 60
BASE_LOCKOUT_SEC = 15 * 60
MAX_LOCKOUT_SEC = 24 * 60 * 60


def _load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(d):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, STATE)
    except OSError:
        pass


def _entry(state, ip):
    return state.setdefault(ip, {"fails": [], "locked_until": 0, "lockouts": 0})


# An IP that failed once and never came back would otherwise sit in this file
# forever. Slow growth (text, only on failed logins) but unbounded is still
# unbounded, so entries are dropped once they can no longer affect a decision:
# not locked out, no fails inside the window, and long enough past the last
# activity that the escalating-lockout ladder should reset anyway.
FORGET_SEC = 24 * 60 * 60


def _prune(state, now):
    """Drop entries that can no longer change any outcome. Returns state.

    Deliberately conservative: an IP is only forgotten when it is NOT locked
    out AND has no live failures AND its last activity is older than
    FORGET_SEC. Forgetting an IP resets its lockout ladder, so pruning too
    eagerly would hand a patient attacker a free reset - which is why this
    keys on last activity rather than just "not currently locked".
    """
    for ip in list(state.keys()):
        e = state.get(ip) or {}
        if e.get("locked_until", 0) > now:
            continue
        fails = [t for t in e.get("fails", []) if now - t < WINDOW_SEC]
        last = max(fails + [e.get("locked_until", 0)] or [0])
        if fails:
            e["fails"] = fails
            continue
        if now - last >= FORGET_SEC:
            del state[ip]
    return state


def check(ip, now=None):
    """(locked: bool, retry_after_seconds: int). Read-only - does not record
    anything, so loading the login FORM never counts as an attempt, only
    submitting wrong credentials does."""
    now = now or time.time()
    state = _load()
    e = state.get(ip)
    if not e:
        return False, 0
    remaining = e.get("locked_until", 0) - now
    if remaining > 0:
        return True, int(remaining) + 1
    return False, 0


def record_failure(ip, now=None):
    """Call once, after a confirmed wrong credential. Returns (locked,
    retry_after_seconds) in the same shape as check(), so the caller renders
    one message either way."""
    now = now or time.time()
    state = _load()
    e = _entry(state, ip)

    e["fails"] = [t for t in e["fails"] if now - t < WINDOW_SEC] + [now]

    locked, retry_after = False, 0
    if len(e["fails"]) >= MAX_FAILS:
        e["lockouts"] = e.get("lockouts", 0) + 1
        lockout_sec = min(BASE_LOCKOUT_SEC * (2 ** (e["lockouts"] - 1)),
                          MAX_LOCKOUT_SEC)
        e["locked_until"] = now + lockout_sec
        e["fails"] = []          # the lockout itself is the record now
        locked, retry_after = True, int(lockout_sec)

    _prune(state, now)
    _save(state)
    return locked, retry_after


def record_success(ip):
    """A legitimate sign-in. Wipe the IP's history - it was not the threat
    the fail count made it look like."""
    state = _load()
    changed = ip in state
    if changed:
        del state[ip]
    before = len(state)
    _prune(state, time.time())
    if changed or len(state) != before:
        _save(state)
