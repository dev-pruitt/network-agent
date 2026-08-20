"""Shared alert gating: say it once, then stay quiet until something changes.

THE PROBLEM THIS REPLACES
  Every monitor used a fixed cooldown - 4h for the lock, 6h for DoH, 1h for the
  leak watch. A cooldown re-fires forever. On 2026-08-11 the lock alert arrived
  at 00:00, 04:00, 08:00, 12:00, 16:00 and 20:00 carrying identical text, and
  the 20:00 copy announced "seen on 281 consecutive checks". The monitor had
  counted to 281 and still introduced itself from scratch. Twenty-two alerts
  that day; four carried information.

  The fault was never detection. Detection was right every time. What was
  missing is any notion of "already reported".

THE RULE HERE
  Alert on the TRANSITION, not on the CONDITION.

  A fingerprint describes what is materially true - not the readings that
  wobble. The lock's latency moved 785 -> 853 -> 732 -> 1168 -> 398 ms across
  the day. None of that is news; the lock is wedged either way, so its
  fingerprint is just "wedged" and it speaks once. The DoH watcher's resolver
  DID change, Google -> Cloudflare, and that is worth exactly one more alert.

  Same fingerprint  -> silent (the digest still lists it as standing)
  New fingerprint   -> alert once
  Condition clears  -> reset, so a genuine recurrence is heard

GUARDS
  min_gap    anti-flap. A condition oscillating between two fingerprints cannot
             page faster than this, or "alert on change" becomes its own spam.
  heartbeat  a standing fault re-announces this rarely (default 7 days) so an
             indefinitely-open item cannot fall out of memory entirely.

WHAT THIS DOES NOT DO
  It does not decide whether something is broken - the monitor still does that,
  unchanged. It only decides whether you have already been told. A suppressed
  alert is still written to the monitor's own diagnostic log; suppression
  affects notification, never the record.
"""

from datetime import datetime, timedelta

# Namespaced so this cannot collide with a monitor's own state keys.
FP_KEY = "alert_fp"
AT_KEY = "alert_fp_at"
SUPPRESSED_KEY = "alert_suppressed"
FIRST_KEY = "alert_first_at"

DEFAULT_MIN_GAP = timedelta(minutes=30)
DEFAULT_HEARTBEAT = timedelta(days=7)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def gate(state, fingerprint, now=None,
         min_gap=DEFAULT_MIN_GAP, heartbeat=DEFAULT_HEARTBEAT):
    """Decide whether this condition should notify.

    Returns (should_alert: bool, reason: str). The caller MUST call commit()
    when it actually sends, so a send that fails does not mark the condition
    as reported - that would lose the alert entirely.
    """
    now = now or datetime.now()
    fingerprint = str(fingerprint)
    prev = state.get(FP_KEY)
    last_at = _parse(state.get(AT_KEY))

    if not prev:
        return True, "first occurrence"

    if fingerprint != prev:
        # Something material changed. Worth hearing - but not faster than
        # min_gap, or a condition flapping between two states pages endlessly.
        if last_at and now - last_at < min_gap:
            state[SUPPRESSED_KEY] = state.get(SUPPRESSED_KEY, 0) + 1
            return False, f"changed but within {min_gap} anti-flap window"
        return True, f"changed: {prev!r} -> {fingerprint!r}"

    if last_at and now - last_at >= heartbeat:
        return True, f"still open after {heartbeat}"

    state[SUPPRESSED_KEY] = state.get(SUPPRESSED_KEY, 0) + 1
    return False, "unchanged since last alert"


def commit(state, fingerprint, now=None):
    """Record that an alert was actually delivered."""
    now = now or datetime.now()
    if not state.get(FIRST_KEY) or state.get(FP_KEY) != str(fingerprint):
        state[FIRST_KEY] = now.isoformat(timespec="seconds")
    state[FP_KEY] = str(fingerprint)
    state[AT_KEY] = now.isoformat(timespec="seconds")
    state[SUPPRESSED_KEY] = 0
    return state


def clear(state):
    """The condition is no longer present.

    Drops the fingerprint so a later recurrence is treated as new. Without
    this, a fault that fixes itself and returns a week later would stay silent
    because the fingerprint still matched.
    """
    for k in (FP_KEY, AT_KEY, SUPPRESSED_KEY, FIRST_KEY):
        state.pop(k, None)
    return state


def standing(state):
    """What the digest needs: is something open, since when, how many muted.

    Returns None when nothing is open.
    """
    if not state.get(FP_KEY):
        return None
    first = _parse(state.get(FIRST_KEY)) or _parse(state.get(AT_KEY))
    return {
        "fingerprint": state.get(FP_KEY),
        "since": state.get(FIRST_KEY) or state.get(AT_KEY),
        "last_alert": state.get(AT_KEY),
        "suppressed": state.get(SUPPRESSED_KEY, 0),
        "age_hours": round((datetime.now() - first).total_seconds() / 3600, 1)
        if first else None,
    }
