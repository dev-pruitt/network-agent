#!/usr/bin/env python3
"""Act on sign-up decisions made by Discord reaction.

WHERE THIS SITS
    portal signup -> proposals.jsonl (pending)
    discord_relay -> posts it, seeds the two reactions, and on a reaction from
                     DISCORD_APPROVER_ID sets status approved/denied
    THIS SCRIPT   -> turns that status into the actual account change, which
                     is what sends the resident their email

  The relay records a decision; it does not know what a resident is. Keeping
  the acting here means one place grants access, and the web admin screen and
  the Discord path converge on the same function rather than each having their
  own idea of what approval does.

IDEMPOTENCY IS THE WHOLE JOB
  This runs every five minutes against an append-only log. Acting twice would
  email a resident twice, and acting on a decision the web screen already
  handled would email them again. Two independent guards:

    1. a processed-ids file, so a proposal is acted on once
    2. the user's CURRENT status in the database - if they are no longer
       pending, someone already decided, and this does nothing but close the
       proposal

  The second guard is the one that matters: the state file could be lost, and
  the database is the truth about who has access.

A DECISION IS NOT AN OUTCOME
  Approval writes the account change first and mails second. If mail fails the
  approval still stands and the failure is recorded, because a resident who is
  approved but un-emailed is recoverable, while a resident who was emailed but
  not approved is a support call.
"""
import json
import os
import sys
from datetime import datetime

BASE = os.path.expanduser("~/network-agent")
SCRIPTS = os.path.expanduser("~/network-agent-backup/agent-pc/scripts")
PROPOSALS = os.path.join(BASE, "logs/proposals.jsonl")
NOTICES = os.path.join(BASE, "logs/notices.jsonl")
STATE = os.path.join(BASE, "logs/signup_approver_state.json")

sys.path.insert(0, SCRIPTS)
import portal_users as users            # noqa: E402


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {"processed": []}


def save_state(s):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(s, open(STATE, "w"), indent=2)
    except OSError:
        pass


def notice(eid, title, msg, kind="info"):
    try:
        with open(NOTICES, "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "kind": kind, "event_id": eid, "title": title,
                "message": msg, "source": "signup_approver"}) + "\n")
    except OSError:
        pass


def read_rows():
    rows = []
    try:
        for line in open(PROPOSALS):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return rows


def write_rows(rows):
    tmp = PROPOSALS + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, PROPOSALS)


def user_status(uid):
    with users.connect() as c:
        row = c.execute("SELECT status, email FROM users WHERE id=?",
                        (uid,)).fetchone()
    return (row["status"], row["email"]) if row else (None, None)


def main():
    quiet = "--quiet" in sys.argv
    st = load_state()
    done = set(st.get("processed", []))
    rows = read_rows()
    changed = False
    acted = 0

    def say(*a):
        if not quiet:
            print(*a)

    for r in rows:
        if r.get("anomaly_type") != "resident_signup":
            continue
        pid = r.get("proposal_id")
        status = r.get("status")
        uid = r.get("signup_user_id")

        if status not in ("approved", "denied") or pid in done or not uid:
            continue

        cur_status, email = user_status(uid)
        if cur_status is None:
            say(f"  {pid}: user {uid} no longer exists - closing")
            r["status"] = "resolved"
            r["resolution_note"] = "user record gone"
            done.add(pid)
            changed = True
            continue

        if cur_status != "pending":
            # Already decided elsewhere, almost certainly the web admin screen.
            # Close the proposal, send nothing. Emailing here would be a second
            # message for one decision.
            say(f"  {pid}: already {cur_status} (decided elsewhere) - closing")
            done.add(pid)
            changed = True
            continue

        approve = status == "approved"
        ok, mail_status = users.decide(int(uid), approve)
        acted += 1
        done.add(pid)
        changed = True

        if not ok:
            say(f"  {pid}: FAILED to apply - {mail_status}")
            notice("signup_apply_failed", "sign-up decision could not be applied",
                   f"proposal {pid}, user {uid}: {mail_status}", kind="alert")
            continue

        verdict = "approved" if approve else "denied"
        say(f"  {pid}: {verdict} via discord -> {email}  (mail: {mail_status})")
        notice(f"signup_{verdict}", f"resident {verdict} via Discord",
               f"{email} - mail: {mail_status}",
               kind="recover" if approve else "info")

        if approve and str(mail_status).startswith("FAILED"):
            # The account is live; only the notification failed. Say so loudly,
            # because the resident is now able to sign in and does not know it.
            notice("signup_mail_failed", "approved but the email did not send",
                   f"{email} is approved and can sign in, but the notification "
                   f"failed ({mail_status}). Tell them directly.", kind="alert")

    if changed:
        write_rows(rows)
        st["processed"] = sorted(done)
        save_state(st)

    if not quiet:
        print(f"[signup] {acted} decision(s) applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
