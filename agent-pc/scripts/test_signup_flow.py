#!/usr/bin/env python3
"""Exercise the Discord approval path without touching Discord.

The relay's only output is a status change on a proposal, so setting that
status by hand is a faithful stand-in and tests the part that can actually
hurt someone: acting twice, and emailing a resident who was already decided
on from the web screen.

Cleans up after itself.
"""
import json
import os
import subprocess
import sys

SCRIPTS = os.path.expanduser("~/network-agent-backup/agent-pc/scripts")
PROPOSALS = os.path.expanduser("~/network-agent/logs/proposals.jsonl")
PY = os.path.expanduser("~/network-agent-backup/venv/bin/python3")
sys.path.insert(0, SCRIPTS)
import portal_users as users        # noqa: E402

TEST = "resident-test@example.com"


def rows():
    return [json.loads(l) for l in open(PROPOSALS) if l.strip()]


def write(rs):
    with open(PROPOSALS, "w") as f:
        for r in rs:
            f.write(json.dumps(r) + "\n")


def status_of(email):
    with users.connect() as c:
        r = c.execute("SELECT status, mail_status FROM users WHERE email=?",
                      (email,)).fetchone()
    return (r["status"], r["mail_status"]) if r else (None, None)


def run_approver():
    out = subprocess.run([PY, os.path.join(SCRIPTS, "signup_approver.py")],
                         capture_output=True, text=True)
    return (out.stdout + out.stderr).strip()


print("=== 1. before ===")
print("   user:", status_of(TEST))

print()
print("=== 2. simulate the Discord reaction (relay sets status) ===")
rs = rows()
target = None
for r in rs:
    if r.get("anomaly_type") == "resident_signup" and r.get("status") == "pending":
        r["status"] = "approved"
        r["decided_via"] = "discord"
        target = r["proposal_id"]
write(rs)
print("   marked approved:", target)

print()
print("=== 3. run the approver ===")
print("  ", run_approver().replace("\n", "\n   "))
print("   user now:", status_of(TEST))

print()
print("=== 4. run AGAIN - must do nothing (no second email) ===")
print("  ", run_approver().replace("\n", "\n   "))

print()
print("=== 5. the double-decision case: web screen decided first ===")
# A fresh request, decided in the DB before the proposal is processed.
users.create("second-test@example.com", "averylongpassword2", "9A")
rs = rows()
pid2 = None
for r in rs:
    if (r.get("anomaly_type") == "resident_signup"
            and r.get("status") == "pending"):
        r["status"] = "approved"
        pid2 = r["proposal_id"]
        uid = r["signup_user_id"]
write(rs)
users.decide(int(uid), True)          # web screen acts first
print("   web approved user", uid, "- now running the approver")
print("  ", run_approver().replace("\n", "\n   "))
print("   expect 'already approved (decided elsewhere) - closing', no 2nd email")

print()
print("=== cleanup ===")
with users.connect() as c:
    c.execute("DELETE FROM users WHERE email LIKE '%-test@example.com'")
    c.commit()
write([r for r in rows() if r.get("anomaly_type") != "resident_signup"])
st = os.path.expanduser("~/network-agent/logs/signup_approver_state.json")
if os.path.exists(st):
    os.remove(st)
print("   test users, proposals and state removed")
print("   remaining users:",
      users.connect().execute("SELECT COUNT(*) FROM users").fetchone()[0])
