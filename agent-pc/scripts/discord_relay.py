#!/usr/bin/env python3
"""Discord approval bridge - replaces the IMAP approval workflow.

WHY THIS REPLACES EMAIL
-----------------------
approval_monitor.py parsed IMAP for "approve-<ID>" strings. Over its entire
operating life it processed 0 approvals against 29 proposals. Email is a poor
approval channel: UID tracking, threading, and free-text parsing all have to
work perfectly, and any one of them silently drops the decision.

Here the decision is a reaction, not text. Reading it is one API call that
returns a list of user IDs. There is nothing to parse and nothing to mis-parse.

SECURITY
--------
- Only reactions from DISCORD_APPROVER_ID count. Anyone else reacting is
  ignored, so a public channel is still safe for approvals.
- This script NEVER executes anything. It only marks proposals approved or
  denied. execute_action.py remains the sole executor and keeps enforcing
  guardrails.toml, cooldowns, and the escalation levels.
- Level 3 proposals are posted for visibility but cannot be approved here;
  they require manual intervention by design.

NETWORK
-------
Forces IPv4. The agent had a broken IPv6 default route that stalled every
outbound connection ~10s. The route is fixed, but pinning to v4 keeps this
path deterministic.
"""
import json
import os
import socket
import time
import urllib.error
import urllib.request

# --- force IPv4 (see module docstring) --------------------------------------
_orig_gai = socket.getaddrinfo
def _gai_v4(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_gai(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _gai_v4

BASE       = os.path.expanduser("~/network-agent")
CONF       = os.path.join(BASE, "config/discord.conf")
PROPOSALS  = os.path.join(BASE, "logs/proposals.jsonl")
APPROVALS  = os.path.join(BASE, "logs/approvals.jsonl")
POSTED     = os.path.join(BASE, "logs/discord_posted.json")

API        = "https://discord.com/api/v10"
MAX_POST   = 4          # per run, to stay well inside rate limits
OK, NO     = "✅", "❌"     # white_check_mark, x


def load_conf():
    cfg = {}
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip("'\"")
    missing = [k for k in ("DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID",
                           "DISCORD_APPROVER_ID") if not cfg.get(k)]
    if missing:
        raise SystemExit(f"[FATAL] discord.conf missing: {', '.join(missing)}")
    if "PASTE" in cfg["DISCORD_BOT_TOKEN"]:
        raise SystemExit("[FATAL] token placeholder not replaced")
    return cfg


def api(cfg, method, path, body=None, retries=3):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bot " + cfg["DISCORD_BOT_TOKEN"])
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "NetworkAgent (self-hosted, 1.0)")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 429:                       # rate limited
                try:
                    wait = json.loads(e.read()).get("retry_after", 2)
                except Exception:
                    wait = 2
                time.sleep(float(wait) + 0.5)
                continue
            print(f"[ERROR] {method} {path} -> HTTP {e.code}")
            return None
        except Exception as e:
            if attempt == retries - 1:
                print(f"[ERROR] {method} {path} -> {e}")
                return None
            time.sleep(2 * (attempt + 1))
    return None


def read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def write_jsonl(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, path)


def load_posted():
    try:
        with open(POSTED) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_posted(d):
    tmp = POSTED + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, POSTED)


# ---------------------------------------------------------------------------
# Notification gate: say it once, then stay quiet until something changes.
#
# Added 2026-08-11 after a day that produced 24 notifications of which 4 were
# informative. The monitors were right every time; nothing tracked whether the
# operator had ALREADY been told. A fixed cooldown re-fires forever - the lock
# alert reached "281 consecutive checks" and still introduced itself.
#
# This gates NOTIFICATION only. proposals.jsonl is untouched, so the digest and
# any later audit still see every detection.
# ---------------------------------------------------------------------------
import re as _re
import hashlib as _hashlib
try:
    import alert_state as _astate
except ImportError:                      # module missing -> gate disables
    _astate = None                       # itself rather than dropping alerts

QUIET_STATE = os.path.join(BASE, "logs/alert_gate_state.json")

# Alert types where the generic number-stripped fingerprint is still too
# twitchy, with the reason.
_FP_OVERRIDE = {
    # Which WAN leaked varies from run to run, but the material fact is
    # that the router is leaking at all. Keyed on the bare
    # fact so it speaks once, not once per WAN combination.
    "router_leak": lambda p: "leaking",
    # drain_router_alerts prefixes the router own alert name, so the wire
    # anomaly_type is router_router_leak, not router_leak. Without this alias the
    # override above is inert and every WAN combo (ISP vs ISP+Carrier)
    # is a fresh fingerprint that re-pages. Verified: 3 fps collapse to 1.
    # Recovery still clears via reconcile (router_router_leak is not escalate-only).
    "router_router_leak": lambda p: "leaking",
    # The live emitter now types the anomaly router_tunnel_leak; the two
    # aliases above are legacy names and no longer match, leaving the
    # "speak once" collapse inert. Track the current name too. Additive;
    # legacy aliases kept. (refinement run 2026-08-16)
    "router_tunnel_leak": lambda p: "leaking",
    # DoH: the offending device only ever toggles between two already-
    # known public resolvers. Resolver NAMES are words, not stripped
    # numbers, so each flip read as a NEW condition and re-paged. Collapse
    # the acknowledged set to one voice; a genuinely new resolver still
    # pages once (a new endpoint to block). See _doh_fp.
    "dns_escape_doh": lambda p: _doh_fp(p),
    # Severity bucket only; the exact ms is noise. Paired with _ESCALATE_ONLY
    # below so a tunnel RECOVERING does not page.
    "performance_degradation": lambda p: (
        "%s:%s" % (p.get("component", "?"),
                   "major" if _pct_of(p) >= 100 else "minor")),
    # recorder_recovered's details text is a static sentence with no numbers
    # or names in it ("Recording had stalled; auto-restarted mediamtx and it
    # recovered."). The generic number-stripped fingerprint hashes to the same
    # value for every occurrence forever, so after the first real stall+
    # recovery, every LATER independent stall+recovery silently collapsed into
    # the same fingerprint and never posted again - confirmed 2026-08-19: the
    # 2026-08-16 incident posted, the 2026-08-18 incident (a separate, real
    # recovery two days later) was suppressed 297 times and never told to
    # agent. This is a discrete point-in-time incident, not a standing
    # condition, so it needs an entity to distinguish occurrences the way DoH
    # uses the resolver name. Day-bucket the timestamp: repeats within the same
    # day still collapse (a flapping recorder should not spam), but a new day's
    # incident is material and pages once.
    "recorder_recovered": lambda p: str(p.get("timestamp", "?"))[:10],
}
_ESCALATE_ONLY = {"performance_degradation": {"minor": 1, "major": 2}}


def _pct_of(p):
    m = _re.search(r"\+(\d+)%", str(p.get("details", "")))
    return int(m.group(1)) if m else 0

# DoH resolvers already surfaced and acknowledged as a standing fault.
# The monitor re-proposes every ~6h and the device flips between these,
# which under the number-stripped fingerprint reads as new each time
# because resolver names are text. Collapse the known set to one
# fingerprint; anything outside it is a new endpoint and still pages.
# Fail-loud: an unparseable resolver gets a unique fingerprint so it is
# never silently swallowed.
_DOH_ACK = {"cloudflare", "google"}


def _doh_fp(p):
    d = str(p.get("details", ""))
    marker = d.find("Observed:")
    if marker == -1:
        return "unparsed:" + _hashlib.md5(d.encode("utf-8", "replace")).hexdigest()[:10]
    # Multiple resolvers can be named in one cycle: "Cloudflare (..); Google
    # (..)". re.search only ever returns the FIRST match, so a genuinely new
    # resolver riding alongside an already-acknowledged one was invisible -
    # the fingerprint still came out "known" and the new endpoint would have
    # waited for the 7-day heartbeat instead of paging when it first showed up.
    # (refinement run 2026-08-17) Check every name in the list, not just the first.
    names = [n.strip().lower()
             for n in _re.findall(r"([A-Za-z0-9.\- ]+?)\s*\(", d[marker:])]
    names = [n for n in names if n]
    if not names:
        return "unparsed:" + _hashlib.md5(d.encode("utf-8", "replace")).hexdigest()[:10]
    unknown = sorted(set(names) - _DOH_ACK)
    if not unknown:
        return "known"
    return "new:" + ",".join(unknown)


def _fingerprint(p):
    """What is MATERIALLY true, ignoring readings that wobble."""
    typ = p.get("anomaly_type", "?")
    if typ in _FP_OVERRIDE:
        return "%s|%s" % (typ, _FP_OVERRIDE[typ](p))
    # Strip every number. The lock's 785/853/732/1168/398 ms all collapse to
    # one fingerprint; "Observed: Google" vs "Observed: Cloudflare" do not.
    det = _re.sub(r"[-+]?\d[\d,.:]*", "#", str(p.get("details", "")))
    det = _re.sub(r"\s+", " ", det).strip()
    # Hash the WHOLE normalised string rather than truncating it. An earlier
    # draft cut at 240 chars, which silently discarded the tail - and for the
    # DoH alert the tail is "Observed: Cloudflare (#)", the only part that
    # distinguishes one resolver from another. Truncation would have muted the
    # single most useful alert of the day. A readable prefix is kept for logs.
    digest = _hashlib.md5(det.encode("utf-8", "replace")).hexdigest()[:10]
    return "%s|%s|%s|%s" % (p.get("component", "?"), typ, det[:60], digest)


def _quiet_load():
    try:
        with open(QUIET_STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _quiet_save(d):
    try:
        os.makedirs(os.path.dirname(QUIET_STATE), exist_ok=True)
        tmp = QUIET_STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, QUIET_STATE)
    except OSError:
        pass


def quiet_gate(store, p):
    """(should_post, reason, commit). Fails OPEN - a broken gate must not lose
    alerts. commit() records that the alert was delivered; the caller MUST call
    it ONLY after a confirmed send, so a failed send is retried next run instead
    of being silently marked as reported (alert_state's documented contract)."""
    _noop = lambda: None
    if _astate is None:
        return True, "gate unavailable", _noop
    typ = p.get("anomaly_type", "?")
    # Level 1 items are things a human must answer (sign-ups). Never suppressed.
    if int(p.get("severity", 2) or 2) <= 1:
        return True, "actionable, never suppressed", _noop
    key = "%s|%s" % (p.get("component", "?"), typ)
    st = store.setdefault(key, {})
    fp = _fingerprint(p)
    ladder = _ESCALATE_ONLY.get(typ)
    if ladder:
        prev = st.get(_astate.FP_KEY)
        if prev:
            now_rank = ladder.get(fp.rsplit(":", 1)[-1], 0)
            prev_rank = ladder.get(prev.rsplit(":", 1)[-1], 0)
            if now_rank <= prev_rank:
                # Recovery, or the same grade again. Not news.
                st[_astate.SUPPRESSED_KEY] = st.get(_astate.SUPPRESSED_KEY, 0) + 1
                return False, "not an escalation (%s -> %s)" % (prev, fp), _noop
    ok, why = _astate.gate(st, fp)
    # Do NOT commit here: committing before the send means a failed post would
    # mark the condition "already told" and the alert is lost. Return a closure
    # the caller runs only after post_proposal confirms delivery.
    def _commit():
        _astate.commit(st, fp)
    return ok, why, (_commit if ok else _noop)


def reconcile_gate(store, proposals):
    """Clear gate flags whose condition no longer has a pending proposal.

    A recovery that closes its proposal but does not clear the gate leaves the
    fingerprint standing, so the NEXT occurrence matches it and is silently
    suppressed. Clearing here (alert_state.clear) means a recurrence is heard.
    Escalate-only types are exempt: staying quiet between escalations is the
    point, and clearing them would re-page every minor blip. Returns keys cleared.
    """
    if _astate is None:
        return []
    pending = {"%s|%s" % (q.get("component", "?"), q.get("anomaly_type", "?"))
               for q in proposals if q.get("status") == "pending"}
    cleared = []
    for key in list(store.keys()):
        if key.split("|", 1)[-1] in _ESCALATE_ONLY:
            continue
        if store[key].get(_astate.FP_KEY) and key not in pending:
            _astate.clear(store[key])
            if not store[key]:
                del store[key]
            cleared.append(key)
    return cleared


def dedupe_pending(proposals):
    """Collapse repeat proposals for the same issue.

    The queue is dominated by repeated latency-degradation reports for the
    same two tunnels. Posting all of them would bury the signal. Keep the
    newest per (anomaly_type, component) and mark the rest superseded, so
    the channel shows current state rather than a backlog.
    """
    newest, superseded = {}, []
    for p in proposals:
        if p.get("status") != "pending":
            continue
        key = (p.get("anomaly_type"), p.get("component"))
        prev = newest.get(key)
        if prev is None or p.get("timestamp", "") > prev.get("timestamp", ""):
            if prev is not None:
                superseded.append(prev)
            newest[key] = p
        else:
            superseded.append(p)
    return list(newest.values()), superseded


SEV_COLOR = {1: 0x639922, 2: 0xBA7517, 3: 0xE24B4A}


def post_proposal(cfg, p):
    sev = int(p.get("severity", 2))
    lvl3 = sev >= 3
    fields = [
        {"name": "Component", "value": str(p.get("component", "?")), "inline": True},
        {"name": "Severity", "value": f"Level {sev}", "inline": True},
        {"name": "Detected", "value": str(p.get("timestamp", "?"))[:19].replace("T", " "), "inline": True},
        {"name": "Recommended action", "value": str(p.get("recommended_action", "?"))[:1000]},
    ]
    footer = ("Level 3 - manual intervention required. Reactions are disabled."
              if lvl3 else f"React {OK} to approve  |  {NO} to deny")
    body = {"embeds": [{
        "title": f"{p.get('anomaly_type', 'anomaly')}  -  {p.get('proposal_id')}",
        "description": str(p.get("details", ""))[:2000],
        "color": SEV_COLOR.get(sev, 0xBA7517),
        "fields": fields,
        "footer": {"text": footer},
    }]}
    msg = api(cfg, "POST", f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages", body)
    if not msg:
        return None
    if not lvl3:
        for emoji in (OK, NO):
            api(cfg, "PUT",
                f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages/{msg['id']}"
                f"/reactions/{urllib.request.quote(emoji)}/@me")
            time.sleep(0.3)
    return msg["id"]


def check_reaction(cfg, message_id, emoji):
    """Return True if the configured approver reacted with this emoji."""
    users = api(cfg, "GET",
                f"/channels/{cfg['DISCORD_CHANNEL_ID']}/messages/{message_id}"
                f"/reactions/{urllib.request.quote(emoji)}")
    if not users:
        return False
    return any(u.get("id") == cfg["DISCORD_APPROVER_ID"] for u in users)


def main():
    cfg = load_conf()
    proposals = read_jsonl(PROPOSALS)
    if not proposals:
        print("[INFO] no proposals")
        return

    posted = load_posted()
    by_id = {}
    for p in proposals:
        by_id.setdefault(p.get("proposal_id"), []).append(p)

    # 1. Resolve decisions on anything already posted.
    decided = 0
    for pid, mid in list(posted.items()):
        rows = by_id.get(pid) or []
        if not rows or all(r.get("status") != "pending" for r in rows):
            continue
        verdict = None
        if check_reaction(cfg, mid, OK):
            verdict = "approved"
        elif check_reaction(cfg, mid, NO):
            verdict = "denied"
        if not verdict:
            continue
        for r in rows:
            r["status"] = verdict
            r["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            r["decided_via"] = "discord"
        with open(APPROVALS, "a") as f:
            f.write(json.dumps({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "proposal_id": pid, "decision": verdict,
                "channel": "discord", "message_id": mid,
                "approver": cfg["DISCORD_APPROVER_ID"],
            }) + "\n")
        decided += 1
        print(f"[DECISION] {pid} -> {verdict}")

    # 2. Collapse the backlog so the channel shows current state.
    current, superseded = dedupe_pending(proposals)
    for p in superseded:
        p["status"] = "superseded"
    if superseded:
        print(f"[INFO] marked {len(superseded)} superseded")

    # 3. Post what is still pending and not yet in the channel.
    posted_now = 0
    quiet = _quiet_load()
    quieted = 0
    for p in sorted(current, key=lambda x: x.get("timestamp", "")):
        pid = p.get("proposal_id")
        if pid in posted or p.get("status") != "pending":
            continue
        _ok, _why, _commit = quiet_gate(quiet, p)
        if not _ok:
            # Suppressed, not dropped: it stays pending in proposals.jsonl and
            # is reported as a standing fault by the daily digest.
            print(f"  [quiet] {pid}: {_why}")
            quieted += 1
            continue
        if posted_now >= MAX_POST:
            break
        mid = post_proposal(cfg, p)
        if mid:
            _commit()  # record the send ONLY after Discord accepted it
            posted[pid] = mid
            posted_now += 1
            print(f"[POSTED] {pid}")
            time.sleep(0.5)

    for _k in reconcile_gate(quiet, proposals):
        print(f"[GATE-CLEARED] {_k}: condition resolved, flag cleared")

    write_jsonl(PROPOSALS, proposals)
    save_posted(posted)
    _quiet_save(quiet)

    remaining = sum(1 for p in proposals if p.get("status") == "pending"
                    and p.get("proposal_id") not in posted)
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] "
          f"decided={decided} posted={posted_now} awaiting_post={remaining}")


if __name__ == "__main__":
    main()
