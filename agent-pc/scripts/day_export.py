#!/usr/bin/env python3
"""Full-day export: stitch a whole LOCAL day of recording into one MP4.

ffmpeg concatenates the day's segment files (stream copy, no re-encode) inside
the mediamtx container, run detached so a portal restart cannot interrupt it.
A recording gap is simply absent -- concat stitches only footage that exists,
so a day with an outage still yields a valid file of everything captured.

RETENTION (2026-08-19, per agent)
  Every resident can trigger this now, not just admin - see camera_portal.py.
  A finished export is several GB, and nothing pruned _exports/ before, so
  opening this up to everyone with no cleanup would let disk usage grow
  without bound. The clock starts when the file finishes building, not when
  someone downloads it: RETENTION_SEC after the .mp4's own mtime (set the
  moment ffmpeg's last write to it lands - mv/rename preserve that, they do
  not reset it to "now"), sweep_expired() deletes it. Called at the top of
  every route here for the common case, AND from a dedicated cron script
  (export_retention.py) so a file still gets removed on schedule even if no
  one visits the page again after it finishes.

Routes: /export_day (start), /export_status (poll), /export_file (fetch).
Available to any logged-in user - the decorator is passed in by the caller.
"""
import os, re, subprocess, time
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, send_file
import requests

EXPORT_DIR = os.path.expanduser("~/camera-recordings/_exports")
os.makedirs(EXPORT_DIR, exist_ok=True)
CEXPORT = "/recordings/_exports"
CREC = "/recordings/sd"
_SEG = re.compile(r"^(\d{2})-(\d{2})-(\d{2})-\d+\.mp4$")

RETENTION_SEC = 30 * 60

# A build that dies (ffmpeg killed, container restarted mid-concat) leaves a
# multi-GB .part and its .txt concat list behind. The finished-file sweep
# never sees them, because it only scans .mp4 - so the very thing retention
# exists to prevent (unbounded disk growth) comes back through the failure
# path. Orphans are cleaned on a LONGER clock than finished files: a real
# build must never be deleted out from under a running ffmpeg, and a full day
# of 24/7 footage can legitimately take a while to stitch.
ORPHAN_SEC = 6 * 60 * 60

def _paths(day):
    return (os.path.join(EXPORT_DIR, day + ".mp4"),
            os.path.join(EXPORT_DIR, day + ".part"),
            os.path.join(EXPORT_DIR, day + ".txt"))

def _valid(day):
    try:
        datetime.strptime(day, "%Y-%m-%d"); return True
    except ValueError:
        return False

def segments_for_day(rec_dir, day):
    local0 = datetime.fromisoformat(day + "T00:00:00").astimezone()
    w0 = local0.timestamp(); w1 = (local0 + timedelta(days=1)).timestamp()
    uds = sorted({datetime.fromtimestamp(w0, timezone.utc).strftime("%Y-%m-%d"),
                  datetime.fromtimestamp(w1 - 1, timezone.utc).strftime("%Y-%m-%d")})
    out = []
    for ud in uds:
        d = os.path.join(rec_dir, ud)
        if not os.path.isdir(d):
            continue
        base = datetime.fromisoformat(ud + "T00:00:00+00:00").timestamp()
        for name in sorted(os.listdir(d)):
            m = _SEG.match(name)
            if not m:
                continue
            h, mi, sec = (int(x) for x in m.groups())
            st = base + h * 3600 + mi * 60 + sec
            if (st + 3600) > w0 and st < w1:
                out.append((st, CREC + "/" + ud + "/" + name))
    out.sort()
    return [p for _, p in out]

def available_days(mtx, rec):
    try:
        items = requests.get(mtx + "/list", params={"path": rec}, timeout=10).json()
    except Exception:
        return []
    days = set()
    for it in items:
        st = it.get("start")
        if not st:
            continue
        try:
            days.add(datetime.fromisoformat(st.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d"))
        except ValueError:
            pass
    return sorted(days, reverse=True)

def sweep_expired(now=None):
    """Delete any finished export whose .mp4 has been sitting >= RETENTION_SEC
    since it finished building. Returns the list of days removed.

    Reads mtime rather than tracking a separate "finished at" timestamp
    anywhere - one fewer piece of state that could drift from the file it is
    supposed to describe. Missing/already-gone files are not an error; two
    callers (a route and the cron sweep) can race here harmlessly, whoever's
    os.remove() loses just gets FileNotFoundError, which is not a failure.
    """
    now = now or time.time()
    removed = []
    if not os.path.isdir(EXPORT_DIR):
        return removed
    for name in os.listdir(EXPORT_DIR):
        if not name.endswith(".mp4"):
            continue
        day = name[:-4]
        if not _valid(day):
            continue
        done, part, lst = _paths(day)
        try:
            age = now - os.path.getmtime(done)
        except OSError:
            continue
        if age < RETENTION_SEC:
            continue
        for p in (done, lst):
            try:
                os.remove(p)
            except OSError:
                pass
        removed.append(day)
    removed.extend(sweep_orphans(now=now))
    return removed


def sweep_orphans(now=None):
    """Remove abandoned .part builds and their stranded .txt concat lists.

    A .part whose mtime has not advanced in ORPHAN_SEC is not being written
    to any more - ffmpeg appends continuously while stitching, so a live
    build always has a recent mtime. Checking mtime rather than "does a
    process exist" keeps this correct across a reboot, where the ffmpeg that
    owned the file is gone but the file remains.
    """
    now = now or time.time()
    removed = []
    if not os.path.isdir(EXPORT_DIR):
        return removed
    for name in os.listdir(EXPORT_DIR):
        if not (name.endswith(".part") or name.endswith(".txt")):
            continue
        day = name.rsplit(".", 1)[0]
        if not _valid(day):
            continue
        done, part, lst = _paths(day)
        path = part if name.endswith(".part") else lst
        # A .txt beside a live .part belongs to that build - judge it by the
        # .part, or a slow stitch would lose the concat list it is reading.
        ref = part if os.path.exists(part) else path
        try:
            age = now - os.path.getmtime(ref)
        except OSError:
            continue
        if age < ORPHAN_SEC or os.path.exists(done):
            if not os.path.exists(done):
                continue
        try:
            os.remove(path)
            removed.append(name + " (orphan)")
        except OSError:
            pass
    return removed


def retention_status(day):
    """(exists, seconds_remaining) for a finished export, or (False, 0)."""
    done, _, _ = _paths(day)
    try:
        age = time.time() - os.path.getmtime(done)
    except OSError:
        return False, 0
    return True, max(0, int(RETENTION_SEC - age))


def start_export(rec_dir, day):
    done, part, lst = _paths(day)
    if os.path.exists(done):
        return "done", os.path.getsize(done)
    if os.path.exists(part):
        return "running", os.path.getsize(part)
    segs = segments_for_day(rec_dir, day)
    if not segs:
        return "empty", 0
    with open(lst, "w") as fh:
        for sp in segs:
            fh.write("file '%s'\n" % sp)
    cpart = CEXPORT + "/" + day + ".part"; cdone = CEXPORT + "/" + day + ".mp4"
    clst = CEXPORT + "/" + day + ".txt"
    shell = ("ffmpeg -y -hide_banner -loglevel error -f concat -safe 0 -i '%s' "
             "-c copy -f mp4 '%s' && mv '%s' '%s' || rm -f '%s'" % (clst, cpart, cpart, cdone, cpart))
    subprocess.run(["docker", "exec", "-d", "mediamtx", "sh", "-c", shell], timeout=20, check=False)
    return "running", 0

_SECTION = """
<hr>
<div class=sub>Download a full day</div>
<div class=note>Stitches the whole day of recording into one MP4. It is 24/7
footage, so a day is several GB and takes a minute or two to build. You can
leave this page &mdash; it keeps going and the file waits here until ready. Any
recording gap that day is simply skipped. <b>Once it is ready you have 30
minutes to download it</b> before it is removed automatically - come back and
build it again if you miss the window.</div>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0">
  <select id=exday style="width:auto;flex:0 0 auto;padding:8px">__DAYOPTS__</select>
  <button class="btn sm" id=exbtn type=button>Prepare download</button>
</div>
<div id=exstatus class=note style="display:none"></div>
<script>
(function(){
  var btn=document.getElementById('exbtn'),sel=document.getElementById('exday'),
      st=document.getElementById('exstatus'),timer=null,ctimer=null;
  function mb(b){return b?(b/1048576).toFixed(0)+' MB':'0 MB';}
  function mmss(s){s=Math.max(0,s|0);return Math.floor(s/60)+':'+String(s%60).padStart(2,'0');}
  function show(t){st.style.display='block';st.innerHTML=t;}
  function startCountdown(day,secs){
    if(ctimer){clearInterval(ctimer);ctimer=null;}
    var remain=secs;
    function tick(){
      if(remain<=0){clearInterval(ctimer);ctimer=null;show('Expired. Build it again to download.');return;}
      show('Ready. <a href="/export_file?day='+day+'"><b>Download '+day+'</b></a> &mdash; available for '+mmss(remain)+' more.');
      remain--;
    }
    tick();ctimer=setInterval(tick,1000);
  }
  function poll(day){
    fetch('/export_status?day='+day).then(function(r){return r.json();}).then(function(d){
      if(d.status==='done'){if(timer){clearInterval(timer);timer=null;}btn.disabled=false;
        startCountdown(day,d.expires_in||0);}
      else if(d.status==='running'){show('Building '+day+' &hellip; '+mb(d.size)+' so far. You can leave; it keeps going.');}
      else{show('Not started for '+day+'.');}
    }).catch(function(){});
  }
  btn.onclick=function(){var day=sel.value;if(!day)return;btn.disabled=true;show('Starting &hellip;');
    if(ctimer){clearInterval(ctimer);ctimer=null;}
    var fd=new FormData();fd.append('day',day);
    fetch('/export_day',{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(d){
      if(d.error){show('Error: '+d.error);btn.disabled=false;return;}
      if(timer)clearInterval(timer);timer=setInterval(function(){poll(day);},3000);poll(day);
    }).catch(function(){show('Could not start.');btn.disabled=false;});};
  sel.onchange=function(){if(!timer)poll(sel.value);};
  if(sel.value)poll(sel.value);
})();
</script>
"""

def inject_settings(body, mtx, rec):
    opts = "".join('<option value="%s">%s</option>' % (d, d) for d in available_days(mtx, rec))
    if not opts:
        opts = '<option value="">(no recordings found)</option>'
    section = _SECTION.replace("__DAYOPTS__", opts)
    if "<div class=alt>" in body:
        return body.replace("<div class=alt>", section + "<div class=alt>", 1)
    return body + section

def register(app, login_required, rec_dir, mtx, rec):
    # Parameter kept named for the caller's readability at the call site;
    # camera_portal.py now passes login_required, not admin_required - see
    # the module docstring. Every route sweeps expired exports first, so the
    # 30-minute window is enforced on the request path too, not only by cron.
    @app.route("/export_day", methods=["POST"])
    @login_required
    def export_day():
        sweep_expired()
        day = request.form.get("day", "")
        if not _valid(day):
            return jsonify({"error": "bad day"}), 400
        try:
            status, size = start_export(rec_dir, day)
        except Exception as e:
            return jsonify({"error": "could not start: " + type(e).__name__}), 500
        if status == "empty":
            return jsonify({"error": "no footage for that day"}), 404
        return jsonify({"status": status, "size": size})

    @app.route("/export_status")
    @login_required
    def export_status():
        sweep_expired()
        day = request.args.get("day", "")
        if not _valid(day):
            return jsonify({"error": "bad day"}), 400
        done, part, _ = _paths(day)
        if os.path.exists(done):
            _, remaining = retention_status(day)
            return jsonify({"status": "done", "size": os.path.getsize(done),
                            "expires_in": remaining})
        if os.path.exists(part):
            return jsonify({"status": "running", "size": os.path.getsize(part)})
        return jsonify({"status": "none", "size": 0})

    @app.route("/export_file")
    @login_required
    def export_file():
        sweep_expired()
        day = request.args.get("day", "")
        if not _valid(day):
            return "bad day", 400
        done, _, _ = _paths(day)
        if not os.path.exists(done):
            return "not ready", 404
        return send_file(done, mimetype="video/mp4", as_attachment=True,
                         download_name="parking-lot-" + day + ".mp4")
