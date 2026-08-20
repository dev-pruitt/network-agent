#!/usr/bin/env python3
"""
activity_scan.py -- build an activity index for the parking-lot recordings.

WHAT IT DOES
  Reads each finished 1-hour recording segment with ffmpeg (inside the
  mediamtx container, which already carries the binary), samples one frame a
  second at 320px wide, and records how much of the frame changed since the
  previous sample. Writes one JSON file per day.

  Recording itself is never touched. This only reads files that MediaMTX has
  already closed, so a scanner crash or a CPU spike cannot cost footage.

WHY IT STORES SCORES, NOT EVENTS
  The obvious design is to pick a threshold, emit "motion from 18:42 to
  18:44", and store that. It is also the design that has to re-read 36GB
  every time the threshold turns out to be wrong - and on an outdoor lot it
  WILL be wrong at first, because headlights, rain, moving shadows and the
  camera's own IR cut filter all move pixels.

  So the expensive pass stores the raw per-second score and nothing else.
  Thresholds are applied when the timeline is drawn, which makes retuning
  free and reversible. Scan once, tune forever.

  Measured on this hardware: ~10s of CPU per 5 minutes of video, so roughly
  2 minutes per 1-hour segment, ~50 minutes for the 4-day backlog across 4
  cores.

SCALE NOTE
  ffmpeg's scdet reports a PERCENTAGE of the frame changed, 0-100 - not the
  0-1 scale used by the older select=gt(scene,N) filter. An empty parking lot
  measured p50 0.06 and max 0.64 over five minutes. Anything sharing that
  range is a still scene. Do not port a 0-1 threshold across without
  rescaling; that mistake reads as "no activity ever".

Usage:
  activity_scan.py --backfill          scan every unscanned segment
  activity_scan.py --day 2026-08-11    one day
  activity_scan.py                     scan only segments newer than the index
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

REC_DIR = os.path.expanduser("~/camera-recordings/sd")
OUT_DIR = os.path.expanduser("~/network-agent/logs/activity")
CONTAINER = "mediamtx"
CONTAINER_REC = "/recordings/sd"
FPS = 1                       # one sample a second
WIDTH = 320                   # downscale before differencing - the lot does
                              # not need 720p to answer "did anything move"

SCORE_RE = re.compile(r"lavfi\.scd\.score=([0-9.]+)")
SEG_RE = re.compile(r"^(\d{2})-(\d{2})-(\d{2})-\d+\.mp4$")


def seg_start_seconds(name):
    """Second-of-day the segment begins, from its filename."""
    m = SEG_RE.match(name)
    if not m:
        return None
    h, mi, s = (int(x) for x in m.groups())
    return h * 3600 + mi * 60 + s


def scan_segment(day, name, timeout=900):
    """Return a list of per-second change scores, or None if it could not run."""
    path = f"{CONTAINER_REC}/{day}/{name}"
    vf = (f"fps={FPS},scale={WIDTH}:-2,scdet=s=0:t=0,"
          f"metadata=print:key=lavfi.scd.score:file=-")
    cmd = ["docker", "exec", CONTAINER, "ffmpeg", "-hide_banner",
           "-loglevel", "error", "-i", path, "-vf", vf, "-an", "-f", "null", "-"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        print("docker not found", file=sys.stderr)
        return None
    # scdet writes to stdout via file=-; ffmpeg's own noise goes to stderr.
    blob = (p.stdout or "") + (p.stderr or "")
    return [round(float(x), 2) for x in SCORE_RE.findall(blob)]


def load_day(day):
    f = os.path.join(OUT_DIR, f"{day}.json")
    if os.path.exists(f):
        try:
            with open(f) as fh:
                return json.load(fh)
        except ValueError:
            pass
    return {"day": day, "fps": FPS, "scale": "percent_0_100", "segments": {}}


def save_day(day, data):
    os.makedirs(OUT_DIR, exist_ok=True)
    f = os.path.join(OUT_DIR, f"{day}.json")
    tmp = f + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, separators=(",", ":"))
    os.replace(tmp, f)          # atomic: a reader never sees a half file


def segment_is_closed(full_path):
    """MediaMTX writes the current hour live. Judging a file that is still
    growing produces an index that silently stops short, so only scan a
    segment whose size has stopped changing."""
    try:
        a = os.path.getsize(full_path)
        time.sleep(1.5)
        return a == os.path.getsize(full_path)
    except OSError:
        return False


def scan_day(day, force=False, verbose=True):
    src = os.path.join(REC_DIR, day)
    if not os.path.isdir(src):
        print(f"no such day: {day}")
        return 0
    data = load_day(day)
    done = 0
    for name in sorted(os.listdir(src)):
        if not name.endswith(".mp4"):
            continue
        if not force and name in data["segments"]:
            continue
        full = os.path.join(src, name)
        if not segment_is_closed(full):
            if verbose:
                print(f"  {day}/{name}  still being written - skipped")
            continue
        start = seg_start_seconds(name)
        if start is None:
            continue
        t0 = time.time()
        scores = scan_segment(day, name)
        if scores is None:
            if verbose:
                print(f"  {day}/{name}  FAILED to scan")
            continue
        data["segments"][name] = {"start": start, "scores": scores}
        save_day(day, data)      # save per segment, so a kill loses one file
        done += 1
        if verbose:
            peak = max(scores) if scores else 0
            print(f"  {day}/{name}  {len(scores)} samples  peak {peak:.2f}  "
                  f"({time.time()-t0:.0f}s)")
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--day")
    ap.add_argument("--backfill", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    days = []
    if a.day:
        days = [a.day]
    elif a.backfill:
        days = sorted(d for d in os.listdir(REC_DIR)
                      if os.path.isdir(os.path.join(REC_DIR, d)))
    else:
        days = sorted(d for d in os.listdir(REC_DIR)
                      if os.path.isdir(os.path.join(REC_DIR, d)))[-1:]

    total = 0
    for d in days:
        if not a.quiet:
            print(f"[{datetime.now():%H:%M:%S}] {d}")
        total += scan_day(d, force=a.force, verbose=not a.quiet)
    print(f"scanned {total} segment(s)")


if __name__ == "__main__":
    main()
