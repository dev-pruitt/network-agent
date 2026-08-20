#!/usr/bin/env python3
"""detect_scan.py -- confirm noisy motion clusters as real car/person events.

REWRITE (2026-08-20, per agent)
  The previous design gated on activity_scan's whole-frame motion-percent
  score: only look at a video slice when enough of the FRAME changed, and
  even then only classify one or two single frames from it. Measured against
  known ground truth (dense per-second YOLO over a 10-minute window with
  visible people) that design caught about 5% of actual person-time. A
  walking person at typical distance on this camera does not move enough
  PIXELS to separate from ambient noise (shadows, trees, headlights) on any
  whole-frame threshold - tiled (per-region) motion was tested too and only
  reached ~80% recall at a false-positive rate too high to be worth it
  (measured, not assumed - see the audit this replaces).

  So this no longer gates on motion at all. It samples every SAMPLE_STEP
  seconds through the whole segment, runs the zone-aware detector on each
  sample, and tracks detections across samples by bounding-box overlap so
  each physical object becomes its own event - a person and a car present
  at the same time no longer merge into one blob, and a car sitting in the
  lot for an hour doesn't get treated as new every sample it's re-detected.

WHY 'bus' GETS FOLDED INTO 'car'
  The model reads certain parked cars as "bus" at this camera's angle and
  lighting, consistently, at confidence up to 0.75 - verified against real
  footage (2026-08-20): two DIFFERENT stationary cars, over 2+ minutes of
  continuous frames each, never once read as their correct class. A bus is
  not a plausible object in this lot. Rather than surface a wrong noun,
  fold it into car before anything else (tracking, static-suppression) sees
  it - REMAP happens first so a flickering bus/car/truck read on one
  physical object doesn't fracture into multiple tracks.

WHY STATIC SUPPRESSION IS BOX-POSITION, NOT LABEL
  A parked car's label can flicker between car/truck/bus across samples
  (see above). Judging "is this the same object I saw last time" by label
  match would treat that flicker as several different objects, and none of
  them would individually hit the presence threshold to be recognized as
  parked. Matching is IoU on the box only; the reported label for an event
  is decided once, from whichever class was seen most across its samples.

WHAT THIS DOES NOT CHANGE
  detect.py, the zone config, and detect_zoned() are untouched - zone
  filtering (person-only + lower confidence in the trash-can/gate nook,
  everything else at the site-wide bar) still runs on every sample exactly
  as before. The output schema (day.det.json: segments -> events with
  s/e/l/c/all, s and e measured in seconds from the START OF THE SEGMENT
  FILE) is unchanged, so camera_portal.py's /api/activity needs no changes.
  activity_scan.py is still what discovers which segments exist and are
  closed (finished, safe to read) - this reads its motion index purely for
  that segment list, not for the per-second scores, which this no longer
  uses for anything.
"""
import argparse, json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect as D
import numpy as np
from PIL import Image

REC_DIR = os.path.expanduser("~/camera-recordings/sd")
ACT_DIR = os.path.expanduser("~/network-agent/logs/activity")
CONTAINER = "mediamtx"; CONTAINER_REC = "/recordings/sd"
DEC_W, DEC_H = 640, 360
PRIORITY = ["person", "car", "truck", "bus", "motorcycle", "bicycle"]

# Seconds between samples. Measured cost (2026-08-20, real hardware, i3-6100
# 4 cores, load already ~2.0 from recording+scanning): a real, full ~1hr
# closed segment took 114s wall (0.158s/sample, 720 samples) at this step.
# At ~26 segments/day that's ~50 CPU-minutes/day total, and since cron only
# ever processes the ONE segment that just closed each run, a single run
# costs under 2 minutes inside a 10-minute cron window - comfortable
# headroom on this box. Not pushed lower than 5s; this was not tested finer.
SAMPLE_STEP = 5

# Same physical object across two samples/frames.
BOX_IOU_SAME = 0.55
# Present in at least this fraction of a segment's samples => parked car /
# furniture, not an event. Evaluated per segment (per hour), so a car that
# arrives partway through one hour still generates its arrival as a real
# event, and is only suppressed as static in the FULL hours it then sits.
STATIC_FRAC = 0.80
# A track can go unmatched for up to this long (occlusion, a brief miss, or
# just a low-confidence sample the model dropped) and still be considered
# the same object rather than closed out. Raised from an initial 20s after
# real-footage testing (2026-08-20) showed a single standing/slow-moving
# person recurring every 30-90s for a 9-minute stretch was being sliced
# into a dozen 1-sample events at 20s - occlusion/recall gaps at 5s sampling
# run longer than that in practice.
TRACK_GAP = 45

# Matching a detection to an existing track. Tested at a looser, dilated
# version of this first (padding boxes out ~60% before comparing) to
# tolerate movement between 5s samples - real footage showed that was TOO
# loose: it started bridging genuinely different objects (a passing car
# absorbed into a person's track) any time their paths happened to cross
# the same general area, which is worse than the fragmentation it was
# meant to fix. Same-object consecutive sightings of this camera's real
# people/cars measured 0.6-0.9 IoU even un-dilated (see 2026-08-20 test
# notes) - the fragmentation problem was TRACK_GAP being too short, not
# this. Left close to BOX_IOU_SAME on purpose.
TRACK_IOU_MIN = 0.35
# A single-sample track only becomes an event on its own if confident enough
# that it is unlikely to be a one-frame model hallucination on a static
# scene; otherwise it needs a second corroborating sample. This is a light
# guard, not a recall-limiting gate - it does not require CONSECUTIVE
# samples (TRACK_GAP already allows gaps), just two hits anywhere in the
# track's life.
SOLO_SAMPLE_MIN_CONF = 0.45

REMAP = {"bus": "car"}  # see module docstring


# ---------------------------------------------------------------------------
# Detection zones (added 2026-08-19, unchanged by this rewrite).
#
# The trash-can/gate nook (top-right of frame) also has a sightline through
# the gate to the public road. A car detected there is road traffic, not lot
# activity, and should never have made a "recorded action". A person there
# IS the thing this zone exists to catch -- and may be partially hidden by
# the can, so it gets its own (lower) confidence bar instead of the
# site-wide one. One zone covers both asks: only "person" survives inside
# it, everything else is dropped regardless of confidence.
#
# Fails OPEN: if the config is missing or unreadable, detect_zoned() falls
# straight through to plain D.detect() -- a broken zone file must not start
# silently hiding people, the way a broken alert gate must not lose alerts.
# ---------------------------------------------------------------------------
ZONES_FILE = os.path.expanduser("~/network-agent/config/detection_zones.json")
_ZONES = None


def _zones():
    global _ZONES
    if _ZONES is None:
        try:
            with open(ZONES_FILE) as f:
                _ZONES = json.load(f).get("zones", [])
        except (OSError, ValueError):
            _ZONES = []
    return _ZONES


def _in_ellipse(cx_pct, cy_pct, zone):
    dx = (cx_pct - zone["center_x_pct"]) / zone["radius_x_pct"]
    dy = (cy_pct - zone["center_y_pct"]) / zone["radius_y_pct"]
    return (dx * dx + dy * dy) <= 1.0


def _zone_for_box(box, W, H, zones):
    """Zone containing the box's CENTER, or None. Center rather than any
    overlap -- a car whose edge clips the oval boundary should not get the
    zone's rules just because a corner of its bounding box crossed the line."""
    x1, y1, x2, y2 = box
    cx_pct = (x1 + x2) / 2.0 / W * 100.0
    cy_pct = (y1 + y2) / 2.0 / H * 100.0
    for z in zones:
        if z.get("shape") == "ellipse" and _in_ellipse(cx_pct, cy_pct, z):
            return z
    return None


def detect_zoned(im):
    """D.detect() plus zone rules, plus the bus->car remap (see docstring).

    One inference pass at the LOWEST confidence any zone needs, then filtered
    back up per-detection: inside a zone, only its allowed_classes count, at
    the zone's own confidence bar; outside every zone, standard site-wide
    behavior (all classes, D.CONF).
    """
    zones = _zones()
    needed = [D.CONF] + [
        z["rule"]["min_conf_person"] for z in zones
        if "min_conf_person" in z.get("rule", {})
    ]
    raw = D.detect(im, min_conf=min(needed)) if zones else D.detect(im)
    for d in raw:
        d["label"] = REMAP.get(d["label"], d["label"])
    if not zones:
        return raw
    W, H = im.size
    kept = []
    for d in raw:
        z = _zone_for_box(d["box"], W, H, zones)
        if z is None:
            if d["conf"] >= D.CONF:
                kept.append(d)
            continue
        rule = z.get("rule", {})
        allowed = rule.get("allowed_classes")
        if allowed is not None and d["label"] not in allowed:
            continue
        min_c = rule.get("min_conf_person", D.CONF) if d["label"] == "person" else D.CONF
        if d["conf"] >= min_c:
            kept.append(d)
    return kept


# ---------------------------------------------------------------------------
# Sampling: one streaming ffmpeg call per segment (NOT one process per
# frame - that was measured too expensive at this sample density) extracting
# a frame every SAMPLE_STEP seconds, run through detect_zoned().
# ---------------------------------------------------------------------------
def sample_segment(day, name, step=SAMPLE_STEP):
    """Yield (t, detections) for t = 0, step, 2*step, ... across the WHOLE
    segment file. t is seconds-from-start-of-this-segment-file, matching the
    s/e units the rest of this file and camera_portal.py already use."""
    path = f"{CONTAINER_REC}/{day}/{name}"
    cmd = ["docker", "exec", CONTAINER, "ffmpeg", "-hide_banner", "-loglevel", "error",
           "-i", path, "-vf", f"fps=1/{step},scale={DEC_W}:{DEC_H}",
           "-pix_fmt", "rgb24", "-f", "rawvideo", "-"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    fsz = DEC_W * DEC_H * 3
    out = []
    i = 0
    try:
        while True:
            buf = p.stdout.read(fsz)
            if not buf or len(buf) < fsz:
                break
            im = Image.fromarray(np.frombuffer(buf, np.uint8).reshape(DEC_H, DEC_W, 3))
            out.append((i * step, detect_zoned(im)))
            i += 1
    finally:
        p.stdout.close()
        p.wait(timeout=30)
    return out


def _iou(a, b):
    ix1, iy1 = max(a[0], b[0]), max(a[1], b[1])
    ix2, iy2 = min(a[2], b[2]), min(a[3], b[3])
    iw, ih = max(0, ix2 - ix1), max(0, iy2 - iy1)
    inter = iw * ih
    ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / ua if ua > 0 else 0.0


def mark_static(samples):
    """Objects present (by box position, not label - see docstring) in at
    least STATIC_FRAC of this segment's samples. Returns representative
    boxes to suppress; greedy first-seen representative per cluster is
    sufficient here since parked objects do not drift."""
    n = len(samples)
    if n == 0:
        return []
    static, claimed_id = [], set()
    all_dets = [(t, i, d) for t, dets in samples for i, d in enumerate(dets)]
    for t, i, d in all_dets:
        key = (t, i)
        if key in claimed_id:
            continue
        if any(_iou(d["box"], s["box"]) > BOX_IOU_SAME for s in static):
            continue
        hits = 0
        for t2, dets2 in samples:
            if any(_iou(d["box"], x["box"]) > BOX_IOU_SAME for x in dets2):
                hits += 1
        if hits >= n * STATIC_FRAC:
            static.append(d)
    return static


def build_events(samples, static):
    """Track detections across samples by box overlap; each track becomes
    one event. Label for the event is the PRIORITY-highest class actually
    seen on that track (a person briefly misread as something else on one
    sample should not make the whole track disappear as that something)."""
    def is_static(d):
        return any(_iou(d["box"], s["box"]) > BOX_IOU_SAME for s in static)

    active, finished = [], []
    for t, dets in samples:
        live = [d for d in dets if not is_static(d)]
        for d in live:
            best, best_iou = None, 0.0
            for tr in active:
                v = _iou(d["box"], tr["box"])
                if v > best_iou:
                    best, best_iou = tr, v
            if best is not None and best_iou > TRACK_IOU_MIN:
                best["box"] = d["box"]
                best["last_t"] = t
                best["samples"].append((t, d["label"], d["conf"]))
            else:
                active.append({"box": d["box"], "first_t": t, "last_t": t,
                               "samples": [(t, d["label"], d["conf"])]})
        still = []
        for tr in active:
            (finished if t - tr["last_t"] > TRACK_GAP else still).append(tr)
        active = still
    finished.extend(active)

    events = []
    for tr in finished:
        s = tr["samples"]
        if len(s) < 2 and max(c for _, _, c in s) < SOLO_SAMPLE_MIN_CONF:
            continue
        from collections import Counter
        labels_seen = Counter(lab for _, lab, _ in s)
        lab = next((L for L in PRIORITY if L in labels_seen), s[0][1])
        events.append({
            "s": tr["first_t"], "e": tr["last_t"], "l": lab,
            "c": round(max(c for _, _, c in s), 2),
            "all": sorted(labels_seen) if len(labels_seen) > 1 else None,
        })
    return sorted(events, key=lambda e: e["s"])


def scan_segment(day, name):
    samples = sample_segment(day, name)
    static = mark_static(samples)
    events = build_events(samples, static)
    return events, len(samples), len(static)


def load(day, suffix):
    f = os.path.join(ACT_DIR, f"{day}{suffix}")
    if os.path.exists(f):
        try: return json.load(open(f))
        except ValueError: pass
    return None


def save_det(day, data):
    f = os.path.join(ACT_DIR, f"{day}.det.json"); tmp = f + ".tmp"
    json.dump(data, open(tmp, "w"), separators=(",", ":")); os.replace(tmp, f)


def scan_day(day, force=False, verbose=True):
    # activity_scan's motion index is used ONLY to learn which segments
    # exist and are closed (finished, safe to read) - see module docstring.
    # Its per-second scores are not read; nothing here gates on motion.
    motion = load(day, ".json")
    if not motion:
        if verbose: print(f"  {day}: no motion index yet")
        return 0
    det = load(day, ".det.json") or {"day": day, "segments": {}}
    done = 0
    for name, seg in sorted(motion.get("segments", {}).items()):
        if not force and name in det["segments"]: continue
        t0 = time.time()
        events, nsamp, nstatic = scan_segment(day, name)
        det["segments"][name] = {"start": seg.get("start", 0), "events": events}
        save_det(day, det); done += 1
        if verbose:
            print(f"  {day}/{name}: {nsamp} samples, {nstatic} static -> "
                  f"{len(events)} events ({time.time()-t0:.0f}s)")
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--day"); ap.add_argument("--backfill", action="store_true")
    ap.add_argument("--force", action="store_true"); ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    if a.day: days = [a.day]
    elif a.backfill: days = sorted(d for d in os.listdir(REC_DIR) if os.path.isdir(os.path.join(REC_DIR, d)))
    else: days = sorted(d for d in os.listdir(REC_DIR) if os.path.isdir(os.path.join(REC_DIR, d)))[-1:]
    total = 0
    for d in days:
        if not a.quiet: print(f"[{time.strftime('%H:%M:%S')}] {d}")
        total += scan_day(d, force=a.force, verbose=not a.quiet)
    print(f"detect-scanned {total} segment(s)")

if __name__ == "__main__": main()
