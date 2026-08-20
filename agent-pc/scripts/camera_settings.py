"""Operator-changeable camera settings, and applying them for real.

Only one setting so far: whether audio is recorded. It gets its own module
because changing it is not a flag flip - it rewrites the MediaMTX config and
restarts the container, and the result has to be verified rather than assumed.

WHAT "OFF" ACTUALLY MEANS
  The audio track stops being recorded. It is not muted in the player, and it
  is not hidden in the UI. Muting would leave the archive full of audio while
  looking like it had been turned off, which is worse than leaving it on -
  the operator would believe something about their recordings that is false.

  Footage recorded BEFORE the change keeps whatever it had. Turning audio off
  does not retroactively strip 30 days of archive, and saying otherwise would
  be a lie the UI has to tell honestly.
"""
import os
import subprocess
import sys

BASE = os.path.expanduser("~/network-agent-backup")
SETTINGS = os.path.join(BASE, "config", "camera-settings.conf")
SCRIPTS = os.path.join(BASE, "agent-pc", "scripts")

DEFAULTS = {"record_audio": "yes"}
TRUTHY = ("yes", "true", "1", "on")


def read():
    s = dict(DEFAULTS)
    if os.path.exists(SETTINGS):
        for line in open(SETTINGS):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                s[k.strip()] = v.strip()
    return s


def record_audio():
    return read().get("record_audio", "yes").lower() in TRUTHY


def write(key, value):
    s = read()
    s[key] = value
    os.makedirs(os.path.dirname(SETTINGS), exist_ok=True)
    fd = os.open(SETTINGS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# Camera settings, changed from the portal admin screen.\n")
        for k, v in sorted(s.items()):
            f.write(f"{k} = {v}\n")


def set_record_audio(on):
    """Persist, rebuild the MediaMTX config, restart, then VERIFY.

    Returns (ok, message). The verify step is the point: a restart that
    silently failed would leave the operator believing audio was off while
    the old container kept recording it.
    """
    write("record_audio", "yes" if on else "no")

    sys.path.insert(0, SCRIPTS)
    try:
        import importlib
        import setup_mediamtx
        importlib.reload(setup_mediamtx)
        ok, detail = setup_mediamtx.apply(with_audio=on)
    except Exception as e:
        return False, f"could not rebuild config: {type(e).__name__}: {e}"
    if not ok:
        return False, f"restart failed: {detail}"

    import time
    time.sleep(8)
    tracks, err = current_tracks()
    if err:
        # Could not look. Do not claim success, and do not claim failure.
        return True, (f"Setting saved and MediaMTX restarted, but the track "
                      f"list could not be read ({err}). Check the recorded "
                      f"stream before relying on this.")

    has_audio = any("audio" in t.lower() for t in tracks)
    if has_audio == on:
        return True, ("Audio is being recorded." if on else
                      "Audio recording is OFF. Existing footage keeps the "
                      "audio it was recorded with.")
    return False, (f"Setting saved but the stream still reports "
                   f"{'audio' if has_audio else 'no audio'} "
                   f"({', '.join(tracks) or 'no tracks'}). The camera may "
                   f"still be reconnecting - re-check in a minute.")


def current_tracks():
    """Tracks on the recorded path. Returns (tracks, error)."""
    try:
        import requests
        r = requests.get("http://127.0.0.1:9997/v3/paths/get/sd", timeout=6)
        if r.status_code != 200:
            return [], f"api returned {r.status_code}"
        return r.json().get("tracks", []) or [], None
    except Exception as e:
        return [], type(e).__name__
