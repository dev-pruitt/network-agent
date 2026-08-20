#!/usr/bin/env python3
"""Find out what each camera channel actually sends.

Codec decides the whole design. H.264 goes straight to a browser untouched -
cheap, and the stream stays pristine. H.265 does not play in most browsers,
so it would need transcoding on every view. This box has QuickSync so that is
survivable, but it is a real cost and worth knowing before building on it.

Resolution per channel is asked, not assumed. The app lists 360/720/1080 but
says nothing about which is ch1.

Credentials are read from config, used in the RTSP Authorization header, and
never printed. The URL is redacted in every output path.
"""
import base64
import hashlib
import os
import re
import socket
import sys

CONF = os.path.expanduser("~/network-agent-backup/config/camera.conf")
CHANNELS = ["ch1", "ch2", "ch3"]
TIMEOUT = 6


def load():
    if not os.path.exists(CONF):
        sys.exit(f"FATAL: {CONF} missing")
    c = {}
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            c[k.strip()] = v.strip()
    for k in ("rtsp_user", "rtsp_pass", "rtsp_host"):
        if k not in c:
            sys.exit(f"FATAL: {k} missing from {CONF}")
    return c


def rtsp(host, port, path, user, pw):
    """DESCRIBE with digest or basic auth. Returns SDP text or an error string."""
    url = f"rtsp://{host}:{port}/{path}"

    def send(extra_hdr=""):
        s = socket.create_connection((host, port), TIMEOUT)
        s.settimeout(TIMEOUT)
        req = (f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n"
               f"Accept: application/sdp\r\n{extra_hdr}\r\n")
        s.sendall(req.encode())
        buf = b""
        try:
            while len(buf) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf and b"m=video" in buf:
                    break
        except socket.timeout:
            pass
        s.close()
        return buf.decode(errors="replace")

    first = send()
    if " 200 " in first.split("\r\n")[0]:
        return first

    m = re.search(r'WWW-Authenticate:\s*(\w+)\s+(.*)', first, re.I)
    if not m:
        return first.split("\r\n")[0] or "no response"
    scheme, params = m.group(1).lower(), m.group(2)

    if scheme == "basic":
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        return send(f"Authorization: Basic {tok}\r\n")

    realm = re.search(r'realm="([^"]*)"', params)
    nonce = re.search(r'nonce="([^"]*)"', params)
    if not (realm and nonce):
        return "digest challenge missing realm/nonce"
    realm, nonce = realm.group(1), nonce.group(1)
    h = lambda x: hashlib.md5(x.encode()).hexdigest()
    resp = h(f"{h(f'{user}:{realm}:{pw}')}:{nonce}:{h(f'DESCRIBE:{url}')}")
    hdr = (f'Authorization: Digest username="{user}", realm="{realm}", '
           f'nonce="{nonce}", uri="{url}", response="{resp}"\r\n')
    return send(hdr)


def summarise(sdp):
    """Pull codec, resolution and any advertised bitrate out of the SDP."""
    status = sdp.split("\r\n")[0] if sdp else "no data"
    if " 200 " not in status:
        return {"status": status}

    out = {"status": "OK"}
    rtpmap = re.findall(r'a=rtpmap:\d+\s+([A-Za-z0-9\-]+)', sdp)
    if rtpmap:
        out["codecs"] = ", ".join(sorted(set(rtpmap)))

    fr = re.search(r'a=framerate:([\d.]+)', sdp) or re.search(r'a=x-framerate:\s*(\d+)', sdp)
    if fr:
        out["fps"] = fr.group(1)

    dim = re.search(r'a=x-dimensions:\s*(\d+)\s*,\s*(\d+)', sdp)
    if dim:
        out["resolution"] = f"{dim.group(1)}x{dim.group(2)}"

    b = re.search(r'b=AS:(\d+)', sdp)
    if b:
        out["bitrate_kbps"] = b.group(1)

    # sprop-parameter-sets carries SPS for H.264; its presence confirms H.264
    if "sprop-parameter-sets" in sdp:
        out.setdefault("codecs", "H264")
    return out


def main():
    c = load()
    host, _, port = c["rtsp_host"].partition(":")
    port = int(port or 554)
    print(f"=== camera {host}:{port} ===")
    print("  (credentials read from config, never printed)")
    print()

    for ch in CHANNELS:
        sdp = rtsp(host, port, ch, c["rtsp_user"], c["rtsp_pass"])
        info = summarise(sdp)
        if info.get("status") != "OK":
            print(f"  {ch}: {info['status']}")
            continue
        bits = [f"{k}={v}" for k, v in info.items() if k != "status"]
        print(f"  {ch}: OK   " + "  ".join(bits) if bits else f"  {ch}: OK")

    print()
    print("Browser note: H264 streams direct with no transcode. H265 does not")
    print("play in most browsers and would need one on every view.")


if __name__ == "__main__":
    main()
