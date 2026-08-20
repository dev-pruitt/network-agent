#!/usr/bin/env python3
"""Does the DoH check parse conntrack correctly, or did it cry wolf?

It flagged the robot vacuum as talking to Google DoH on its first run, and
three follow-up samples showed only ICMP pings to 8.8.8.8 - a benign
connectivity check. Before telling the operator a device on his network is
bypassing DNS, establish whether the parser can produce that claim from
innocent input.

A conntrack line carries TWO src/dst pairs: the original direction and the
reply, which is reversed. Taking the FIRST src and FIRST dst is right for the
original direction - but the fields sit on one line, so a naive regex over the
whole line can pair a source from one direction with a destination from the
other. That is the exact class of mistake this project keeps producing:
matching a pattern against a representation without checking what the
representation actually contains.
"""
import re

# Real shapes taken from /proc/net/nf_conntrack on this router.
SAMPLES = [
    # 1. Benign: LAN host to a normal web server. dport=443, dst NOT a resolver.
    ("benign https",
     "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.216 "
     "dst=3.147.137.189 sport=45012 dport=443 src=3.147.137.189 "
     "dst=10.2.0.2 sport=443 dport=45012 mark=49152 zone=0 use=2",
     False),

    # 2. Benign: ICMP ping to 8.8.8.8. No dport at all - must never match.
    ("icmp ping to 8.8.8.8",
     "ipv4     2 icmp     1 0 src=192.168.1.216 dst=8.8.8.8 type=8 code=0 "
     "id=31753 packets=1 bytes=48 src=8.8.8.8 dst=10.2.0.2 type=0 code=0 "
     "id=31753 mark=49152 zone=0 use=2",
     False),

    # 3. THE TRAP: a normal https connection whose REPLY comes from a resolver
    #    address. First dst is innocent; a sloppy regex could still pick 8.8.8.8.
    ("https whose reply mentions 8.8.8.8",
     "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.216 "
     "dst=142.250.72.14 sport=45012 dport=443 src=8.8.8.8 "
     "dst=10.2.0.2 sport=443 dport=45012 mark=49152 zone=0 use=2",
     False),

    # 4. Genuine DoH: original direction goes to a resolver on 443.
    ("real DoH to Cloudflare",
     "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.216 "
     "dst=1.1.1.1 sport=45013 dport=443 src=1.1.1.1 "
     "dst=10.2.0.2 sport=443 dport=45013 mark=49152 zone=0 use=2",
     True),
]

DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
           "149.112.112.112", "208.67.222.222", "208.67.220.220"}


def old_parse(line):
    """What the monitor does now: first src, first dst, anywhere on the line."""
    if "dport=443" not in line:
        return False
    s = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
    d = re.search(r"dst=(\d+\.\d+\.\d+\.\d+)", line)
    if not (s and d):
        return False
    return d.group(1) in DOH_IPS and s.group(1).startswith("192.168.")


def new_parse(line):
    """Require src, dst and dport=443 to belong to the SAME direction.

    Anchoring on the original-direction tuple as a unit means a reply address
    cannot be mistaken for a destination, and a protocol with no dport cannot
    match at all.
    """
    m = re.search(r"src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)\s+"
                  r"sport=\d+\s+dport=443\b", line)
    if not m:
        return False
    src, dst = m.group(1), m.group(2)
    return dst in DOH_IPS and src.startswith("192.168.")


print(f"{'case':38} {'expect':7} {'old':6} {'new':6}")
print("-" * 62)
old_wrong = new_wrong = 0
for name, line, expect in SAMPLES:
    o, n = old_parse(line), new_parse(line)
    if o != expect:
        old_wrong += 1
    if n != expect:
        new_wrong += 1
    flag_o = "  " if o == expect else "<-"
    flag_n = "  " if n == expect else "<-"
    print(f"{name:38} {str(expect):7} {str(o):4}{flag_o} {str(n):4}{flag_n}")

print()
print(f"  old parser wrong on {old_wrong}/{len(SAMPLES)}")
print(f"  new parser wrong on {new_wrong}/{len(SAMPLES)}")
