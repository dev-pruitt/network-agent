#!/usr/bin/env python3
"""Benchmark candidate Ollama models against REAL router telemetry.

Scores faithfulness, not vibes. The incumbent qwen2.5:1.5b was caught
inventing interfaces ('wg1', 'wgtunnel2') that do not exist on this router
and contradicting handshake numbers present in its own input. Those are the
exact failures this harness detects.
"""
import json, os, re, sys, time, urllib.request

OLLAMA = "http://localhost:11434/api/generate"
TELEM  = os.path.expanduser("~/network-agent/logs/router_telemetry.jsonl")

CANDIDATES = ["qwen2.5:1.5b", "gemma3:4b", "qwen2.5:3b", "llama3.2:3b"]

# Ground truth for this router. Anything outside REAL_IFACES is a fabrication.
REAL_IFACES  = {"wg2", "wgclient"}
GHOST_IFACES = ["wg1", "wg0", "wg3", "wgtunnel", "wgtunnel2", "wireguard0",
                "tun0", "eth0.1", "wgserver"]


def latest_telemetry():
    with open(TELEM) as f:
        lines = [l for l in f if l.strip()]
    return json.loads(lines[-1])


def build_prompt(t):
    return (
        "You are a network monitoring assistant. Analyze this router telemetry "
        "and write a SHORT status summary (max 120 words).\n\n"
        "RULES:\n"
        "- This router has EXACTLY TWO WireGuard interfaces: wg2 and wgclient.\n"
        "- Never mention any other interface name.\n"
        "- Do not invent numbers. Use only values present in the data.\n"
        "- State whether action is needed.\n\n"
        f"TELEMETRY:\n{json.dumps(t, indent=2)[:2500]}\n"
    )


def ask(model, prompt, timeout=600):
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 220},
        "keep_alive": 0,
    }).encode()
    req = urllib.request.Request(OLLAMA, data=body,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return data, time.time() - t0


def numeric_faithfulness(text, truth):
    """Flag numbers the model asserts that do not appear in the source data.

    The dominant failure of small models here is not inventing interface
    names, it is misreading cumulative byte counters as rates and
    averaging two different latencies into one. Interface-name checks
    miss all of that.
    """
    claimed = set()
    for m in re.finditer(r"(\d[\d,]*\.?\d*)\s*(ms|gb|mb|kb|days?|hours?|%)", text.lower()):
        val = m.group(1).replace(",", "")
        try:
            claimed.add((float(val), m.group(2).rstrip("s")))
        except ValueError:
            pass
    bad = []
    for val, unit in claimed:
        ok = False
        for t in truth:
            if t == 0:
                continue
            for scale in (1, 1e3, 1e6, 1e9, 1/1e3, 1/1e6, 1/1e9, 1/60, 1/3600, 1/86400):
                if abs(val - t * scale) <= max(0.05 * abs(t * scale), 0.6):
                    ok = True
                    break
            if ok:
                break
        if not ok:
            bad.append(f"{val}{unit}")
    return bad


def collect_truth(t):
    vals = []
    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, (int, float)):
            vals.append(float(o))
        elif isinstance(o, str):
            for m in re.finditer(r"-?\d+\.?\d*", o):
                try:
                    vals.append(float(m.group()))
                except ValueError:
                    pass
    walk(t)
    return vals


def score(text):
    low = text.lower()
    ghosts = sorted({g for g in GHOST_IFACES if re.search(rf"\b{re.escape(g)}\b", low)})
    mentions_real = sorted({i for i in REAL_IFACES if i in low})
    # crude repetition check: same 40-char chunk appearing 3+ times
    chunks = [text[i:i+40] for i in range(0, max(0, len(text) - 40), 40)]
    dupes = len(chunks) - len(set(chunks))
    return {
        "hallucinated_ifaces": ghosts,
        "real_ifaces_named": mentions_real,
        "duplicate_blocks": dupes,
        "words": len(text.split()),
    }


def main():
    t = latest_telemetry()
    prompt = build_prompt(t)
    print(f"Telemetry sample: {t.get('timestamp','?')}")
    print("=" * 72)

    truth = collect_truth(t)
    results = []
    for model in CANDIDATES:
        print(f"\n### {model}")
        try:
            data, wall = ask(model, prompt)
        except Exception as e:
            print(f"  SKIP ({e})")
            continue

        text = data.get("response", "").strip()
        ec   = data.get("eval_count", 0)
        ed   = data.get("eval_duration", 1) / 1e9
        ld   = data.get("load_duration", 0) / 1e9
        tps  = ec / ed if ed else 0
        s    = score(text)
        s["unsupported_numbers"] = numeric_faithfulness(text, truth)

        verdict = "PASS" if (not s["hallucinated_ifaces"]
                             and s["duplicate_blocks"] == 0
                             and len(s["unsupported_numbers"]) <= 1) else "FAIL"
        print(f"  wall {wall:6.1f}s | load {ld:5.1f}s | {tps:5.1f} tok/s | {ec} tok")
        print(f"  hallucinated: {s['hallucinated_ifaces'] or 'none'}")
        print(f"  named real:   {s['real_ifaces_named'] or 'NONE (bad)'}")
        print(f"  dupe blocks:  {s['duplicate_blocks']}")
        print(f"  unsupported#: {s['unsupported_numbers'] or 'none'}")
        print(f"  VERDICT: {verdict}")
        print("  --- output ---")
        for line in text.splitlines()[:14]:
            print(f"  | {line}")

        sys.stdout.flush()
        results.append({"model": model, "wall_s": round(wall, 1),
                        "load_s": round(ld, 1), "tok_per_s": round(tps, 1),
                        "verdict": verdict, **s})

    print("\n" + "=" * 72)
    print(f"{'MODEL':<18} {'TOK/S':>7} {'WALL':>7} {'IFACE':>6} {'BADNUM':>7}  VERDICT")
    for r in results:
        print(f"{r['model']:<18} {r['tok_per_s']:>7.1f} {r['wall_s']:>6.1f}s "
              f"{len(r['hallucinated_ifaces']):>6} {len(r['unsupported_numbers']):>7}  {r['verdict']}")

    out = os.path.expanduser("~/network-agent/logs/model_bench.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved -> {out}")


if __name__ == "__main__":
    main()
