#!/usr/bin/env python3
"""Re-measure the unloaded baseline latency from the legitimate generator host.

The Week 2 baseline was taken from the researcher's workstation and therefore
includes domestic broadband latency. Every latency comparison in the
dissertation is relative to this figure, so it has to be measured from the
same vantage point the experiment uses: gen-legit, against configuration C1,
with no attack traffic and no protection layer.

Deliberately not one of the 60 scheduled runs. This is a reference
measurement, recorded separately, so it cannot be mistaken for a result.

    ./.venv/bin/python scripts/baseline_ec2.py
"""
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import config  # noqa: E402

N = 300
RATE = 1.0
WARMUP = 15

MEASURE = r'''
import json, time, urllib.request
BASE = "{base}"
samples, statuses = [], {{}}
def get():
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(BASE + "/api/items", timeout=20) as r:
            r.read()
            return r.status, (time.perf_counter() - t0) * 1000
    except Exception as e:
        return type(e).__name__, (time.perf_counter() - t0) * 1000

# Warm-up, discarded: first requests carry Lambda cold start and TLS setup.
for _ in range({warmup}):
    get(); time.sleep(1.0)

interval = 1.0 / {rate}
nxt = time.perf_counter()
for _ in range({n}):
    nxt += interval
    s, ms = get()
    statuses[str(s)] = statuses.get(str(s), 0) + 1
    if s == 200:
        samples.append(ms)
    d = nxt - time.perf_counter()
    if d > 0:
        time.sleep(d)

samples.sort()
def pct(p):
    return round(samples[min(len(samples)-1, int(len(samples)*p/100))], 2)
print(json.dumps({{
    "n": len(samples), "statuses": statuses,
    "min_ms": round(samples[0], 2), "p50_ms": pct(50), "p95_ms": pct(95),
    "p99_ms": pct(99), "max_ms": round(samples[-1], 2),
    "mean_ms": round(sum(samples)/len(samples), 2),
}}))
'''


def tf(layer, key):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def main():
    cfg = json.loads((REPO / "data" / "processed" / "active-config.json").read_text())
    if cfg["configuration"] != "C1":
        sys.exit(f"Active configuration is {cfg['configuration']}. "
                 "The baseline must be measured against C1 (no protection). "
                 "Run: switch/apply_config.py C1")

    host = tf("40-harness", "legit_instance_id")
    ip = tf("40-harness", "legit_public_ip")
    base = cfg["endpoint"]

    print(f"host     : gen-legit {host} ({ip})")
    print(f"endpoint : {base}")
    print(f"sampling : {N} requests at {RATE}/s, {WARMUP} discarded\n")

    script = MEASURE.format(base=base, n=N, rate=RATE, warmup=WARMUP)
    b64 = base64.b64encode(script.encode()).decode()

    ssm = config.session().client("ssm", region_name=config.AWS_REGION)
    cid = ssm.send_command(
        InstanceIds=[host], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [f"echo {b64} | base64 -d > /tmp/bl.py",
                                 "python3.12 /tmp/bl.py"],
                    "executionTimeout": ["1800"]})["Command"]["CommandId"]

    print("measuring...")
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            r = ssm.get_command_invocation(CommandId=cid, InstanceId=host)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(3)
            continue
        if r["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
        time.sleep(10)
    else:
        sys.exit("measurement did not finish in time")

    if r["Status"] != "Success":
        sys.exit(f"measurement failed: {r['StandardErrorContent'][:400]}")

    stats = json.loads(r["StandardOutputContent"].strip().splitlines()[-1])

    print(f"\n  {'statistic':<12}{'ms'}")
    print("  " + "-" * 26)
    for k in ("min_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms"):
        mark = "   <- baseline" if k == "p95_ms" else ""
        print(f"  {k:<12}{stats[k]:>8}{mark}")
    print(f"\n  statuses: {stats['statuses']}")

    out = REPO / "data" / "processed" / "baseline-ec2.json"
    payload = {
        "measured_from": "gen-legit",
        "instance_id": host, "source_ip": ip,
        "configuration": "C1", "endpoint": base,
        "measured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_requests": N, "rate_req_s": RATE, "warmup_discarded": WARMUP,
        "latency": stats,
        "note": ("Reference measurement, not one of the 60 scheduled runs. "
                 "Supersedes the Week 2 workstation baseline, which included "
                 "domestic broadband latency and is not comparable."),
    }
    out.write_text(json.dumps(payload, indent=2))
    print(f"\n  written to {out.relative_to(REPO)}")

    old = REPO / "data" / "processed" / "baseline-c1.json"
    if old.exists():
        w2 = json.loads(old.read_text())["baseline_latency"]
        print(f"\n  Week 2 workstation p95 was {w2['p95_ms']} ms; this is "
              f"{stats['p95_ms']} ms.")
        print("  The difference is vantage point, not a change in the service.")


if __name__ == "__main__":
    main()
