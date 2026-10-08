#!/usr/bin/env python3
"""Tasks T016 and T017 - verify the target service and record the baseline.

Three things:
  1. Functional check: the endpoint answers, and every scenario S4 URI-path
     payload actually reaches the Lambda rather than being rejected by API
     Gateway. If a path 404s here, that payload can never be evaluated by the
     WAF in Week 3 and the S4 result for it would be a silent false negative.
  2. Unloaded baseline latency, paced well below any throttle.
  3. The API Gateway throttle limits actually in force (a confound present in
     every configuration, including C1).

    ./.venv/bin/python scripts/smoke_test.py --n 200
"""
import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import boto3
import httpx

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import config

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed"

# One representative payload per scenario S4 class that travels in the URI
# path or headers. Query-argument classes are exercised in Week 3 against the
# WAF; here we only prove the request reaches the origin.
PATH_PROBES = [
    ("plain", "/", None),
    ("plain-sub", "/api/items", None),
    ("lfi-path", "/api/../../etc/passwd", None),
    ("ssrf-path", "/latest/meta-data/", None),
    ("long-path", "/api/" + "a" * 200, None),
    ("bad-ua", "/api/items", {"User-Agent": "nmap"}),
    ("no-ua", "/api/items", {"User-Agent": None}),
]


def tf_output(key):
    import subprocess
    r = subprocess.run(
        ["terraform", f"-chdir={REPO}/infra/00-core", "output", "-raw", key],
        capture_output=True, text=True, check=True)
    return r.stdout.strip()


async def probe_all(base, probes):
    """Send each probe with its URI path preserved exactly.

    httpx normalises `..` segments away before the request leaves the machine,
    which would silently turn the S4 path-traversal payload into a different
    request. aiohttp with yarl(encoded=True) sends the path verbatim. See
    docs/adr/0002-http-client.md.
    """
    import aiohttp
    from yarl import URL

    host_and_stage = base.split("//", 1)[1]
    host, _, stage_prefix = host_and_stage.partition("/")
    out = []
    async with aiohttp.ClientSession() as s:
        for label, path, headers in probes:
            h = {k: v for k, v in (headers or {}).items() if v is not None}
            h.setdefault("User-Agent", "ddos-eval-smoke")
            if headers and headers.get("User-Agent", "") is None:
                h.pop("User-Agent", None)
            url = URL(f"https://{host}/{stage_prefix}{path}", encoded=True)
            try:
                async with s.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    body = await r.read()
                    out.append((label, r.status, len(body), str(url.path)))
            except Exception as e:  # noqa: BLE001
                out.append((label, f"ERR {type(e).__name__}", 0, path))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200, help="baseline latency samples")
    ap.add_argument("--rate", type=float, default=2.0, help="requests/second while sampling")
    a = ap.parse_args()

    base = tf_output("api_invoke_url")
    rest_api_id = tf_output("rest_api_id")
    stage = "exp"
    print(f"Endpoint: {base}\n")

    results = {"endpoint": base, "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # -- 1. functional probes ------------------------------------------------
    print("Functional probes (does every S4-shaped path reach the Lambda?)")
    print("-" * 78)
    probe_rows = []
    for label, status, size, sent_path in asyncio.run(probe_all(base, PATH_PROBES)):
        ok = "OK  " if status == 200 else "FAIL"
        print(f"  [{ok}] {label:<12} {str(status):<6} {size:>5}B  {sent_path[:46]}")
        probe_rows.append({"label": label, "sent_path": sent_path,
                           "status": status, "bytes": size})
    results["probes"] = probe_rows

    failed = [p for p in probe_rows if p["status"] != 200]
    if failed:
        print(f"\n  {len(failed)} probe(s) did not return 200 - investigate before Week 3.")

    # -- 2. baseline latency -------------------------------------------------
    print(f"\nUnloaded baseline latency: {a.n} requests at {a.rate} req/s")
    print("-" * 78)
    samples = []
    interval = 1.0 / a.rate
    with httpx.Client(http2=False) as client:
        # Warm-up, discarded: the first requests include Lambda cold start and
        # TLS session setup, neither of which belongs in a steady-state baseline.
        for _ in range(10):
            client.get(base + "/api/items", timeout=15)
        next_at = time.perf_counter()
        for i in range(a.n):
            next_at += interval
            t0 = time.perf_counter()
            r = client.get(base + "/api/items", timeout=15)
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code == 200:
                samples.append(dt)
            sleep = next_at - time.perf_counter()
            if sleep > 0:
                time.sleep(sleep)

    samples.sort()
    def pct(p):
        return samples[min(len(samples) - 1, int(len(samples) * p / 100))]

    stats = {
        "n": len(samples),
        "rate_req_s": a.rate,
        "min_ms": round(samples[0], 2),
        "p50_ms": round(pct(50), 2),
        "p95_ms": round(pct(95), 2),
        "p99_ms": round(pct(99), 2),
        "max_ms": round(samples[-1], 2),
        "mean_ms": round(statistics.fmean(samples), 2),
        "stdev_ms": round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
    }
    for k, v in stats.items():
        print(f"  {k:<12} {v}")
    results["baseline_latency"] = stats

    # -- 3. throttle limits in force (T017) ----------------------------------
    print("\nAPI Gateway throttle limits in force (T017)")
    print("-" * 78)
    s = config.session()
    apigw = s.client("apigateway")
    acct = apigw.get_account()
    st = apigw.get_stage(restApiId=rest_api_id, stageName=stage)

    throttle = {
        "account_rate_limit": acct.get("throttleSettings", {}).get("rateLimit"),
        "account_burst_limit": acct.get("throttleSettings", {}).get("burstLimit"),
        "stage_rate_limit": st.get("methodSettings", {}).get("*/*", {}).get("throttlingRateLimit"),
        "stage_burst_limit": st.get("methodSettings", {}).get("*/*", {}).get("throttlingBurstLimit"),
    }
    for k, v in throttle.items():
        print(f"  {k:<22} {v}")
    results["throttle_limits"] = throttle

    peak = 11  # the study's hard ceiling, from docs/aws-aup-compliance.md
    lowest = min(v for v in throttle.values() if isinstance(v, (int, float)))
    print(f"\n  Study peak rate is {peak} req/s against a lowest limit of {lowest:.0f} req/s")
    print(f"  Headroom: {lowest / peak:.0f}x - throttling should never engage, which is")
    print("  what the C1 measurements must demonstrate rather than assume.")

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "baseline-c1.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"\nWritten to {path.relative_to(REPO)}")
    print("\nNOTE: measured from the researcher's laptop. The generator hosts do not")
    print("exist until Week 4, so this baseline includes home-network latency and is")
    print("PROVISIONAL. Re-measure from gen-legit in Week 4 for the figure used in")
    print("the dissertation.")


if __name__ == "__main__":
    main()
