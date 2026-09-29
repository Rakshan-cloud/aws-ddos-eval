#!/usr/bin/env python3
"""Task T026 - calibrate the rate-based rule.

Confirms the configured threshold sits in the gap between the scenarios, and
measures how long AWS takes to start and stop rate limiting.

AWS documents that rate limiting is approximate: requests can exceed the limit
"for up to several minutes" before WAF detects them, and limiting stops
"usually below 30 seconds" after the rate drops. Those delays are not noise to
be averaged away -- a practitioner needs to know how long their service stays
degraded before the rule engages, so they are measured here and reported as a
finding.

Three phases, shaped like scenario S2:
    1. BELOW  threshold  - should never block      (validates S1 and S4)
    2. ABOVE  threshold  - should block            (validates S2 and S3)
    3. BELOW  threshold  - should stop blocking    (measures release)

    ./.venv/bin/python switch/apply_config.py C4
    ./.venv/bin/python scripts/calibrate_rate.py
"""
import asyncio
import json
import sys
import time
from pathlib import Path

import aiohttp
from yarl import URL

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from loadgen.payloads import BENIGN_HEADERS, BENIGN_PATH  # noqa: E402

PHASES = [
    ("below-1", 1.0, 90),    # 60 req/window, threshold is 100
    ("above", 10.0, 180),    # 600 req/window
    ("below-2", 1.0, 150),   # back under, measure release
]


async def pace(session, base, rate, duration, records, t0):
    """Send at a fixed rate, recording the outcome of every request."""
    interval = 1.0 / rate
    next_at = time.perf_counter()
    end = time.perf_counter() + duration
    while time.perf_counter() < end:
        next_at += interval
        sent = time.time()
        try:
            async with session.get(
                    URL(base + BENIGN_PATH, encoded=True),
                    headers=BENIGN_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=20)) as r:
                await r.read()
                status = r.status
        except Exception as e:  # noqa: BLE001
            status = f"ERR {type(e).__name__}"
        records.append({"t": round(sent - t0, 2), "status": status})
        sleep = next_at - time.perf_counter()
        if sleep > 0:
            await asyncio.sleep(sleep)


async def main():
    state = json.loads((REPO / "data" / "processed" / "active-config.json").read_text())
    cfg, base = state["configuration"], state["endpoint"]
    import subprocess
    if cfg == "C4":
        limit = subprocess.run(
            ["terraform", f"-chdir={REPO}/infra/30-waf-rate", "output", "-raw", "rate_limit"],
            capture_output=True, text=True, check=True).stdout.strip()
        window = subprocess.run(
            ["terraform", f"-chdir={REPO}/infra/30-waf-rate", "output", "-raw",
             "evaluation_window_sec"], capture_output=True, text=True, check=True).stdout.strip()
        rule_desc = f"block above {limit} requests per {window}s per source IP"
    else:
        # C5 has no explicit threshold - the anti-DDoS rule group decides for
        # itself, from traffic baselines it builds. That is precisely what is
        # unknown and worth measuring.
        limit, window = "n/a", "60"
        rule_desc = "AWS anti-DDoS managed rule group (no explicit threshold)"

    print(f"Configuration : {cfg}   {base}")
    print(f"Rule          : {rule_desc}\n")

    records = []
    t0 = time.time()
    async with aiohttp.ClientSession() as s:
        for name, rate, dur in PHASES:
            per_window = rate * int(window)
            rel = ("BELOW" if per_window < int(limit) else "ABOVE") if limit != "n/a" else "     "
            print(f"  phase {name:<9} {rate:>5.1f} req/s for {dur:>3}s "
                  f"= {per_window:>4.0f} per window  ({rel} threshold)")
            start = len(records)
            await pace(s, base, rate, dur, records, t0)
            seg = records[start:]
            blocked = sum(1 for r in seg if r["status"] == 403)
            print(f"                  -> {len(seg)} sent, {blocked} blocked "
                  f"({100 * blocked / max(1, len(seg)):.1f}%)")

    # --- onset and release ---------------------------------------------------
    above_start = PHASES[0][2]
    above_end = above_start + PHASES[1][2]

    first_block = next((r["t"] for r in records if r["status"] == 403), None)
    last_block = next((r["t"] for r in reversed(records) if r["status"] == 403), None)

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    below1 = [r for r in records if r["t"] < above_start]
    b1 = sum(1 for r in below1 if r["status"] == 403)
    print(f"  Below threshold, phase 1 : {b1} blocks in {len(below1)} requests")
    print(f"    {'no blocking at low rate' if b1 == 0 else 'blocking observed at low rate'}")

    if first_block is None:
        print("\n  NO BLOCKS OBSERVED - the rule did not engage.")
        print("  Either the threshold is too high, or the burst was too short.")
    else:
        onset = first_block - above_start
        print(f"\n  Block onset  : {onset:.0f}s after the rate went above threshold")
        print(f"                 (AWS documents this can take up to several minutes)")
        if last_block > above_end:
            print(f"  Block release: {last_block - above_end:.0f}s after the rate dropped")
            print(f"                 (AWS documents 'usually below 30 seconds')")
        else:
            print(f"  Block release: within the burst window - rate limiting had already")
            print(f"                 stopped before the rate dropped")

        above = [r for r in records if above_start <= r["t"] < above_end]
        ab = sum(1 for r in above if r["status"] == 403)
        print(f"\n  Above threshold : {ab}/{len(above)} blocked "
              f"({100 * ab / max(1, len(above)):.1f}%)")
        print("    PASS - S2 and S3 will trip the rule" if ab else "    FAIL")

    out = REPO / "data" / "processed" / f"rate-calibration-{cfg}.json"
    out.write_text(json.dumps({
        "configuration": cfg, "rate_limit": limit,
        "evaluation_window_sec": int(window),
        "phases": [{"name": n, "rate": r, "duration_s": d} for n, r, d in PHASES],
        "first_block_t": first_block, "last_block_t": last_block,
        "records": records,
    }, indent=2))
    print(f"\n  {len(records)} requests recorded -> {out.relative_to(REPO)}")


asyncio.run(main())
