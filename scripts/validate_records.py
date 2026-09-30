#!/usr/bin/env python3
"""Task T032 - validate the run record schema and measure achieved rate.

The generator's output is the primary source for M2, M3 and M4. Before 60 runs
are executed against it, three properties need checking on real output rather
than assumed:

  SCHEMA   every record carries every field the analysis will need
  RATE     the attacker phases achieved the rate the scenario specified
  JOINABLE the AWS request ids needed to reconcile against WAF and API
           Gateway logs are actually present

    ./.venv/bin/python scripts/validate_records.py
"""
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "data" / "raw"

REQUIRED = {
    "t_send", "t_mono_ms", "source", "payload", "path", "status",
    "latency_ms", "ttfb_ms", "bytes", "aws_request_id", "phase",
}


def check(run_base: Path):
    manifest = json.loads(run_base.with_suffix(".manifest.json").read_text())
    records = [json.loads(l) for l in
               run_base.with_suffix(".records.jsonl").read_text().splitlines() if l]

    print(f"\n{manifest['run_id']}  ({manifest['scenario']}, {len(records)} records)")
    print("-" * 72)

    # --- schema ---------------------------------------------------------
    missing = REQUIRED - set(records[0])
    extra = set(records[0]) - REQUIRED - {"bytes_", "cf_request_id", "waf_action"}
    print(f"  schema      : {'OK' if not missing else 'MISSING ' + str(missing)}"
          f"{'  unexpected: ' + str(extra) if extra else ''}")

    # --- joinability ----------------------------------------------------
    with_aws_id = sum(1 for r in records if r.get("aws_request_id"))
    with_cf_id = sum(1 for r in records if r.get("cf_request_id"))
    print(f"  aws req id  : {with_aws_id}/{len(records)} "
          f"({'joinable to API Gateway logs' if with_aws_id else 'NOT joinable'})")
    print(f"  cf req id   : {with_cf_id}/{len(records)} "
          f"({'present' if with_cf_id else 'absent - expected for C1, direct to API Gateway'})")

    # --- achieved rate per phase ----------------------------------------
    by_phase = {}
    for r in records:
        by_phase.setdefault((r["source"], r["phase"]), []).append(r)

    print("  achieved rate per phase:")
    for (src, phase), rs in sorted(by_phase.items()):
        span = (max(r["t_mono_ms"] for r in rs) - min(r["t_mono_ms"] for r in rs)) / 1000
        # (n-1)/span, not n/span: n requests span n-1 intervals. Using n/span
        # overstates the rate by 1/span, which at short spans looks like drift
        # that is not there.
        rate = (len(rs) - 1) / span if span > 0 and len(rs) > 1 else 0
        target = phase.split("-r")[-1] if "-r" in phase else "1.0"
        try:
            t = float(target)
            drift = abs(rate - t) / t * 100 if t else 0
            flag = "" if drift <= 5 else "   <-- drift above 5%"
        except ValueError:
            t, drift, flag = "?", 0, ""
        print(f"    {src:<9} {phase:<10} {len(rs):>4} req over {span:>5.1f}s "
              f"= {rate:>5.2f} req/s  target {t}{flag}")

    # --- latency and status ---------------------------------------------
    lat = sorted(r["latency_ms"] for r in records if isinstance(r["status"], int))
    if lat:
        p = lambda q: lat[min(len(lat) - 1, int(len(lat) * q / 100))]
        print(f"  latency     : p50 {p(50):.1f}ms  p95 {p(95):.1f}ms  p99 {p(99):.1f}ms")
    print(f"  statuses    : {dict(Counter(r['status'] for r in records))}")
    print(f"  source ips  : {manifest['source_ips']}")

    ips = manifest["source_ips"]
    if ips.get("attacker") and ips.get("legit"):
        same = ips["attacker"] == ips["legit"]
        print(f"  ip separation: {'FAIL - both sources share an address' if same else 'OK - distinct'}")


runs = sorted(RAW.glob("*.manifest.json"))
if not runs:
    raise SystemExit("No runs found in data/raw/")
for m in runs:
    check(m.with_suffix("").with_suffix(""))
