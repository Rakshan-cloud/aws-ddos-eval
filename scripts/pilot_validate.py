#!/usr/bin/env python3
"""Task T037 - compute all five metrics for one cell and check every join.

This is the Week 5 gate. It answers one question: can a completed run be
turned into the five numbers the dissertation reports, with every figure
traceable to a source?

If any join fails here, it would fail silently sixty times in Weeks 6 and 7.

    ./.venv/bin/python scripts/pilot_validate.py C4-S2-R1
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "data" / "raw"


def load_cell(run_id: str):
    """A cell is two half-runs, one per generator host, merged."""
    parts = {}
    for role in ("legit", "attacker"):
        manifests = sorted(RAW.glob(f"{run_id}-{role}-*.manifest.json"))
        if not manifests:
            continue
        m = manifests[-1]
        recs_path = m.with_name(m.name.replace(".manifest.json", ".records.jsonl"))
        parts[role] = {
            "manifest": json.loads(m.read_text()),
            "records": [json.loads(l) for l in recs_path.read_text().splitlines() if l],
            "stem": m.name.replace(".manifest.json", ""),
        }
    if not parts:
        sys.exit(f"no run files found for {run_id} in {RAW}")
    return parts


def pct(values, q):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * q / 100))], 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    a = ap.parse_args()

    parts = load_cell(a.run_id)
    print(f"PILOT VALIDATION — {a.run_id}")
    print("=" * 74)

    # ---------------------------------------------------- integrity ------
    print("\n1. RUN INTEGRITY")
    print("-" * 74)
    ips = {}
    for role, p in parts.items():
        m = p["manifest"]
        ips[role] = m["source_ips"].get(role) or m["source_ips"].get("legit")
        print(f"  {role:<9} {len(p['records']):>5} records  "
              f"started {m['started_utc']}  elapsed {m['elapsed_seconds']:.0f}s  "
              f"host={m.get('generator_host')}")

    if len(parts) == 2:
        starts = {p["manifest"]["started_utc"] for p in parts.values()}
        print(f"  synchronised start : {'OK - identical' if len(starts) == 1 else f'DRIFT {starts}'}")
        a_ip = parts["attacker"]["manifest"]["source_ips"]["attacker"]
        l_ip = parts["legit"]["manifest"]["source_ips"]["legit"]
        print(f"  attacker IP        : {a_ip}")
        print(f"  legitimate IP      : {l_ip}")
        print(f"  source separation  : {'OK - distinct (D3 satisfied)' if a_ip != l_ip else 'FAIL - shared address'}")
        print(f"  git sha            : {parts['legit']['manifest']['git_sha']}")
        waf = parts["legit"]["manifest"].get("waf", {})
        print(f"  rule groups        : {waf.get('rule_groups') or waf.get('note', 'n/a')}")

    legit = parts.get("legit", {}).get("records", [])
    attacker = parts.get("attacker", {}).get("records", [])

    # ---------------------------------------------------- M1 -------------
    print("\n2. M1 — BLOCKED-REQUEST RATIO")
    print("-" * 74)
    stem = parts[list(parts)[0]]["stem"]
    waf_file = RAW / f"{stem}.waflogs.json"
    if waf_file.exists():
        w = json.loads(waf_file.read_text())["summary"]
        print(f"  source      : WAF full logs (primary)")
        print(f"  evaluated   : {w.get('evaluated')}")
        print(f"  actions     : {w.get('actions')}")
        print(f"  M1          : {w.get('blocked_ratio')}")
    else:
        print("  WAF log file not collected yet — run collect/waf_logs.py first")

    # Client-side cross-check. These should agree with the WAF ratio; a large
    # divergence means requests are being answered by something other than the
    # web ACL, which is itself a finding.
    att_403 = sum(1 for r in attacker if r["status"] == 403)
    print(f"  cross-check : attacker saw {att_403}/{len(attacker)} forbidden "
          f"({att_403 / len(attacker) * 100:.1f}%)" if attacker else "  cross-check : no attacker records")

    # ---------------------------------------------------- M2 -------------
    print("\n3. M2 — LEGITIMATE-TRAFFIC SUCCESS RATE")
    print("-" * 74)
    if legit:
        ok = sum(1 for r in legit if r["status"] == 200)
        m2 = ok / len(legit)
        print(f"  source      : client records from the legitimate host only")
        print(f"  successful  : {ok}/{len(legit)}")
        print(f"  M2          : {m2:.4f}  ({m2 * 100:.2f}%)")
        print(f"  statuses    : {dict(Counter(r['status'] for r in legit))}")
        if m2 == 1.0 and att_403:
            print("\n  KEY RESULT: the attacker was rate limited while the legitimate")
            print("  client was untouched. That separation is only observable because")
            print("  the two sources have different addresses (decision D3).")
    else:
        print("  no legitimate records")

    # ---------------------------------------------------- M3 -------------
    print("\n4. M3 — ERROR BEHAVIOUR")
    print("-" * 74)
    def classify(status):
        if status == 200:
            return "2xx success"
        if status == 403:
            return "403 blocked"
        if status == 429:
            return "429 throttled"
        if isinstance(status, int) and 500 <= status < 600:
            return f"{status} origin error"
        if isinstance(status, int) and 400 <= status < 500:
            return f"{status} client error"
        return str(status)

    for label, recs in (("legit", legit), ("attacker", attacker)):
        if recs:
            c = Counter(classify(r["status"]) for r in recs)
            print(f"  {label:<9} {dict(c)}")

    # ---------------------------------------------------- M4 -------------
    print("\n5. M4 — p95 LATENCY (legitimate traffic)")
    print("-" * 74)
    lat = [r["latency_ms"] for r in legit if r["status"] == 200]
    if lat:
        print(f"  source      : client-measured, legitimate host, successful requests only")
        print(f"  n           : {len(lat)}")
        print(f"  p50         : {pct(lat, 50)} ms")
        print(f"  p95         : {pct(lat, 95)} ms   <- M4")
        print(f"  p99         : {pct(lat, 99)} ms")
        base = REPO / "data" / "processed" / "baseline-c1.json"
        if base.exists():
            b = json.loads(base.read_text())["baseline_latency"]
            print(f"  Week 2 laptop baseline p95 was {b['p95_ms']} ms — not comparable,")
            print(f"  different vantage point. The EC2 baseline replaces it.")
    else:
        print("  no successful legitimate requests to measure")

    # ---------------------------------------------------- M5 -------------
    print("\n6. M5 — PROTECTION COST")
    print("-" * 74)
    cm = REPO / "data" / "processed" / "cost-model.json"
    if cm.exists():
        model = json.loads(cm.read_text())["model"]
        cfg = parts[list(parts)[0]]["manifest"]["configuration"]
        row = model["by_configuration"].get(cfg, {})
        print(f"  source      : AWS Pricing API, read {json.loads(cm.read_text())['read_at'][:10]}")
        print(f"  at {model['monthly_requests']:,} requests/month, {cfg} costs "
              f"${row.get('total_monthly_usd')}/month")
        print(f"    fixed ${row.get('fixed_monthly_usd')} + requests ${row.get('request_monthly_usd')}")
    else:
        print("  run collect/costs.py first")

    # ---------------------------------------------------- phases ---------
    print("\n7. ONSET AND RELEASE (scenario S2 only)")
    print("-" * 74)
    if attacker:
        blocked_times = [r["t_mono_ms"] / 1000 for r in attacker if r["status"] == 403]
        phases = sorted({r["phase"] for r in attacker})
        print(f"  attacker phases: {phases}")
        if blocked_times:
            burst_start = 120  # from scenarios.yaml S2 phase 0 duration
            burst_end = 300
            print(f"  first block at  : {min(blocked_times):.0f}s  "
                  f"(onset {min(blocked_times) - burst_start:+.0f}s after burst start)")
            print(f"  last block at   : {max(blocked_times):.0f}s  "
                  f"(release {max(blocked_times) - burst_end:+.0f}s after burst end)")
        else:
            print("  no blocks observed in the attacker stream")

    print("\n" + "=" * 74)
    print("All five metrics computed from collected data. If every section above")
    print("has a value and a named source, the pipeline is ready for Weeks 6-7.")


if __name__ == "__main__":
    main()
