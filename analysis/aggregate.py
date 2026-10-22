#!/usr/bin/env python3
"""Summarise completed runs into per-cell results.

A cell is one configuration crossed with one scenario, across its
replications. This reduces the raw per-request records to the five metrics and
reports the median and spread across replications rather than a single run, so
that a result is distinguishable from an outlier.

Non-parametric throughout. With three replications there is no basis for
assuming normality, so medians and ranges are reported rather than means and
standard deviations.

    ./.venv/bin/python -m analysis.aggregate
    ./.venv/bin/python -m analysis.aggregate --config C2
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "data" / "raw"
OUT = REPO / "data" / "processed"


def pct(values, q):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * q / 100))]


def load_run(run_id: str) -> dict | None:
    """Assemble one run from its two half-manifests and their records."""
    parts = {}
    for role in ("legit", "attacker"):
        ms = sorted(RAW.glob(f"{run_id}-{role}-*.manifest.json"))
        if not ms:
            continue
        m = ms[-1]
        recs = m.with_name(m.name.replace(".manifest.json", ".records.jsonl"))
        if not recs.exists():
            continue
        parts[role] = {
            "manifest": json.loads(m.read_text()),
            "records": [json.loads(l) for l in recs.read_text().splitlines() if l],
            "stem": m.name.replace(".manifest.json", ""),
        }
    if "legit" not in parts:
        return None

    legit = parts["legit"]["records"]
    attacker = parts.get("attacker", {}).get("records", [])
    cfg = parts["legit"]["manifest"]["configuration"]

    # --- M1 ---------------------------------------------------------------
    # From the WAF logs where a web ACL exists. In C1 and C2 nothing is
    # evaluating requests, so M1 is zero by definition rather than measured --
    # a distinction worth preserving in the output.
    m1, m1_source = None, "not applicable"
    if cfg in ("C1", "C2"):
        m1, m1_source = 0.0, "no web ACL (zero by definition)"
    else:
        for stem in (parts.get("attacker", {}).get("stem"), parts["legit"]["stem"]):
            if not stem:
                continue
            wf = RAW / f"{stem}.waflogs.json"
            if wf.exists():
                w = json.loads(wf.read_text()).get("summary", {})
                if w.get("M1_blocked_ratio") is not None:
                    m1, m1_source = w["M1_blocked_ratio"], "WAF full logs"
                    break
        if m1 is None and attacker:
            blocked = sum(1 for r in attacker if r["status"] == 403)
            m1, m1_source = blocked / len(attacker), "client-observed 403 (fallback)"

    # --- M2, M3, M4 --------------------------------------------------------
    ok = sum(1 for r in legit if r["status"] == 200)
    m2 = ok / len(legit) if legit else None

    errors = defaultdict(int)
    for r in legit + attacker:
        s = r["status"]
        key = ("2xx" if s == 200 else "403" if s == 403 else "429" if s == 429
               else f"{s // 100}xx" if isinstance(s, int) else "error")
        errors[key] += 1

    lat = [r["latency_ms"] for r in legit if r["status"] == 200]

    return {
        "run_id": run_id,
        "configuration": cfg,
        "scenario": parts["legit"]["manifest"]["scenario"],
        "replication": parts["legit"]["manifest"]["replication"],
        "M1": m1, "M1_source": m1_source,
        "M2": m2,
        "M3": dict(errors),
        "M4_p95_ms": round(pct(lat, 95), 1) if lat else None,
        "M4_p50_ms": round(pct(lat, 50), 1) if lat else None,
        "legit_requests": len(legit),
        "attacker_requests": len(attacker),
        "rate_drift_pct": parts["legit"]["manifest"].get("legit_rate_drift_pct"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", help="limit to one configuration")
    a = ap.parse_args()

    run_ids = sorted({m.name.split("-legit-")[0]
                      for m in RAW.glob("*-legit-*.manifest.json")})
    runs = [r for r in (load_run(rid) for rid in run_ids) if r]
    runs = [r for r in runs if not a.config or r["configuration"] == a.config]
    if not runs:
        raise SystemExit("no completed runs match that selection")

    cells = defaultdict(list)
    for r in runs:
        cells[(r["configuration"], r["scenario"])].append(r)

    print(f"{len(runs)} runs across {len(cells)} cells\n")
    print(f"  {'cell':<10}{'n':>3}  {'M1 blocked':>12}  {'M2 success':>12}"
          f"  {'M4 p95 ms':>18}  {'attacker reqs':>14}")
    print("  " + "-" * 78)

    summary = {}
    for (cfg, scen), rs in sorted(cells.items()):
        m1s = [r["M1"] for r in rs if r["M1"] is not None]
        m2s = [r["M2"] for r in rs if r["M2"] is not None]
        m4s = [r["M4_p95_ms"] for r in rs if r["M4_p95_ms"] is not None]
        att = [r["attacker_requests"] for r in rs]

        def band(vals, fmt="{:.4f}"):
            if not vals:
                return "n/a"
            med = statistics.median(vals)
            if len(vals) == 1:
                return fmt.format(med)
            return f"{fmt.format(med)} [{fmt.format(min(vals))}-{fmt.format(max(vals))}]"

        print(f"  {cfg}-{scen:<6}{len(rs):>3}  {band(m1s):>12}  {band(m2s):>12}"
              f"  {band(m4s, '{:.1f}'):>18}  {statistics.median(att):>14.0f}")

        summary[f"{cfg}-{scen}"] = {
            "n_replications": len(rs),
            "M1_median": statistics.median(m1s) if m1s else None,
            "M1_range": [min(m1s), max(m1s)] if len(m1s) > 1 else None,
            "M1_source": rs[0]["M1_source"],
            "M2_median": statistics.median(m2s) if m2s else None,
            "M2_range": [min(m2s), max(m2s)] if len(m2s) > 1 else None,
            "M4_p95_median_ms": statistics.median(m4s) if m4s else None,
            "M4_p95_range_ms": [min(m4s), max(m4s)] if len(m4s) > 1 else None,
            "attacker_requests_median": statistics.median(att),
        }

    base = OUT / "baseline-ec2.json"
    if base.exists():
        b = json.loads(base.read_text())["latency"]["p95_ms"]
        print(f"\n  unloaded baseline p95: {b} ms (same host, C1, no load)")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "cell-summary.json").write_text(json.dumps({
        "runs_included": len(runs), "cells": summary,
        "note": ("Medians with [min-max] across replications. Non-parametric: "
                 "three replications give no basis for assuming normality."),
    }, indent=2))
    (OUT / "per-run-metrics.json").write_text(json.dumps(runs, indent=2))
    print(f"\n  written: cell-summary.json, per-run-metrics.json")


if __name__ == "__main__":
    main()
