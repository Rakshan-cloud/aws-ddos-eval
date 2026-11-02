#!/usr/bin/env python3
"""Task T050 - build the 5x4 results matrix, five metrics per cell.

This is the table the results chapter is written around: one row per
configuration, one column per scenario, and inside each cell the five
metrics with their spread across replications.

Emitted three ways, because they serve different readers:
  - a console table, for checking the numbers while working
  - Markdown, for pasting into the dissertation
  - JSON, so figures and prose read the same values rather than retyping them

Reads metrics-per-run.json only. Nothing is recomputed here, so a number in
the matrix and the same number in the statistics come from one definition.

    ./.venv/bin/python -m analysis.matrix
    ./.venv/bin/python -m analysis.matrix --markdown
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed"

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
SCENARIOS = ["S1", "S2", "S3", "S4"]

CONFIG_LABEL = {
    "C1": "Unprotected (API Gateway direct)",
    "C2": "CloudFront only",
    "C3": "CloudFront + managed rules",
    "C4": "CloudFront + rate-based rule",
    "C5": "CloudFront + anti-DDoS rule group",
}
SCENARIO_LABEL = {
    "S1": "Normal (1 req/s legitimate only)",
    "S2": "Burst (0 to 10 to 1 req/s)",
    "S3": "Sustained (5 req/s x 600s)",
    "S4": "Signature-bearing (1 req/s x 600s)",
}


def band(values: list[float], fmt: str = "{:.4f}") -> str:
    """Median, with the observed range when the replications disagree.

    No range is printed when all three agree. That is not the same as having
    no spread information: it says the three replications returned exactly
    the same value, which for this dataset is the common case and is itself
    the result worth reporting.
    """
    v = [x for x in values if x is not None]
    if not v:
        return "n/a"
    med = statistics.median(v)
    if len(v) == 1 or max(v) == min(v):
        return fmt.format(med)
    return f"{fmt.format(med)} [{fmt.format(min(v))}–{fmt.format(max(v))}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true", help="print the Markdown table")
    a = ap.parse_args()

    rows = json.loads((OUT / "metrics-per-run.json").read_text())
    cells = defaultdict(list)
    for r in rows:
        cells[(r["configuration"], r["scenario"])].append(r)

    matrix: dict = {}
    for cfg in CONFIGS:
        for scen in SCENARIOS:
            rs = cells.get((cfg, scen), [])
            if not rs:
                continue
            def col(k):
                return [r.get(k) for r in rs]
            m1 = [x for x in col("M1_blocked_ratio") if x is not None]
            matrix[f"{cfg}-{scen}"] = {
                "configuration": cfg, "scenario": scen,
                "n_replications": len(rs),
                "M1_blocked_ratio": {
                    "median": statistics.median(m1) if m1 else None,
                    "range": [min(m1), max(m1)] if len(m1) > 1 else None,
                    "source": rs[0]["M1_source"],
                },
                "M2_success_ratio": {
                    "median": statistics.median(col("M2_success_ratio")),
                    "range": [min(col("M2_success_ratio")), max(col("M2_success_ratio"))],
                },
                "M3_errors": {
                    "legit_2xx": sum(r["legit_2xx"] for r in rs),
                    "legit_non_2xx": sum(r["legit_403"] + r["legit_429"]
                                         + r["legit_4xx_other"] + r["legit_5xx"]
                                         + r["legit_error"] for r in rs),
                    "attacker_2xx": sum(r["attacker_2xx"] for r in rs),
                    "attacker_403": sum(r["attacker_403"] for r in rs),
                    "attacker_429": sum(r["attacker_429"] for r in rs),
                },
                "M4_p95_ms": {
                    "median": statistics.median(col("M4_p95_ms")),
                    "range": [min(col("M4_p95_ms")), max(col("M4_p95_ms"))],
                },
                "M5_monthly_usd": rs[0]["M5_monthly_usd"],
                "onset_s": band(col("onset_s"), "{:.1f}") if any(
                    x is not None for x in col("onset_s")) else None,
                "release_s": band(col("release_s"), "{:.1f}") if any(
                    x is not None for x in col("release_s")) else None,
            }

    # ---------------------------------------------------- console ---------
    print("=" * 100)
    print("RESULTS MATRIX — 5 configurations x 4 scenarios x 3 replications")
    print("=" * 100)
    for metric, key, fmt in (
            ("M1  blocked-request ratio", "M1_blocked_ratio", "{:.4f}"),
            ("M2  legitimate success rate", "M2_success_ratio", "{:.4f}"),
            ("M4  p95 latency (ms)", "M4_p95_ms", "{:.1f}")):
        print(f"\n{metric}")
        print(f"  {'':<6}" + "".join(f"{s:>26}" for s in SCENARIOS))
        print("  " + "-" * 110)
        for cfg in CONFIGS:
            line = f"  {cfg:<6}"
            for scen in SCENARIOS:
                c = matrix.get(f"{cfg}-{scen}")
                if not c:
                    line += f"{'-':>26}"
                    continue
                v = c[key]
                if v["median"] is None:
                    line += f"{'n/a':>26}"
                else:
                    txt = fmt.format(v["median"])
                    if v["range"] and v["range"][0] != v["range"][1]:
                        txt += f" [{fmt.format(v['range'][0])}-{fmt.format(v['range'][1])}]"
                    line += f"{txt:>26}"
            print(line)

    print(f"\nM5  protection cost (USD/month at 10M requests)")
    print("  " + "-" * 60)
    for cfg in CONFIGS:
        c = next((matrix[k] for k in matrix if k.startswith(cfg)), None)
        if c:
            print(f"  {cfg:<6}{c['M5_monthly_usd']:>8.2f}   {CONFIG_LABEL[cfg]}")

    print(f"\nOnset and release (seconds, scenario S2 and S3)")
    print("  " + "-" * 60)
    for cfg in CONFIGS:
        for scen in SCENARIOS:
            c = matrix.get(f"{cfg}-{scen}")
            if c and (c["onset_s"] or c["release_s"]):
                rel = c["release_s"] or "n/a (floods to window end)"
                print(f"  {cfg}-{scen}  onset {c['onset_s']:<22} release {rel}")

    # ---------------------------------------------------- markdown --------
    if a.markdown:
        lines = ["", "### M1 — blocked-request ratio", "",
                 "| | " + " | ".join(SCENARIOS) + " |",
                 "|---|" + "---|" * len(SCENARIOS)]
        for cfg in CONFIGS:
            cs = []
            for scen in SCENARIOS:
                c = matrix.get(f"{cfg}-{scen}")
                if not c or c["M1_blocked_ratio"]["median"] is None:
                    cs.append("—")
                else:
                    v = c["M1_blocked_ratio"]
                    t = f"{v['median']:.4f}"
                    if v["range"] and v["range"][0] != v["range"][1]:
                        t += f"<br><sub>[{v['range'][0]:.4f}–{v['range'][1]:.4f}]</sub>"
                    cs.append(t)
            lines.append(f"| **{cfg}** | " + " | ".join(cs) + " |")
        print("\n".join(lines))

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results-matrix.json").write_text(json.dumps({
        "cells": matrix,
        "config_labels": CONFIG_LABEL,
        "scenario_labels": SCENARIO_LABEL,
        "note": ("Medians across three replications, with the observed range where "
                 "the replications differ. Non-parametric: three replications give "
                 "no basis for assuming normality."),
    }, indent=2))
    print(f"\nwritten: data/processed/results-matrix.json")


if __name__ == "__main__":
    main()
