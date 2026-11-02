#!/usr/bin/env python3
"""Task T049 - descriptive statistics and hypothesis tests over the matrix.

Non-parametric throughout. Three replications give no basis for assuming
normality, so medians, inter-quartile ranges and rank-based tests are used
rather than means, standard deviations and t-tests.

THE CONSTRAINT THAT GOVERNS THIS WHOLE MODULE
---------------------------------------------
A Mann-Whitney U test comparing two cells of three replications each cannot
produce a two-sided p below 0.10. There are C(6,3) = 20 distinct rank
assignments, so the most extreme possible outcome -- every value in one group
above every value in the other -- has probability 2/20 = 0.10.

That floor is a property of the sample size, not of the data. It means no
pairwise comparison in this experiment can be "significant at 0.05", however
large the real difference is. Reporting pairwise non-significance without
saying so would be actively misleading: it would read as evidence that two
configurations behave alike, when the test could not have said otherwise.

This module therefore does three things instead of leaning on pairwise p:

  1. Kruskal-Wallis across all five configurations within a scenario. With
     N = 15 that test CAN reach conventional significance, so it is the one
     place a p-value carries information.
  2. Cliff's delta as an effect size, which does not degrade at small n.
  3. An explicit flag for COMPLETE SEPARATION -- every observation in one
     cell above every observation in another. At n = 3 that is the strongest
     statement the data can support, and it is stronger than any p-value
     this design can produce.

    ./.venv/bin/python -m analysis.stats
    ./.venv/bin/python -m analysis.stats --metric M4_p95_ms
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import kruskal

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed"

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
SCENARIOS = ["S1", "S2", "S3", "S4"]
METRICS = ["M1_blocked_ratio", "M2_success_ratio", "M4_p95_ms"]

# Two-sided Mann-Whitney floor for n1 = n2 = 3.
PAIRWISE_P_FLOOR = 2 / math.comb(6, 3)


def iqr(v: list[float]) -> float | None:
    if len(v) < 2:
        return None
    q1, q3 = np.percentile(v, [25, 75])
    return float(q3 - q1)


def bootstrap_ci(v: list[float], reps: int = 10000, alpha: float = 0.05,
                 seed: int = 20261012) -> tuple[float, float] | None:
    """Percentile bootstrap CI for the median.

    Reported with a caveat rather than silently: resampling three values can
    only ever produce medians that are among those three values, so the
    interval is a coarse summary of a tiny sample, not a smooth estimate. It
    collapses to a point whenever the three replications agree exactly, which
    in this dataset is most cells.
    """
    if len(v) < 2:
        return None
    rng = np.random.default_rng(seed)
    draws = rng.choice(v, size=(reps, len(v)), replace=True)
    meds = np.median(draws, axis=1)
    lo, hi = np.percentile(meds, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def cliffs_delta(a: list[float], b: list[float]) -> tuple[float, str]:
    """Rank-based effect size: P(a > b) - P(a < b), in [-1, 1].

    Chosen because it does not depend on sample size for its interpretation,
    unlike a p-value. Thresholds are Romano et al.'s conventional bands.
    """
    gt = sum((x > y) for x in a for y in b)
    lt = sum((x < y) for x in a for y in b)
    d = (gt - lt) / (len(a) * len(b))
    m = abs(d)
    label = ("negligible" if m < 0.147 else "small" if m < 0.33
             else "medium" if m < 0.474 else "large")
    return d, label


def complete_separation(a: list[float], b: list[float]) -> bool:
    return min(a) > max(b) or min(b) > max(a)


def exact_mwu_p(a: list[float], b: list[float]) -> float:
    """Exact two-sided permutation p for the Mann-Whitney statistic.

    Computed by enumerating all C(n1+n2, n1) allocations rather than by
    calling scipy with its default method, because that default is unsafe
    here.

    scipy's method="auto" switches to a normal approximation whenever ties
    are present. Every cell in this experiment that reads exactly 0.0000 or
    exactly 1.0000 is entirely tied, so the approximation is what gets used
    precisely where the result is most clear-cut. Comparing [1,1,1] against
    [0,0,0] it returns p = 0.0469 -- below the 0.05 line, and below the 0.10
    floor that three-versus-three makes mathematically unavoidable. Reported
    unchecked, that single number would have become a significant finding in
    the dissertation that the design cannot support.

    The enumeration below returns 0.1000 for the same comparison, which is
    correct: the observed arrangement is the most extreme of twenty, counted
    at both tails.
    """
    pooled = list(a) + list(b)
    n1, n = len(a), len(a) + len(b)

    def U(x, y):
        gt = sum((xi > yi) for xi in x for yi in y)
        eq = sum((xi == yi) for xi in x for yi in y)
        return gt + 0.5 * eq          # mid-ranks, so ties are handled

    observed = U(a, b)
    centre = n1 * (n - n1) / 2
    allocations = list(itertools.combinations(range(n), n1))
    as_extreme = 0
    for comb in allocations:
        picked = set(comb)
        g1 = [pooled[i] for i in comb]
        g2 = [pooled[i] for i in range(n) if i not in picked]
        if abs(U(g1, g2) - centre) >= abs(observed - centre):
            as_extreme += 1
    return as_extreme / len(allocations)


def permutation_kruskal_p(groups: list[list[float]], reps: int = 200_000,
                          seed: int = 20261012) -> float:
    """Monte Carlo permutation p for Kruskal-Wallis H.

    scipy's kruskal() returns a chi-square approximation to H's null
    distribution. That approximation assumes reasonably sized groups and no
    heavy tie structure, and this dataset violates both: several scenarios
    consist of twelve identical values and three identical values, in groups
    of three.

    Rather than trust the approximation where its assumptions plainly fail,
    the null is built by reshuffling the observed values across groups. For
    scenario S4 the approximation gives p = 0.0073 and the permutation null
    gives about 0.011 -- the same conclusion, but the second one is a
    statement about this data rather than about an asymptotic limit this
    experiment never approaches.

    Exact enumeration would need 15!/(3!^5) = 168,168,000 allocations, so
    this is sampled. The seed is the project's randomisation seed.
    """
    sizes = [len(g) for g in groups]
    pooled = np.array([x for g in groups for x in g], dtype=float)

    def H(parts):
        n = len(pooled)
        ranks = np.empty(n)
        order = np.argsort(pooled if parts is None else parts, kind="stable")
        # average ranks for ties
        sorted_vals = (pooled if parts is None else parts)[order]
        ranks_sorted = np.empty(n)
        i = 0
        while i < n:
            j = i
            while j + 1 < n and sorted_vals[j + 1] == sorted_vals[i]:
                j += 1
            ranks_sorted[i:j + 1] = (i + j) / 2.0 + 1.0
            i = j + 1
        ranks[order] = ranks_sorted
        total, out, start = 0.0, 0.0, 0
        for sz in sizes:
            r = ranks[start:start + sz]
            out += (r.sum() ** 2) / sz
            start += sz
        total = 12.0 / (n * (n + 1)) * out - 3 * (n + 1)
        return total

    observed = H(None)
    rng = np.random.default_rng(seed)
    count = 0
    for _ in range(reps):
        if H(rng.permutation(pooled)) >= observed - 1e-12:
            count += 1
    return count / reps


def describe(values: list[float]) -> dict:
    v = [x for x in values if x is not None]
    if not v:
        return {"n": 0}
    ci = bootstrap_ci(v)
    return {
        "n": len(v),
        "median": statistics.median(v),
        "iqr": iqr(v),
        "min": min(v),
        "max": max(v),
        "range": max(v) - min(v),
        "zero_variance": max(v) == min(v),
        "bootstrap_ci_95": list(ci) if ci else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--metric", choices=METRICS, help="limit output to one metric")
    a = ap.parse_args()

    rows = json.loads((OUT / "metrics-per-run.json").read_text())
    metrics = [a.metric] if a.metric else METRICS

    cells: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for r in rows:
        for m in METRICS:
            if r.get(m) is not None:
                cells[(m, r["configuration"], r["scenario"])].append(r[m])

    report: dict = {
        "design": {
            "replications_per_cell": 3,
            "configurations": len(CONFIGS),
            "scenarios": len(SCENARIOS),
            "pairwise_two_sided_p_floor": PAIRWISE_P_FLOOR,
            "note": (
                "Mann-Whitney with n1=n2=3 cannot produce p below 0.10; the floor "
                "is 2/C(6,3). No pairwise comparison in this design can reach "
                "alpha=0.05 regardless of effect size. Pairwise results are "
                "therefore reported as effect sizes and separation, not as "
                "significance. Kruskal-Wallis across five configurations (N=15) "
                "is not subject to this floor and is the omnibus test used."),
        },
        "cells": {}, "omnibus": {}, "pairwise": {},
    }

    print("=" * 78)
    print("DESIGN CONSTRAINT")
    print("=" * 78)
    print(f"  Pairwise Mann-Whitney (3 vs 3) two-sided p floor : {PAIRWISE_P_FLOOR:.2f}")
    print("  No pairwise test here can reach alpha = 0.05. Effect size and")
    print("  complete separation are reported instead. Kruskal-Wallis across")
    print("  five configurations (N = 15) is the omnibus test.\n")

    for m in metrics:
        print("=" * 78)
        print(f"{m}")
        print("=" * 78)
        print(f"  {'cell':<9}{'n':>3}{'median':>10}{'IQR':>8}{'range':>18}  {'':<16}")
        print("  " + "-" * 74)
        for scen in SCENARIOS:
            for cfg in CONFIGS:
                v = cells.get((m, cfg, scen), [])
                d = describe(v)
                report["cells"][f"{m}|{cfg}-{scen}"] = d
                if not d["n"]:
                    continue
                flag = "  (identical)" if d["zero_variance"] else ""
                print(f"  {cfg}-{scen:<6}{d['n']:>3}{d['median']:>10.4f}"
                      f"{(d['iqr'] or 0):>8.4f}"
                      f"{f'[{d['min']:.4f}-{d['max']:.4f}]':>18}{flag}")
            print()

        # ---- omnibus, per scenario ---------------------------------------
        print("  Kruskal-Wallis across configurations, within each scenario")
        print("  " + "-" * 74)
        for scen in SCENARIOS:
            groups = [cells.get((m, c, scen), []) for c in CONFIGS]
            groups = [g for g in groups if len(g) >= 2]
            if len(groups) < 2:
                print(f"    {scen}: not enough populated cells")
                continue
            if all(max(g) == min(g) for g in groups) and len({g[0] for g in groups}) == 1:
                print(f"    {scen}: every configuration identical "
                      f"({groups[0][0]:.4f}) - no test possible, and none needed")
                report["omnibus"][f"{m}|{scen}"] = {"test": "none", "reason": "all cells identical"}
                continue
            try:
                h, p_chi2 = kruskal(*groups)
                p = permutation_kruskal_p(groups)
                sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
                print(f"    {scen}: H = {h:7.3f}   p(perm) = {p:.5f}  "
                      f"[chi2 approx {p_chi2:.5f}]  {sig}")
                report["omnibus"][f"{m}|{scen}"] = {
                    "test": "kruskal-wallis",
                    "H": float(h),
                    "p_permutation": float(p),
                    "p_chi2_approx": float(p_chi2),
                    "p_reported": float(p),
                    "permutation_reps": 200000,
                    "df": len(groups) - 1,
                    "n_total": sum(len(g) for g in groups)}
            except ValueError as e:
                print(f"    {scen}: test not applicable ({e})")
                report["omnibus"][f"{m}|{scen}"] = {"test": "none", "reason": str(e)}
        print()

        # ---- pairwise, as effect size ------------------------------------
        print("  Pairwise effect sizes (Cliff's delta); p shown only for context")
        print("  " + "-" * 74)
        shown = 0
        for scen in SCENARIOS:
            for c1, c2 in itertools.combinations(CONFIGS, 2):
                A, B = cells.get((m, c1, scen), []), cells.get((m, c2, scen), [])
                if len(A) < 2 or len(B) < 2:
                    continue
                if max(A) == min(A) and max(B) == min(B) and A[0] == B[0]:
                    continue                      # identical cells, nothing to compare
                d, label = cliffs_delta(A, B)
                sep = complete_separation(A, B)
                p = exact_mwu_p(A, B)
                report["pairwise"][f"{m}|{scen}|{c1}vs{c2}"] = {
                    "cliffs_delta": d, "magnitude": label,
                    "complete_separation": sep,
                    "mannwhitney_p_exact": p,
                    "p_floor": PAIRWISE_P_FLOOR,
                    "method": "exact enumeration of all C(6,3) allocations"}
                if sep or abs(d) > 0.474:
                    mark = "COMPLETE SEPARATION" if sep else ""
                    print(f"    {scen} {c1} vs {c2:<4} delta = {d:+.3f} ({label:<10}) "
                          f"p = {p:.3f}  {mark}")
                    shown += 1
        if not shown:
            print("    no pair reached a large effect")
        print()

    (OUT / "statistics.json").write_text(json.dumps(report, indent=2, default=str))
    print(f"written: data/processed/statistics.json")


if __name__ == "__main__":
    main()
