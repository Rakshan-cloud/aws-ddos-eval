#!/usr/bin/env python3
"""Task T051 - the dissertation figures.

Four figures, each answering one question the results chapter asks:

    fig1-blocked-ratio      which configuration stops which attack class
    fig2-latency-cdf        what protection costs in latency, full distribution
    fig3-block-onset        how long rate limiting takes to engage and release
    fig4-cost-effectiveness cost against protection, per attack class

Written to figures/ as PNG at 200 dpi and PDF as vector, because a thesis
goes to print and a rasterised plot at A4 looks poor.

Deliberately plain: no colour-coded significance, no error bars implying a
sampling distribution. With three replications an error bar would suggest
more precision than the design supports, so spread is drawn as the observed
individual points instead -- the reader sees three dots and knows exactly
how much data is behind each bar.

    ./.venv/bin/python -m analysis.figures
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "data" / "raw"
OUT = REPO / "data" / "processed"
FIGS = REPO / "figures"

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
SCENARIOS = ["S2", "S3", "S4"]
SCEN_TITLE = {"S1": "S1 normal", "S2": "S2 burst",
              "S3": "S3 sustained", "S4": "S4 signature-bearing"}

# A single grey-scale-safe palette: the thesis may be printed in black and
# white, so the bars are distinguished by hatch as well as by shade.
SHADE = {"C1": "#d9d9d9", "C2": "#bdbdbd", "C3": "#969696",
         "C4": "#636363", "C5": "#252525"}
HATCH = {"C1": "", "C2": "//", "C3": "..", "C4": "xx", "C5": "\\\\"}

# The CDF needs lines that stay distinct in greyscale, so shade alone is not
# enough -- five greys at similar luminance are indistinguishable in print.
LINE_COLOR = {"C1": "#000000", "C2": "#777777", "C3": "#000000",
              "C4": "#777777", "C5": "#000000"}
LINE_STYLE = {"C1": "-", "C2": "-", "C3": "--", "C4": "--", "C5": ":"}


def style():
    plt.rcParams.update({
        "font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
        "figure.dpi": 110, "savefig.dpi": 200, "savefig.bbox": "tight",
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.5,
    })


def save(fig, name: str):
    FIGS.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"{name}.{ext}")
    plt.close(fig)
    print(f"  {name}.png / .pdf")


def load_runs() -> list[dict]:
    return json.loads((OUT / "metrics-per-run.json").read_text())


# ------------------------------------------------------------------ fig 1 --

def fig_blocked_ratio(runs):
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.4), sharey=True)
    for ax, scen in zip(axes, SCENARIOS):
        for i, cfg in enumerate(CONFIGS):
            vals = [r["M1_blocked_ratio"] for r in runs
                    if r["configuration"] == cfg and r["scenario"] == scen
                    and r["M1_blocked_ratio"] is not None]
            if not vals:
                continue
            med = float(np.median(vals))
            ax.bar(i, med, color=SHADE[cfg], hatch=HATCH[cfg],
                   edgecolor="black", linewidth=0.6, width=0.68)
            # The three replications themselves, not an error bar.
            ax.plot([i] * len(vals), vals, "o", color="white",
                    markeredgecolor="black", markersize=3.5,
                    markeredgewidth=0.6, zorder=3)
        ax.set_xticks(range(len(CONFIGS)))
        ax.set_xticklabels(CONFIGS)
        ax.set_ylim(-0.04, 1.08)
        ax.set_title(SCEN_TITLE[scen])
    axes[0].set_ylabel("blocked-request ratio (M1)")
    fig.suptitle("Blocked-request ratio by configuration and attack class",
                 y=1.04, fontsize=11)
    fig.text(0.5, -0.09, "Bars are medians of three replications; "
             "white dots are the individual runs.", ha="center", fontsize=8,
             color="#555555")
    save(fig, "fig1-blocked-ratio")


# ------------------------------------------------------------------ fig 2 --

def fig_latency_cdf(runs):
    """Empirical CDF of legitimate request latency, pooled per configuration.

    A CDF rather than a box plot because the question is not only "how big is
    p95" but "where does the distribution start to diverge" -- and for these
    configurations it diverges only in the tail.
    """
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    for cfg in CONFIGS:
        lat: list[float] = []
        for r in runs:
            if r["configuration"] != cfg or r["scenario"] != "S3":
                continue
            stems = sorted(RAW.glob(f"{r['run_id']}-legit-*.records.jsonl"))
            if not stems:
                continue
            lat += [json.loads(l)["latency_ms"]
                    for l in stems[-1].read_text().splitlines()
                    if l and json.loads(l)["status"] == 200]
        if not lat:
            continue
        x = np.sort(lat)
        y = np.arange(1, len(x) + 1) / len(x)
        ax.step(x, y, where="post", label=f"{cfg}  (n={len(x)})",
                color=LINE_COLOR[cfg], linestyle=LINE_STYLE[cfg],
                linewidth=1.6)
    ax.set_xlim(10, 70)
    ax.set_xlabel("latency (ms)")
    ax.set_ylabel("cumulative proportion of requests")
    ax.set_title("Legitimate-traffic latency under sustained flood (S3)")
    ax.axhline(0.95, color="black", linewidth=0.7, linestyle=":")
    ax.text(10.4, 0.955, "p95", fontsize=8, color="#555555")
    ax.legend(frameon=False, loc="lower right", fontsize=8)
    save(fig, "fig2-latency-cdf")


# ------------------------------------------------------------------ fig 3 --

def fig_block_onset():
    """Attacker request outcomes over time for C4-S2: onset and release.

    The single most informative figure in the set, because it shows the
    mechanism rather than a summary of it -- the rule engaging part-way into
    the burst, and still blocking long after the burst has stopped.
    """
    stems = sorted(RAW.glob("C4-S2-R*-attacker-*.records.jsonl"))
    if not stems:
        print("  (skipped fig3: no C4-S2 attacker records)")
        return
    fig, axes = plt.subplots(3, 1, figsize=(7.2, 5.4), sharex=True)
    for ax, f in zip(axes, stems[:3]):
        recs = [json.loads(l) for l in f.read_text().splitlines() if l]
        t = np.array([r["t_mono_ms"] / 1000.0 for r in recs])
        blocked = np.array([r["status"] == 403 for r in recs])
        ax.scatter(t[~blocked], np.zeros((~blocked).sum()), s=3,
                   color="#999999", label="allowed (200)")
        ax.scatter(t[blocked], np.ones(blocked.sum()), s=3,
                   color="#252525", label="blocked (403)")
        ax.axvspan(120, 300, color="#000000", alpha=0.06)
        if blocked.any():
            ax.axvline(t[blocked].min(), color="black", linewidth=0.8, linestyle="--")
            ax.axvline(t[blocked].max(), color="black", linewidth=0.8, linestyle="--")
        ax.set_yticks([0, 1])
        ax.set_yticklabels(["allowed", "blocked"], fontsize=8)
        ax.set_ylim(-0.5, 1.5)
        ax.set_ylabel(f.name.split("-attacker")[0].split("-")[-1], fontsize=8)
    axes[-1].set_xlabel("seconds since run start")
    axes[0].set_title("Rate-limiting onset and release (C4, scenario S2)\n"
                      "shaded band is the 10 req/s burst", fontsize=10)
    axes[0].legend(frameon=False, fontsize=8, ncol=2, loc="upper right")
    save(fig, "fig3-block-onset")


# ------------------------------------------------------------------ fig 4 --

def fig_cost_effectiveness(runs):
    """Monthly cost against blocked ratio, per attack class.

    Placed last because it is the figure that carries the practical argument:
    the most expensive configuration sits at zero on both attack classes.
    """
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    for ax, (scen, title) in zip(axes, [("S3", "Sustained flood (S3)"),
                                        ("S4", "Signature-bearing (S4)")]):
        # C1 and C2 both cost nothing and both block nothing, so they land on
        # the same point. Labels are stacked rather than overprinted -- two
        # configurations sharing a coordinate is a result, not a collision to
        # hide.
        seen: dict[tuple[float, float], int] = {}
        for cfg in CONFIGS:
            vals = [r["M1_blocked_ratio"] for r in runs
                    if r["configuration"] == cfg and r["scenario"] == scen
                    and r["M1_blocked_ratio"] is not None]
            cost = next((r["M5_monthly_usd"] for r in runs
                         if r["configuration"] == cfg), None)
            if not vals or cost is None:
                continue
            y = float(np.median(vals))
            ax.scatter(cost, y, s=90, color=SHADE[cfg],
                       edgecolor="black", linewidth=0.7, zorder=3)
            k = (round(cost, 2), round(y, 4))
            offset = seen.get(k, 0)
            seen[k] = offset + 1
            ax.annotate(cfg, (cost, y), textcoords="offset points",
                        xytext=(8, 4 + offset * 11), fontsize=9)
        ax.set_xlabel("protection cost (USD/month at 10M requests)")
        ax.set_title(title)
        ax.set_xlim(-2, 37)
        ax.set_ylim(-0.08, 1.12)
    axes[0].set_ylabel("blocked-request ratio (M1)")
    fig.suptitle("Cost against protection delivered", y=1.03, fontsize=11)
    save(fig, "fig4-cost-effectiveness")


def main():
    style()
    runs = load_runs()
    print(f"figures from {len(runs)} runs -> {FIGS.relative_to(REPO)}/")
    fig_blocked_ratio(runs)
    fig_latency_cdf(runs)
    fig_block_onset()
    fig_cost_effectiveness(runs)


if __name__ == "__main__":
    main()
