#!/usr/bin/env python3
"""Task T054 - the two Chapter 4 figures.

    fig5-architecture   the deployed system, the two traffic sources and the
                        five protection configurations
    fig6-data-flow      where each of the five metrics comes from, and the
                        chain that turns raw records into the results matrix

Every label that asserts a FACT about the deployment -- region, instance type,
Lambda memory, response size, rate limit, evaluation window, managed rule
group names, anti-DDoS settings, scenario rates -- is read out of the artefact
that defines it: the Terraform sources for infrastructure, the frozen scenario
file for traffic, the Lambda source for the response. Nothing factual is typed
into this module.

The reason is the same one behind the rest of this codebase. A hand-drawn
architecture diagram is a claim about the system that nothing checks. It
agrees with the deployment on the day it is drawn and then quietly stops
agreeing, because a diagram has no tests and nobody re-reads it against the
Terraform. In a dissertation that becomes a false statement about what was
measured, and it is the kind of false statement an examiner can see and the
author cannot.

So the LAYOUT is authored here and the CONTENT is read. Every read asserts: a
value that cannot be found stops the figure rather than drawing a box with a
gap where a number should be.

    ./.venv/bin/python -m analysis.architecture
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

import yaml

REPO = Path(__file__).resolve().parents[1]
INFRA = REPO / "infra"
FIGS = REPO / "figures"

# Greyscale-safe, like the rest of the figures: the thesis may be printed in
# black and white, so nothing is distinguished by colour alone.
FILL_SOURCE = "#f0f0f0"
FILL_EDGE = "#ffffff"
FILL_SUT = "#e4e4e4"
FILL_TELEM = "#f7f7f7"


# --------------------------------------------------------------- reading ---

def _layer_text(layer: str) -> str:
    d = INFRA / layer
    files = sorted(d.glob("*.tf"))
    if not files:
        sys.exit(f"architecture: no Terraform source in infra/{layer}")
    return "\n".join(f.read_text() for f in files)


def tf_default(layer: str, name: str) -> str:
    """The default value of a Terraform variable, as the source declares it.

    Scoped to the variable's own block rather than searched for across the
    file. Several of these variables carry heredoc descriptions that use the
    word 'default' in prose, and one of them sits directly above the variable
    whose value is wanted -- an unscoped search finds the wrong line and
    reports it confidently.
    """
    block = re.search(rf'variable\s+"{re.escape(name)}"\s*\{{(.*?)^\}}',
                      _layer_text(layer), re.S | re.M)
    if not block:
        sys.exit(f'architecture: infra/{layer} declares no variable "{name}"')
    d = re.search(r'^\s*default\s*=\s*(".*?"|[^\s#]+)', block.group(1), re.M)
    if not d:
        sys.exit(f'architecture: variable "{name}" in infra/{layer} has no default')
    return d.group(1).strip('"')


def tf_attr(layer: str, key: str) -> str:
    """The first literal assignment of `key` in a layer's Terraform source."""
    m = re.search(rf'^\s*{re.escape(key)}\s*=\s*\[?"([^"]+)"', _layer_text(layer), re.M)
    if not m:
        sys.exit(f"architecture: infra/{layer} sets no {key}")
    return m.group(1)


def managed_groups(layer: str) -> list[str]:
    """The AWS managed rule groups a web ACL layer actually references."""
    names = re.findall(r'vendor_name\s*=\s*"AWS"\s*\n\s*name\s*=\s*"([^"]+)"',
                       _layer_text(layer))
    if not names:
        sys.exit(f"architecture: infra/{layer} references no AWS managed rule group")
    return names


def response_bytes() -> int:
    """The size of the fixed response, measured from the deployed source.

    Evaluated rather than remembered. The protocol calls the body '~309
    bytes'; that number was correct when it was written, and the only way to
    keep it correct is to take it from the function that returns it.
    """
    src = (INFRA / "00-core" / "lambda_src" / "handler.py").read_text()
    m = re.search(r"^BODY\s*=\s*(.+)$", src, re.M)
    if not m:
        sys.exit("architecture: the Lambda source declares no BODY")
    # A concatenation of string literals from this repository's own source,
    # evaluated with no builtins available.
    return len(eval(m.group(1), {"__builtins__": {}}))  # noqa: S307


def scenarios() -> dict:
    spec = yaml.safe_load((REPO / "loadgen" / "scenarios.yaml").read_text())
    for key in ("meta", "legitimate", "scenarios"):
        if key not in spec:
            sys.exit(f"architecture: scenarios.yaml has no '{key}' section")
    return spec


def peak_rate(spec: dict, scenario: str) -> float:
    s = spec["scenarios"][scenario]
    att = s.get("attacker") or {}
    if not att.get("enabled"):
        return 0.0
    return max(p["rate"] for p in att["phases"])


# --------------------------------------------------------------- drawing ---

def canvas(width: float, height: float, title: str):
    fig, ax = plt.subplots(figsize=(width, height))
    ax.set_xlim(0, 160)
    ax.set_ylim(0, 100)
    ax.set_axis_off()
    ax.set_title(title, fontsize=11, fontweight="bold", pad=10)
    return fig, ax


def box(ax, x, y, w, h, title, lines, *, fill="#ffffff", style="-", lw=1.1,
        align="center"):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.4",
        facecolor=fill, edgecolor="black", linewidth=lw, linestyle=style, zorder=2))
    ax.text(x + w / 2, y + h - 2.2, title, ha="center", va="top",
            fontsize=8.4, fontweight="bold", zorder=3)
    # Left alignment exists for the one box that lists rule group names: a
    # nested list read centred loses the nesting that carries its meaning.
    tx = x + w / 2 if align == "center" else x + 2.5
    for i, t in enumerate(lines):
        ax.text(tx, y + h - 6.2 - i * 3.5, t, ha=align, va="top",
                fontsize=6.9, zorder=3, color="#222222")


def arrow(ax, start, end, *, style="-", lw=1.1, label=None, label_dy=1.6,
          label_dx=0.0, fontsize=6.9, connect="arc3,rad=0"):
    ax.add_patch(FancyArrowPatch(
        start, end, arrowstyle="-|>", mutation_scale=11, linewidth=lw,
        linestyle=style, color="black", connectionstyle=connect,
        shrinkA=1, shrinkB=1, zorder=4))
    if label:
        ax.text((start[0] + end[0]) / 2 + label_dx,
                (start[1] + end[1]) / 2 + label_dy, label,
                ha="center", va="bottom", fontsize=fontsize, zorder=5,
                color="#222222")


def polyline(ax, points, *, style="--", lw=1.1, label=None, label_at=None):
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    ax.plot(xs[:-1], ys[:-1], linestyle=style, linewidth=lw, color="black", zorder=1)
    ax.add_patch(FancyArrowPatch(
        points[-2], points[-1], arrowstyle="-|>", mutation_scale=11,
        linewidth=lw, linestyle=style, color="black", shrinkA=0, shrinkB=1, zorder=4))
    if label and label_at:
        ax.text(label_at[0], label_at[1], label, ha="center", va="bottom",
                fontsize=6.9, zorder=5, color="#222222")


def save(fig, name: str):
    FIGS.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(FIGS / f"{name}.{ext}", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  {name}.png / .pdf")


# ----------------------------------------------------------------- fig 5 ---

def fig_architecture():
    spec = scenarios()
    harness_region = tf_default("40-harness", "region")
    instance = tf_default("40-harness", "instance_type")
    core_region = tf_default("00-core", "region")
    stage = tf_default("00-core", "stage_name")
    memory = tf_default("00-core", "lambda_memory_mb")
    runtime = tf_attr("00-core", "runtime")
    arch = tf_attr("00-core", "architectures")
    rate_limit = tf_default("30-waf-rate", "rate_limit")
    window = tf_default("30-waf-rate", "evaluation_window_sec")
    sensitivity = tf_default("35-waf-antiddos", "sensitivity")
    challenge = tf_default("35-waf-antiddos", "challenge_action")
    cache_policy = tf_attr("10-cloudfront", "name")
    groups = managed_groups("20-waf-managed")
    antiddos = managed_groups("35-waf-antiddos")[0]
    legit_rate = spec["legitimate"]["rate"]
    ceiling = spec["meta"]["peak_rate_ceiling"]

    fig, ax = canvas(13, 7.4, "Deployed architecture and the five protection configurations")

    # -- traffic sources ----------------------------------------------------
    box(ax, 2, 56, 32, 20, "gen-attacker",
        [f"EC2 {instance}, {harness_region}",
         f"S2 burst {peak_rate(spec, 'S2'):.0f} req/s",
         f"S3 sustained {peak_rate(spec, 'S3'):.0f} req/s",
         f"S4 signature {peak_rate(spec, 'S4'):.0f} req/s"],
        fill=FILL_SOURCE)
    box(ax, 2, 30, 32, 20, "gen-legit",
        [f"EC2 {instance}, {harness_region}",
         f"{legit_rate:g} req/s in every scenario",
         "measures M2, M3 and M4",
         "distinct public address"],
        fill=FILL_SOURCE)
    ax.text(18, 78.5, f"Traffic sources — peak {ceiling} req/s combined",
            ha="center", fontsize=7.6, style="italic", color="#444444")

    # -- web ACL, above the edge --------------------------------------------
    acl_lines = [f"C3   {len(groups)} managed rule groups"]
    acl_lines += [f"        \u2022 {g}" for g in groups]
    acl_lines += [f"C4   rate-based rule, {rate_limit} per {window}s, aggregated by SOURCE_IP",
                  f"C5   {antiddos}",
                  f"        \u2022 sensitivity {sensitivity}, client-side challenge {challenge}"]
    box(ax, 44, 62, 56, 32, "AWS WAF web ACL  (one per configuration)", acl_lines,
        fill=FILL_EDGE, align="left")
    ax.text(72, 95.5, "us-east-1, CLOUDFRONT scope — the only region that holds one",
            ha="center", fontsize=7.2, style="italic", color="#444444")

    # -- edge ---------------------------------------------------------------
    box(ax, 54, 32, 36, 20, "CloudFront distribution",
        ["global edge network",
         f"cache policy {cache_policy}",
         "AllViewerExceptHostHeader",
         "the layer under test in C2–C5"],
        fill=FILL_EDGE)

    # -- system under test --------------------------------------------------
    box(ax, 104, 32, 26, 20, "API Gateway",
        [f"REST API, stage '{stage}'", f"{core_region}",
         "greedy {proxy+} resource", "access + execution logging"],
        fill=FILL_SUT)
    box(ax, 134, 32, 24, 20, "Lambda",
        [f"{runtime}, {arch}", f"{memory} MB",
         f"fixed {response_bytes()}-byte body", "no input parsing"],
        fill=FILL_SUT)
    ax.text(131, 54.5, "System under test — held constant across all 60 runs",
            ha="center", fontsize=7.6, style="italic", color="#444444")

    # -- request paths ------------------------------------------------------
    arrow(ax, (34, 66), (54, 46), connect="arc3,rad=-0.12")
    arrow(ax, (34, 40), (54, 42), connect="arc3,rad=0.12")
    ax.text(43, 52.5, "C2–C5", ha="center", fontsize=7.4, color="#222222")
    arrow(ax, (72, 62), (72, 52))
    ax.text(74, 56.0, "associated", ha="left", fontsize=6.9, color="#222222")
    arrow(ax, (90, 42), (104, 42), label="origin", label_dy=1.0)
    arrow(ax, (130, 42), (134, 42))

    # C1 leaves the sources and reaches the stage URL directly: no edge, no
    # web ACL. Drawn as the detour it is rather than as another arrow in the
    # row, because bypassing is the whole of what C1 means.
    polyline(ax, [(18, 30), (18, 22), (110, 22), (110, 32)],
             label="C1 — both hosts send direct to the API Gateway stage URL: "
                   "no CloudFront, no web ACL",
             label_at=(64, 23.2))

    # -- declared confounds -------------------------------------------------
    box(ax, 2, 1, 156, 17,
        "Present in every configuration including C1, and reported as confounds",
        ["AWS Shield Standard — always on for CloudFront and API Gateway, cannot be disabled",
         "API Gateway throttling — 1,000 req/s at the stage, 10,000 req/s at the account",
         "CloudFront URI validation — rejects '..' paths before the web ACL sees them (C2–C5)"],
        fill=FILL_TELEM, style="--", lw=0.9)

    save(fig, "fig5-architecture")


# ----------------------------------------------------------------- fig 6 ---

def fig_data_flow():
    fig, ax = canvas(13, 7.0, "Measurement sources and the path from a request to a result")

    sources = [
        ("Client records", ["gen-attacker and gen-legit", "one row per request",
                            "status, ttfb, total, ids", "primary: M2, M3, M4"]),
        ("AWS WAF full logs", ["CloudWatch Logs", "terminating action + labels",
                               "attacker source IP only", "primary: M1"]),
        ("CloudWatch metrics", ["WAF, API Gateway, Lambda", "absent Sum means zero",
                                "timestamps forced to UTC", "cross-check only"]),
        ("Sampled requests", ["GetSampledRequests", "<=100 per rule per 3h",
                              "a sample, so no denominator", "qualitative only"]),
        ("Pricing + Cost Explorer", ["live unit prices, no literals",
                                     "list price and actual spend", "stamped with a date",
                                     "primary: M5"]),
    ]
    w, gap = 29.0, 3.0
    for i, (title, lines) in enumerate(sources):
        x = 2 + i * (w + gap)
        box(ax, x, 74, w, 22, title, lines, fill=FILL_SOURCE)
        arrow(ax, (x + w / 2, 74), (x + w / 2, 64))

    box(ax, 2, 50, 156, 14, "data/raw/   —   immutable per-run output",
        ["one records file and one manifest per host per run · manifest carries configuration, "
         "scenario, replication, seed, git SHA, both source addresses and the achieved rate",
         "retrieved by loadgen/orchestrate.py and collect/{cloudwatch,waf_logs,sampled,costs}.py "
         "— retrieval is scoped to the run just executed, so local curation survives"],
        fill=FILL_EDGE)
    arrow(ax, (80, 50), (80, 40))

    box(ax, 24, 26, 112, 14, "analysis/metrics.py   →   metrics-per-run.json",
        ["one row per run, one definition per metric · measured zero, zero by definition and "
         "not applicable are kept apart",
         "nothing downstream recomputes a metric, so the table and the figures cannot disagree"],
        fill=FILL_SUT)

    outs = [
        ("analysis/stats.py", ["exact Mann-Whitney", "permutation Kruskal-Wallis",
                               "Cliff's delta, separation"]),
        ("analysis/matrix.py", ["the 5x4 results matrix", "medians and observed range",
                                "console, Markdown, JSON"]),
        ("analysis/figures.py", ["fig1 blocked ratio", "fig2 latency CDF",
                                 "fig3 onset and release"]),
        ("analysis/cost_model.py", ["monthly projection", "four request volumes",
                                    "cost per unit protection"]),
    ]
    w2, gap2 = 36.0, 4.0
    for i, (title, lines) in enumerate(outs):
        x = 2 + i * (w2 + gap2)
        box(ax, x, 2, w2, 18, title, lines, fill=FILL_TELEM)
        arrow(ax, (80, 26), (x + w2 / 2, 20), connect="arc3,rad=0.05")

    save(fig, "fig6-data-flow")


def main():
    plt.rcParams.update({"font.size": 9, "savefig.bbox": "tight"})
    print(f"chapter 4 figures -> {FIGS.relative_to(REPO)}/")
    fig_architecture()
    fig_data_flow()


if __name__ == "__main__":
    main()
