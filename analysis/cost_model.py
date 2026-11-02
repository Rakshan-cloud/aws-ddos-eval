#!/usr/bin/env python3
"""Task T052 - monthly cost projection and cost-effectiveness.

Two tables.

PROJECTION      what each configuration costs per month across a range of
                request volumes. WAF's fixed charges dominate at low volume
                and its per-request charge dominates at high volume, so a
                single figure at one volume hides the crossover that decides
                which configuration is actually cheaper.

EFFECTIVENESS   cost against protection delivered, using the blocked-request
                ratios this experiment measured. This is the table the
                discussion chapter argues from.

All unit prices come from data/processed/cost-model.json, which collect/costs.py
reads live from the AWS Pricing API and stamps with a date. Nothing here is
hardcoded; this module does arithmetic on prices it is given.

    ./.venv/bin/python -m analysis.cost_model
    ./.venv/bin/python -m analysis.cost_model --markdown
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed"

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
VOLUMES = [100_000, 1_000_000, 10_000_000, 100_000_000]

LABEL = {
    "C1": "Unprotected",
    "C2": "CloudFront only",
    "C3": "CloudFront + managed rules",
    "C4": "CloudFront + rate-based rule",
    "C5": "CloudFront + anti-DDoS group",
}

# Quantities, never prices -- mirrors collect/costs.py so the two agree.
COMPONENTS = {
    "C1": {"web_acls": 0, "rules": 0, "managed_groups": 0, "antiddos": False},
    "C2": {"web_acls": 0, "rules": 0, "managed_groups": 0, "antiddos": False},
    "C3": {"web_acls": 1, "rules": 0, "managed_groups": 3, "antiddos": False},
    "C4": {"web_acls": 1, "rules": 1, "managed_groups": 0, "antiddos": False},
    "C5": {"web_acls": 1, "rules": 0, "managed_groups": 0, "antiddos": True},
}


def monthly_cost(cfg: str, requests: int, p: dict) -> dict:
    c = COMPONENTS[cfg]
    fixed = (c["web_acls"] * p["web_acl_month_usd"]
             + (c["rules"] + c["managed_groups"]) * p["rule_or_group_month_usd"]
             + (p["antiddos_month_usd"] if c["antiddos"] else 0.0))
    millions = requests / 1_000_000
    if c["web_acls"] == 0:
        per_req = 0.0                      # nothing inspects the request
    else:
        rate = p["request_per_million_usd"]
        if c["antiddos"]:
            rate += p["antiddos_request_per_million_usd"]
        per_req = millions * rate
    return {"fixed_usd": round(fixed, 4),
            "request_usd": round(per_req, 4),
            "total_usd": round(fixed + per_req, 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args()

    cm = json.loads((OUT / "cost-model.json").read_text())
    prices = cm["model"]["unit_prices_used"]
    priced_on = cm["read_at"][:10]

    runs = json.loads((OUT / "metrics-per-run.json").read_text())

    print(f"Unit prices read from the AWS Pricing API on {priced_on}")
    for k, v in prices.items():
        print(f"  {k:<36} ${v}")

    # ------------------------------------------------- projection --------
    print(f"\n{'=' * 78}\nMONTHLY COST PROJECTION\n{'=' * 78}")
    print(f"  {'config':<8}" + "".join(f"{v / 1_000_000:>14,.1f}M" for v in VOLUMES))
    print("  " + "-" * 70)
    projection: dict = {}
    for cfg in CONFIGS:
        row = {}
        line = f"  {cfg:<8}"
        for v in VOLUMES:
            c = monthly_cost(cfg, v, prices)
            row[str(v)] = c
            line += f"{'$' + format(c['total_usd'], ',.2f'):>15}"
        projection[cfg] = row
        print(line + f"   {LABEL[cfg]}")

    print("\n  Where the money goes at 100M requests/month:")
    for cfg in CONFIGS:
        c = monthly_cost(cfg, 100_000_000, prices)
        if c["total_usd"] == 0:
            continue
        share = 100 * c["request_usd"] / c["total_usd"]
        print(f"    {cfg}  fixed ${c['fixed_usd']:>6.2f}  "
              f"requests ${c['request_usd']:>7.2f}  "
              f"({share:.0f}% of cost is per-request)")

    # ---------------------------------------------- effectiveness --------
    # Cost per million ATTACK requests blocked. A configuration that blocks
    # nothing has no defined value here, and saying so plainly is the point:
    # it is not expensive per unit of protection, it delivers no units at all.
    print(f"\n{'=' * 78}\nCOST-EFFECTIVENESS, at 10M requests/month\n{'=' * 78}")
    print(f"  {'config':<8}{'$/month':>10}{'S3 flood':>12}{'S4 signature':>14}"
          f"{'$ per M blocked':>18}")
    print("  " + "-" * 70)
    effectiveness: dict = {}
    for cfg in CONFIGS:
        cost = monthly_cost(cfg, 10_000_000, prices)["total_usd"]
        def m1(scen):
            v = [r["M1_blocked_ratio"] for r in runs
                 if r["configuration"] == cfg and r["scenario"] == scen
                 and r["M1_blocked_ratio"] is not None]
            return statistics.median(v) if v else None
        s3, s4 = m1("S3"), m1("S4")
        best = max([x for x in (s3, s4) if x is not None], default=0.0)
        if cost == 0:
            per = "n/a (free)"
        elif best == 0:
            per = "undefined"
        else:
            per = f"${cost / best:,.2f}"
        effectiveness[cfg] = {"monthly_usd": cost, "M1_S3": s3, "M1_S4": s4,
                              "usd_per_million_blocked":
                                  None if (cost == 0 or best == 0) else round(cost / best, 2)}
        print(f"  {cfg:<8}{cost:>10.2f}{(f'{s3:.4f}' if s3 is not None else '-'):>12}"
              f"{(f'{s4:.4f}' if s4 is not None else '-'):>14}{per:>18}")

    print("\n  'undefined' means the configuration blocked nothing in either attack")
    print("  class, so there is no quantity of protection to divide the cost by.")

    if a.markdown:
        print("\n| Configuration | $/month | S3 flood | S4 signature |")
        print("|---|---|---|---|")
        for cfg in CONFIGS:
            e = effectiveness[cfg]
            s3 = f"{e['M1_S3']:.4f}" if e["M1_S3"] is not None else "—"
            s4 = f"{e['M1_S4']:.4f}" if e["M1_S4"] is not None else "—"
            print(f"| **{cfg}** {LABEL[cfg]} | ${e['monthly_usd']:.2f} | {s3} | {s4} |")

    (OUT / "cost-projection.json").write_text(json.dumps({
        "priced_on": priced_on,
        "unit_prices": prices,
        "projection_by_volume": projection,
        "effectiveness_at_10M": effectiveness,
        "note": ("Modelled from AWS Pricing API list prices. The experiment's own "
                 "account is credit-covered and its bill reads zero, which is why "
                 "list prices rather than actual spend are used for M5."),
    }, indent=2))
    print(f"\nwritten: data/processed/cost-projection.json")


if __name__ == "__main__":
    main()
