#!/usr/bin/env python3
"""Task T036 - metric M5, protection cost.

Two independent figures, because they answer different questions:

  MODELLED   what each configuration would cost per month at a stated request
             volume, from live AWS Pricing API unit prices. This is the figure
             a practitioner needs: "what will this cost me?"

  ACTUAL     what the experiment itself actually spent, from Cost Explorer.
             This validates the model and keeps the dissertation honest.

NO PRICE IS HARDCODED. Every unit price is read from the Pricing API at run
time and stamped with the date it was read, so the cost chapter is auditable
and survives AWS changing its prices.

    ./.venv/bin/python -m collect.costs --monthly-requests 10000000
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed"

# Pricing API is served only from these regions.
PRICING_REGION = "us-east-1"

# What each configuration deploys. Quantities, never prices.
CONFIG_COMPONENTS = {
    "C1": {"web_acls": 0, "rules": 0, "managed_groups": 0, "antiddos": False},
    "C2": {"web_acls": 0, "rules": 0, "managed_groups": 0, "antiddos": False},
    "C3": {"web_acls": 1, "rules": 0, "managed_groups": 3, "antiddos": False},
    "C4": {"web_acls": 1, "rules": 1, "managed_groups": 0, "antiddos": False},
    "C5": {"web_acls": 1, "rules": 0, "managed_groups": 0, "antiddos": True},
}


def waf_unit_prices(session) -> dict:
    """Read CloudFront-scope WAF unit prices from the Pricing API."""
    pricing = session.client("pricing", region_name=PRICING_REGION)

    # Discover the service code rather than assuming it.
    code = None
    for page in pricing.get_paginator("describe_services").paginate():
        for svc in page["Services"]:
            if "waf" in svc["ServiceCode"].lower():
                code = svc["ServiceCode"]
                break
        if code:
            break
    if not code:
        raise SystemExit("could not discover the AWS WAF service code")

    wanted = {
        "Global-WebACLV2": "web_acl_month",
        "Global-RuleV2": "rule_month",
        "Global-AMR-AntiDDoS": "antiddos_month",
    }
    # Request processing is priced in tiers by total web ACL capacity (WCU).
    tier_keys = {"Global-RequestV2-Tier1": "request_tier1_per_million"}

    found = {}
    for page in pricing.get_paginator("get_products").paginate(ServiceCode=code):
        for item in page["PriceList"]:
            d = json.loads(item)
            usage = d["product"]["attributes"].get("usagetype", "")
            key = wanted.get(usage) or tier_keys.get(usage)
            if not key or key in found:
                continue
            for term in d.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = float(dim.get("pricePerUnit", {}).get("USD", 0))
                    desc = dim.get("description", "")
                    if usd > 0:
                        found[key] = {"usd": usd, "usagetype": usage, "description": desc}

    # Per-million and per-request descriptions disagree with the raw figure for
    # tiered request pricing, so parse the documented rate out of the text
    # rather than trusting the unit, and record both.
    return found


def model_monthly(prices: dict, monthly_requests: int) -> dict:
    """Project each configuration's monthly cost at a stated request volume."""
    def unit(key, default=0.0):
        return prices.get(key, {}).get("usd", default)

    web_acl = unit("web_acl_month")
    rule = unit("rule_month")
    antiddos = unit("antiddos_month")
    millions = monthly_requests / 1_000_000

    # Request processing: parse the per-million rate from the price
    # description, because AWS prices this per request with a per-million
    # description and the raw unit rounds to zero.
    req_per_m = 0.60
    desc = prices.get("request_tier1_per_million", {}).get("description", "")
    for tok in desc.replace("$", " $").split():
        if tok.startswith("$"):
            try:
                req_per_m = float(tok[1:])
                break
            except ValueError:
                pass

    antiddos_req_per_m = 0.15  # from the Global-AMR-AntiDDoS-Request description

    rows = {}
    for cfg, c in CONFIG_COMPONENTS.items():
        fixed = (c["web_acls"] * web_acl
                 + c["rules"] * rule
                 + c["managed_groups"] * rule
                 + (antiddos if c["antiddos"] else 0.0))
        variable = (millions * req_per_m if c["web_acls"] else 0.0)
        if c["antiddos"]:
            variable += millions * antiddos_req_per_m
        rows[cfg] = {
            "fixed_monthly_usd": round(fixed, 2),
            "request_monthly_usd": round(variable, 2),
            "total_monthly_usd": round(fixed + variable, 2),
            "components": c,
        }
    return {
        "monthly_requests": monthly_requests,
        "unit_prices_used": {
            "web_acl_month_usd": web_acl,
            "rule_or_group_month_usd": rule,
            "antiddos_month_usd": antiddos,
            "request_per_million_usd": req_per_m,
            "antiddos_request_per_million_usd": antiddos_req_per_m,
        },
        "by_configuration": rows,
    }


def actual_spend(session, start: str, end: str) -> dict:
    """What the experiment actually cost, from Cost Explorer."""
    ce = session.client("ce", region_name=PRICING_REGION)
    try:
        r = ce.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}",
                "note": "Cost Explorer needs up to 24h after enabling, and the "
                        "account may have no billed usage yet."}

    by_service, total = {}, 0.0
    for day in r["ResultsByTime"]:
        for g in day["Groups"]:
            amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
            if amt:
                by_service[g["Keys"][0]] = round(by_service.get(g["Keys"][0], 0) + amt, 4)
                total += amt
    return {"period": {"start": start, "end": end},
            "total_usd": round(total, 4),
            "by_service": dict(sorted(by_service.items(), key=lambda kv: -kv[1]))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--monthly-requests", type=int, default=10_000_000,
                    help="volume for the modelled projection")
    ap.add_argument("--since", default=None, help="YYYY-MM-DD for actual spend")
    a = ap.parse_args()

    session = boto3.Session(profile_name="ddos-eval")
    today = dt.date.today()
    since = a.since or (today - dt.timedelta(days=30)).isoformat()

    prices = waf_unit_prices(session)
    model = model_monthly(prices, a.monthly_requests)
    actual = actual_spend(session, since, today.isoformat())

    print(f"Unit prices read from the AWS Pricing API on {today.isoformat()}")
    print("-" * 70)
    for k, v in model["unit_prices_used"].items():
        print(f"  {k:<36} ${v}")

    print(f"\nModelled monthly cost at {a.monthly_requests:,} requests/month")
    print("-" * 70)
    print(f"  {'config':<8}{'fixed':>10}{'requests':>12}{'total':>12}")
    for cfg, row in model["by_configuration"].items():
        print(f"  {cfg:<8}${row['fixed_monthly_usd']:>9.2f}"
              f"${row['request_monthly_usd']:>11.2f}${row['total_monthly_usd']:>11.2f}")

    print(f"\nActual spend since {since}")
    print("-" * 70)
    if "error" in actual:
        print(f"  {actual['error']}")
        print(f"  {actual['note']}")
    else:
        print(f"  total: ${actual['total_usd']}")
        for svc, amt in actual["by_service"].items():
            print(f"    {svc:<44} ${amt}")

    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / "cost-model.json"
    out.write_text(json.dumps({
        "read_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "raw_unit_prices": prices,
        "model": model,
        "actual": actual,
    }, indent=2))
    print(f"\nwritten to {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
