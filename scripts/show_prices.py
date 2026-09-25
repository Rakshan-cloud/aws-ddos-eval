#!/usr/bin/env python3
"""Print the WAF unit prices relevant to this study, from the Pricing API dump.

Regenerate the dump with scripts/preflight.py, then:
    ./.venv/bin/python scripts/show_prices.py
"""
import json

ROWS = json.load(open("data/processed/waf-prices.json"))


def show(title, prefix):
    print("\n" + title)
    print("-" * 88)
    for r in ROWS:
        if r["usagetype"].startswith(prefix):
            print(f"  {r['usagetype']:<34}{r['unit']:<10}${r['usd']:<10.4f} {r['description'][:54]}")


show("CloudFront scope (Global-*) - the prices that apply to C2-C5", "Global-")
show("EU Ireland (EU-*) - regional scope, for reference", "EU-")
