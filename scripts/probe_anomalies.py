#!/usr/bin/env python3
"""Investigate the two S4 payload classes that did not behave as predicted.

  lfi-path       -> 400 rather than 403. Who rejected it, and at which layer?
  no-user-agent  -> 200 rather than 403. Was the header actually omitted?
"""
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import aiohttp
from yarl import URL

REPO = Path(__file__).resolve().parents[1]


def tf_output(layer, key):
    return subprocess.run(
        ["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
        capture_output=True, text=True, check=True).stdout.strip()


APIGW = tf_output("00-core", "api_invoke_url")
CF = "https://" + tf_output("10-cloudfront", "domain_name")


async def get(session, base, path, **kw):
    try:
        async with session.get(URL(base + path, encoded=True),
                               timeout=aiohttp.ClientTimeout(total=20), **kw) as r:
            body = await r.read()
            return r.status, body[:90].decode(errors="replace").replace("\n", " ")
    except Exception as e:  # noqa: BLE001
        return f"ERR {type(e).__name__}", str(e)[:70]


async def main():
    print("ANOMALY 1 -- lfi-path returns 400\n" + "=" * 74)
    print("Which layer rejects a `..` path? Compare origin vs edge.\n")
    async with aiohttp.ClientSession() as s:
        for label, base in (("API Gateway direct (C1)", APIGW), ("CloudFront (C3)", CF)):
            for path in ("/api/../../etc/passwd", "/api/..%2f..%2fetc/passwd", "/api/items"):
                status, body = await get(s, base, path)
                print(f"  {label:<26} {path:<30} {str(status):<6} {body[:44]}")
            print()

    print("\nANOMALY 2 -- no-user-agent returns 200\n" + "=" * 74)
    print("Does the client actually omit the header, or substitute its own?\n")
    async with aiohttp.ClientSession() as s:
        # 1. dict without the key -- aiohttp adds its own default UA
        status, _ = await get(s, CF, "/api/items", headers={})
        print(f"  headers={{}}                              {status}  (aiohttp adds a default UA)")

        # 2. explicitly skip the auto-added header
        status, _ = await get(s, CF, "/api/items", headers={},
                              skip_auto_headers=["User-Agent"])
        print(f"  skip_auto_headers=['User-Agent']        {status}  <- genuinely no UA header")

        # 3. control: a UA that should trip the bad-bot rule
        status, _ = await get(s, CF, "/api/items", headers={"User-Agent": "nmap"})
        print(f"  User-Agent: nmap                        {status}  (control)")


asyncio.run(main())
