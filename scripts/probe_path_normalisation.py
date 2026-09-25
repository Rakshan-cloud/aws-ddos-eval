#!/usr/bin/env python3
"""Does the HTTP client rewrite the URI path before it leaves the machine?

Scenario S4 sends path-traversal payloads intended to match the managed rule
GenericLFI_URIPATH. If the client normalises `..` segments away, AWS never sees
the payload, the WAF has nothing to match, and the result is recorded as "not
blocked" when in truth it was never tested.

That is a silent false negative, so the generator built in Week 4 must be
proven not to do it.
"""
import subprocess

import httpx

BASE = subprocess.run(
    ["terraform", "-chdir=infra/00-core", "output", "-raw", "api_invoke_url"],
    capture_output=True, text=True, check=True).stdout.strip()

PAYLOAD = "/api/../../etc/passwd"

print(f"base    : {BASE}")
print(f"payload : {PAYLOAD}\n")

# --- what httpx does by default ---------------------------------------------
u = httpx.URL(BASE + PAYLOAD)
print("1. httpx.URL(base + payload)")
print(f"   sends path : {u.path}")
print(f"   rewritten  : {u.path != '/exp' + PAYLOAD}")

# --- forcing the raw path ----------------------------------------------------
raw = ("/exp" + PAYLOAD).encode()
u2 = httpx.URL(BASE).copy_with(raw_path=raw)
print("\n2. httpx.URL(...).copy_with(raw_path=...)")
print(f"   sends path : {u2.raw_path.decode()}")
print(f"   preserved  : {u2.raw_path == raw}")

# --- and what AWS actually answers ------------------------------------------
print("\n3. Live responses")
with httpx.Client() as c:
    for label, url in (("normalised", httpx.URL(BASE + PAYLOAD)),
                       ("raw_path  ", u2)):
        r = c.get(url, timeout=15)
        print(f"   {label}  {r.status_code}  {len(r.content):>4}B")
