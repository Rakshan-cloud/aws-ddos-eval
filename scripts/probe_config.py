#!/usr/bin/env python3
"""Task T025 - confirm a configuration behaves as the hypothesis predicts.

Sends one benign request plus all eight scenario S4 payload classes against
whatever configuration is currently live, and compares the result to what
docs/design-freeze.md predicts.

This also settles risk R13 for query-argument payloads: if the WAF BLOCKS a
payload, that is proof the payload survived the client intact and arrived at
AWS as written. A 200 is ambiguous -- it could mean "not blocked" or "never
sent properly" -- so blocks are the evidence that matters here.

    ./.venv/bin/python scripts/probe_config.py
"""
import asyncio
import json
import sys
from pathlib import Path

import aiohttp
from yarl import URL

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from loadgen.payloads import BENIGN_HEADERS, BENIGN_PATH, S4_PAYLOADS  # noqa: E402

# What docs/design-freeze.md predicts for the S4 payload classes.
EXPECTED_S4 = {
    "C1": "allow",   # no protection under study
    "C2": "allow",   # CloudFront alone does no rule-based filtering
    "C3": "block",   # signature matching - this is what managed rules are for
    "C4": "allow",   # rate rule ignores content, and S4 stays below threshold
    "C5": "?",       # genuinely unknown - the novelty-bearing cell
}


async def send(session, base, path, headers):
    h = {k: v for k, v in headers.items() if v is not None}

    # A key set to None means "omit this header entirely". Leaving it out of
    # the dict is NOT enough: aiohttp substitutes its own User-Agent, so the
    # NoUserAgent_HEADER rule never fires and the payload silently tests
    # nothing. skip_auto_headers is what actually suppresses it.
    skip = [k for k, v in headers.items() if v is None]
    if "User-Agent" not in headers:
        h.setdefault("User-Agent", "ddos-eval-probe/1.0")

    # encoded=True sends the URI path and query verbatim. Without it the client
    # rewrites `..` segments and re-encodes the query string, and the payload
    # never reaches AWS as written (ADR 0002).
    url = URL(base + path, encoded=True)
    try:
        async with session.get(url, headers=h, skip_auto_headers=skip,
                               timeout=aiohttp.ClientTimeout(total=20)) as r:
            body = await r.read()
            return r.status, len(body), r.headers.get("x-amzn-waf-action", "")
    except Exception as e:  # noqa: BLE001
        return f"ERR {type(e).__name__}", 0, ""


async def main():
    state_path = REPO / "data" / "processed" / "active-config.json"
    if not state_path.exists():
        sys.exit("No active configuration. Run switch/apply_config.py first.")
    state = json.loads(state_path.read_text())
    cfg, base = state["configuration"], state["endpoint"]

    print(f"Configuration : {cfg}")
    print(f"Endpoint      : {base}")
    print(f"Prediction    : S4 payloads should be {EXPECTED_S4[cfg].upper()}ED\n")

    results = {"configuration": cfg, "endpoint": base, "probes": []}

    async with aiohttp.ClientSession() as s:
        status, size, _ = await send(s, base, BENIGN_PATH, BENIGN_HEADERS)
        benign_ok = status == 200
        print(f"  benign request                  {status}  {size:>5}B  "
              f"{'as expected' if benign_ok else 'UNEXPECTED - should be 200'}")
        results["benign_status"] = status

        print(f"\n  {'payload':<18}{'rule':<40}{'status':<8}{'verdict'}")
        print("  " + "-" * 76)
        blocked = 0
        for label, path, headers, rule, _lbl in S4_PAYLOADS:
            status, size, _ = await send(s, base, path, headers)
            is_block = status == 403
            blocked += is_block
            if EXPECTED_S4[cfg] == "?":
                verdict = "BLOCKED" if is_block else "allowed"
            else:
                want_block = EXPECTED_S4[cfg] == "block"
                verdict = "as predicted" if is_block == want_block else "** UNEXPECTED **"
            print(f"  {label:<18}{rule:<40}{str(status):<8}{verdict}")
            results["probes"].append(
                {"label": label, "rule": rule, "status": status, "blocked": is_block})

    n = len(S4_PAYLOADS)
    print(f"\n  {blocked}/{n} payload classes blocked")
    results["blocked_count"] = blocked

    if EXPECTED_S4[cfg] == "block" and blocked > 0:
        print("\n  R13 SETTLED for the blocked classes: a block proves the payload")
        print("  reached AWS intact. The client is not rewriting them.")
    if EXPECTED_S4[cfg] == "allow" and blocked == 0:
        print("\n  Note: 0 blocked is the prediction here, but it is also what a")
        print("  broken client would produce. R13 for this configuration is only")
        print("  settled by the C3 result above.")

    out = REPO / "data" / "processed" / f"probe-{cfg}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\n  written to {out.relative_to(REPO)}")


asyncio.run(main())
