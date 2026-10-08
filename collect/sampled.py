#!/usr/bin/env python3
"""Task T035 - GetSampledRequests, as qualitative evidence only.

AWS returns at most 100 matched requests plus 100 default-action requests from
the previous three hours. That is a SAMPLE: it has no denominator, so it can
never produce a ratio.

It is collected because it shows what a matched request actually looked like --
the headers AWS saw, the URI AWS received, the rule that fired. That is useful
illustration for the dissertation, and a second independent confirmation that
payloads arrived intact. It is never used to compute M1.

    ./.venv/bin/python -m collect.sampled data/raw/<run>.manifest.json
"""
import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path

import boto3

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import config

REPO = Path(__file__).resolve().parents[1]
LAYER = {"C3": "20-waf-managed", "C4": "30-waf-rate", "C5": "35-waf-antiddos"}


def tf_output(layer, key):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    # The rule metric name, not the rule name. For a web ACL-wide sample use
    # the ACL's own metric name; AWS rejects "ALL" here even though it is a
    # valid CloudWatch dimension value.
    ap.add_argument("--rule", default=None,
                    help="rule metric name; defaults to the web ACL metric name")
    a = ap.parse_args()

    mpath = Path(a.manifest)
    manifest = json.loads(mpath.read_text())
    cfg = manifest["configuration"]

    if cfg not in LAYER:
        print(f"{manifest['run_id']}: configuration {cfg} has no web ACL, nothing to sample")
        return

    arn = tf_output(LAYER[cfg], "web_acl_arn")
    if not arn:
        print(f"{manifest['run_id']}: {LAYER[cfg]} not deployed")
        return

    start = dt.datetime.strptime(manifest["started_utc"], "%Y-%m-%dT%H:%M:%SZ")
    start = start.replace(tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(seconds=manifest["elapsed_seconds"] + 180)

    acl_metric = {"C3": "ddosEvalManaged", "C4": "ddosEvalRate",
                  "C5": "ddosEvalAntiDDoS"}[cfg]
    rule = a.rule or acl_metric

    waf = config.session().client("wafv2", region_name=config.AWS_GLOBAL_REGION)
    try:
        r = waf.get_sampled_requests(
            WebAclArn=arn, RuleMetricName=rule, Scope="CLOUDFRONT",
            TimeWindow={"StartTime": start, "EndTime": end}, MaxItems=100)
    except Exception as e:  # noqa: BLE001
        print(f"  could not sample: {type(e).__name__}: {e}")
        return

    samples = r.get("SampledRequests", [])
    print(f"{manifest['run_id']}  configuration {cfg}  rule metric {rule}")
    print(f"  population size AWS sampled from : {r.get('PopulationSize')}")
    print(f"  samples returned                 : {len(samples)}  (AWS caps at 100)")
    print("  NOT used for any ratio - this is a sample, it has no denominator.\n")

    rows = []
    for s in samples:
        req = s.get("Request", {})
        headers = {h["Name"].lower(): h["Value"] for h in req.get("Headers", [])}
        rows.append({
            "timestamp": s.get("Timestamp").isoformat() if s.get("Timestamp") else None,
            "action": s.get("Action"),
            "rule": s.get("RuleNameWithinRuleGroup", ""),
            "uri": req.get("URI", ""),
            "args": req.get("Args", ""),
            "method": req.get("HTTPMethod", ""),
            "client_ip": req.get("ClientIP", ""),
            "user_agent": headers.get("user-agent", "(absent)"),
            "labels": [l.get("Name") for l in s.get("Labels", [])],
        })

    for row in rows[:6]:
        ua = row["user_agent"][:24]
        print(f"  {row['action']:<7} {row['rule'][:30]:<30} {row['uri'][:26]:<26} UA={ua}")
    if len(rows) > 6:
        print(f"  ... {len(rows) - 6} more")

    out = mpath.with_name(mpath.name.replace(".manifest.json", ".sampled.json"))
    out.write_text(json.dumps({
        "run_id": manifest["run_id"], "configuration": cfg,
        "population_size": r.get("PopulationSize"),
        "sample_count": len(rows),
        "caveat": ("AWS returns at most 100 matched plus 100 default-action requests "
                   "from the previous three hours. Qualitative evidence only; M1 comes "
                   "from the full WAF logs."),
        "samples": rows,
    }, indent=2, default=str))
    print(f"\nwritten to {out.resolve().relative_to(REPO)}")


if __name__ == "__main__":
    main()
