#!/usr/bin/env python3
"""Find which CloudWatch dimension combinations actually return data.

The AWS WAF documentation lists WebACL, Rule and Region as the core
dimensions. Querying that combination returned zeros for a run that
demonstrably blocked 1,575 requests -- the dimension set simply does not
exist for this account.

A metric query with wrong dimensions does not error. It returns an empty
series, which zero-fills to a clean, plausible, completely wrong result. So
the collector is built against OBSERVED dimensions, verified here, rather
than against documented ones.

    ./.venv/bin/python scripts/probe_metric_dimensions.py <manifest.json>
"""
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
manifest = json.loads(Path(sys.argv[1]).read_text())

start = dt.datetime.strptime(manifest["started_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(
    tzinfo=dt.timezone.utc)
end = start + dt.timedelta(seconds=manifest["elapsed_seconds"] + 300)
start -= dt.timedelta(seconds=300)


def tf(layer, key):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


acl = tf("30-waf-rate", "web_acl_name")
dist = tf("10-cloudfront", "distribution_id")
session = boto3.Session(profile_name="ddos-eval")

CANDIDATES = [
    ("AWS/WAFV2", "BlockedRequests", "us-east-1", [{"Name": "WebACL", "Value": acl}]),
    ("AWS/WAFV2", "BlockedRequests", "us-east-1",
     [{"Name": "WebACL", "Value": acl}, {"Name": "Rule", "Value": "ALL"}]),
    ("AWS/WAFV2", "BlockedRequests", "us-east-1",
     [{"Name": "WebACL", "Value": acl}, {"Name": "Rule", "Value": "ALL"},
      {"Name": "Region", "Value": "Global"}]),
    ("AWS/WAFV2", "BlockedRequests", "us-east-1",
     [{"Name": "WebACL", "Value": acl}, {"Name": "Rule", "Value": "RateLimitPerIP"}]),
    ("AWS/WAFV2", "AllowedRequests", "us-east-1", [{"Name": "WebACL", "Value": acl}]),
    ("AWS/ApiGateway", "Count", "eu-west-1", [{"Name": "ApiName", "Value": "ddos-eval-api"}]),
    ("AWS/ApiGateway", "Count", "eu-west-1",
     [{"Name": "ApiName", "Value": "ddos-eval-api"}, {"Name": "Stage", "Value": "exp"}]),
    ("AWS/ApiGateway", "Latency", "eu-west-1",
     [{"Name": "ApiName", "Value": "ddos-eval-api"}, {"Name": "Stage", "Value": "exp"}]),
    ("AWS/Lambda", "Invocations", "eu-west-1",
     [{"Name": "FunctionName", "Value": "ddos-eval-target"}]),
    ("AWS/Lambda", "Duration", "eu-west-1",
     [{"Name": "FunctionName", "Value": "ddos-eval-target"}]),
    ("AWS/CloudFront", "Requests", "us-east-1",
     [{"Name": "DistributionId", "Value": dist}, {"Name": "Region", "Value": "Global"}]),
    ("AWS/CloudFront", "Requests", "us-east-1", [{"Name": "DistributionId", "Value": dist}]),
]

print(f"window {start.isoformat()} .. {end.isoformat()}")
print(f"web ACL {acl}   distribution {dist}\n")
print(f"  {'namespace':<18}{'metric':<18}{'dimensions':<46}{'sum'}")
print("  " + "-" * 92)

working = []
for ns, metric, region, dims in CANDIDATES:
    cw = session.client("cloudwatch", region_name=region)
    stat = "p95" if metric in ("Latency", "Duration") else "Sum"
    try:
        r = cw.get_metric_data(
            MetricDataQueries=[{
                "Id": "m", "MetricStat": {
                    "Metric": {"Namespace": ns, "MetricName": metric, "Dimensions": dims},
                    "Period": 60, "Stat": stat}}],
            StartTime=start, EndTime=end)
        vals = r["MetricDataResults"][0]["Values"]
        total = sum(vals) if stat == "Sum" else (max(vals) if vals else 0)
        label = ", ".join(f"{d['Name']}={d['Value']}" for d in dims)[:44]
        mark = "  <-- DATA" if vals else ""
        print(f"  {ns:<18}{metric:<18}{label:<46}{total:>8.0f}{mark}")
        if vals:
            working.append((ns, metric, region, dims))
    except Exception as e:  # noqa: BLE001
        print(f"  {ns:<18}{metric:<18}ERROR {type(e).__name__}")

print(f"\n{len(working)} of {len(CANDIDATES)} dimension sets returned data.")
print("A wrong dimension set returns an EMPTY series, not an error -- which")
print("zero-fills into a clean and completely wrong result.")
