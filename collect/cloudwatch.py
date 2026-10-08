#!/usr/bin/env python3
"""Task T033 - pull CloudWatch metrics for a run window.

These are the cross-check for M1 and M3, and the origin-side reference for M4.
They are NOT the primary source for any metric: AWS's own latency metric
excludes CloudFront and WAF time, which is precisely the overhead under study.

One AWS behaviour drives the whole design of this module:

    AWS WAF publishes a metric ONLY when the value is non-zero.

A minute with no blocked requests produces an ABSENT datapoint, not a zero.
Treating absence as missing data would silently drop every quiet minute out of
the denominator and inflate every ratio. So the series are reindexed onto a
complete minute-by-minute timeline with explicit zeros.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import boto3

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import config

REPO = Path(__file__).resolve().parents[1]

LAYER_FOR = {"C3": "20-waf-managed", "C4": "30-waf-rate", "C5": "35-waf-antiddos"}


def tf_output(layer: str, key: str):
    """Resolve an AWS identifier from Terraform state.

    The run manifests are written ON the generator hosts, which have neither
    Terraform nor the repository, so they cannot carry the web ACL name,
    distribution id or API name. This collector runs locally where Terraform
    state is available, so it resolves them here instead of depending on the
    manifest to have known them.
    """
    import subprocess
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def resolve_identifiers(manifest: dict) -> dict:
    cfg = manifest["configuration"]
    ids = {
        "api_name": tf_output("00-core", "rest_api_id") and config.API_NAME,
        "web_acl": None,
        "distribution_id": None,
    }
    if cfg in LAYER_FOR:
        ids["web_acl"] = tf_output(LAYER_FOR[cfg], "web_acl_name")
    if cfg != "C1":
        ids["distribution_id"] = tf_output("10-cloudfront", "distribution_id")
    return ids

# (metric_id, namespace, metric_name, stat) -- dimensions are filled per run.
SPECS = [
    ("waf_allowed", "AWS/WAFV2", "AllowedRequests", "Sum"),
    ("waf_blocked", "AWS/WAFV2", "BlockedRequests", "Sum"),
    ("waf_counted", "AWS/WAFV2", "CountedRequests", "Sum"),
    ("apigw_count", "AWS/ApiGateway", "Count", "Sum"),
    ("apigw_4xx", "AWS/ApiGateway", "4XXError", "Sum"),
    ("apigw_5xx", "AWS/ApiGateway", "5XXError", "Sum"),
    ("apigw_latency_p95", "AWS/ApiGateway", "Latency", "p95"),
    ("apigw_integ_p95", "AWS/ApiGateway", "IntegrationLatency", "p95"),
    ("lambda_duration_p95", "AWS/Lambda", "Duration", "p95"),
    ("lambda_invocations", "AWS/Lambda", "Invocations", "Sum"),
    ("lambda_errors", "AWS/Lambda", "Errors", "Sum"),
    ("lambda_throttles", "AWS/Lambda", "Throttles", "Sum"),
    ("cf_requests", "AWS/CloudFront", "Requests", "Sum"),
    ("cf_error_rate", "AWS/CloudFront", "TotalErrorRate", "Average"),
]


def dimensions_for(ns: str, manifest: dict) -> list[dict] | None:
    """Dimensions differ per namespace, and some only exist for some configs."""
    waf_name = manifest.get("_ids", {}).get("web_acl")
    if ns == "AWS/WAFV2":
        if not waf_name:
            return None  # C1 and C2 have no web ACL, so no WAF metrics exist
        # VERIFIED, not documented. The developer guide lists Region as a core
        # dimension, but including it returns an EMPTY series for a run that
        # demonstrably blocked 1,575 requests. WebACL + Rule=ALL is what this
        # account actually publishes. See scripts/probe_metric_dimensions.py.
        return [{"Name": "WebACL", "Value": waf_name},
                {"Name": "Rule", "Value": "ALL"}]
    if ns == "AWS/ApiGateway":
        return [{"Name": "ApiName", "Value": manifest["_ids"].get("api_name") or config.API_NAME},
                {"Name": "Stage", "Value": config.API_STAGE}]
    if ns == "AWS/Lambda":
        return [{"Name": "FunctionName", "Value": config.LAMBDA_FUNCTION}]
    if ns == "AWS/CloudFront":
        dist = manifest["_ids"].get("distribution_id")
        if not dist:
            return None
        # CloudFront is the opposite of WAF: here Region=Global IS required,
        # and omitting it returns an empty series. Verified the same way.
        return [{"Name": "DistributionId", "Value": dist},
                {"Name": "Region", "Value": "Global"}]
    return None


def fetch(manifest: dict, pad_seconds: int = 180) -> dict:
    """Pull every metric for the run window, padded either side.

    Padding matters for scenario S2: rate limiting engages tens of seconds
    after the burst starts and releases a minute or more after it stops, so a
    window clipped exactly to the run would cut off the release tail that is
    itself a finding.
    """
    start = dt.datetime.strptime(manifest["started_utc"], "%Y-%m-%dT%H:%M:%SZ")
    start = start.replace(tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(seconds=manifest["elapsed_seconds"])
    q_start = start - dt.timedelta(seconds=pad_seconds)
    q_end = end + dt.timedelta(seconds=pad_seconds)

    manifest = {**manifest, "_ids": resolve_identifiers(manifest)}
    session = config.session()
    # WAF and CloudFront metrics for a CLOUDFRONT-scope ACL live in us-east-1.
    regional = session.client("cloudwatch", region_name=config.AWS_REGION)
    global_cw = session.client("cloudwatch", region_name=config.AWS_GLOBAL_REGION)

    queries = {"eu-west-1": [], "us-east-1": []}
    for mid, ns, name, stat in SPECS:
        dims = dimensions_for(ns, manifest)
        if dims is None:
            continue
        region = "us-east-1" if ns in ("AWS/WAFV2", "AWS/CloudFront") else "eu-west-1"
        queries[region].append({
            "Id": mid,
            "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": name, "Dimensions": dims},
                "Period": 60,
                "Stat": stat,
            },
            "ReturnData": True,
        })

    series = {}
    for region, qs in queries.items():
        if not qs:
            continue
        client = global_cw if region == "us-east-1" else regional
        resp = client.get_metric_data(
            MetricDataQueries=qs, StartTime=q_start, EndTime=q_end,
            ScanBy="TimestampAscending")
        for r in resp["MetricDataResults"]:
            # NORMALISE TO UTC BEFORE KEYING.
            #
            # boto3 returns CloudWatch timestamps in the LOCAL timezone
            # (tzlocal()), not UTC. Keying on the raw isoformat produces
            # '2026-10-05T12:24:00+05:30' while the minute index holds
            # '2026-10-05T06:54:00+00:00'. The strings never match, every
            # lookup falls through to the zero-fill default, and a metric
            # that genuinely summed to 1,575 reads as 0.
            #
            # No error, no warning -- just a clean, plausible, wrong number.
            series[r["Id"]] = {
                t.astimezone(dt.timezone.utc).isoformat(): v
                for t, v in zip(r["Timestamps"], r["Values"])
            }

    # --- reindex onto a complete minute timeline --------------------------
    minutes = []
    t = q_start.replace(second=0, microsecond=0)
    while t <= q_end:
        minutes.append(t.isoformat())
        t += dt.timedelta(minutes=1)

    # Sum metrics: absent means zero (AWS omits zero-valued datapoints).
    # Percentile and average metrics: absent means no requests in that minute,
    # which is genuinely unknown rather than zero, so they stay null.
    sum_metrics = {mid for mid, _ns, _n, stat in SPECS if stat == "Sum"}

    filled = {}
    for mid, _ns, _name, _stat in SPECS:
        if mid not in series:
            continue
        raw = series[mid]
        filled[mid] = [
            raw.get(m, 0.0 if mid in sum_metrics else None) for m in minutes
        ]

    return {
        "run_id": manifest["run_id"],
        "resolved_identifiers": manifest["_ids"],
        "window_utc": {"start": start.isoformat(), "end": end.isoformat()},
        "query_window_utc": {"start": q_start.isoformat(), "end": q_end.isoformat(),
                             "pad_seconds": pad_seconds},
        "minutes": minutes,
        "series": filled,
        "zero_filled": sorted(sum_metrics & set(filled)),
        "note": ("Sum metrics are zero-filled because AWS WAF publishes a datapoint "
                 "only when the value is non-zero. Percentile metrics are left null "
                 "when absent, since 'no requests' is not the same as 'zero latency'."),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", help="path to a run manifest json")
    ap.add_argument("--pad", type=int, default=180)
    a = ap.parse_args()

    mpath = Path(a.manifest)
    manifest = json.loads(mpath.read_text())
    data = fetch(manifest, a.pad)

    out = mpath.with_name(mpath.name.replace(".manifest.json", ".cloudwatch.json"))
    out.write_text(json.dumps(data, indent=2))

    print(f"{data['run_id']}  {len(data['minutes'])} minutes")
    print(f"  identifiers: {data['resolved_identifiers']}")
    for mid, vals in data["series"].items():
        present = sum(1 for v in vals if v is not None)
        total = sum(v for v in vals if v) if mid in data["zero_filled"] else None
        extra = f"  sum={total:.0f}" if total is not None else ""
        print(f"  {mid:<22} {present:>3}/{len(vals)} datapoints{extra}")
    print(f"\nwritten to {out.resolve().relative_to(REPO)}")


if __name__ == "__main__":
    main()
