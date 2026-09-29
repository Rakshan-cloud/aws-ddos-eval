#!/usr/bin/env python3
"""Task T024 - move the deployment between configurations C1 to C5.

Each configuration is a different combination of endpoint and attached web
ACL. Switching means updating the CloudFront distribution, waiting for AWS to
finish deploying it, and then VERIFYING what is actually live rather than
trusting that the apply worked.

    ./.venv/bin/python switch/apply_config.py C3
    ./.venv/bin/python switch/apply_config.py --show

Configurations
    C1  API Gateway direct, no CloudFront, no WAF
    C2  CloudFront, no web ACL
    C3  CloudFront + managed rule groups        (content-based blocking)
    C4  CloudFront + rate-based rule            (rate-based blocking)
    C5  CloudFront + anti-DDoS rule group       ($20/month - see R12)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("AWS_PROFILE", "ddos-eval")

# Terraform runs as a subprocess and resolves credentials itself, so the
# profile has to be in the environment it inherits -- boto3's session does not
# reach it.
os.environ["AWS_PROFILE"] = PROFILE

# Which Terraform layer supplies the web ACL for each configuration.
ACL_LAYER = {
    "C1": None,
    "C2": None,
    "C3": "20-waf-managed",
    "C4": "30-waf-rate",
    "C5": "35-waf-antiddos",
}

COSTLY = {"C5"}  # layers that must not be left deployed - see risk R12


def tf(layer, *args, capture=True):
    cmd = ["terraform", f"-chdir={REPO}/infra/{layer}", *args]
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if r.returncode != 0:
        sys.exit(f"terraform {' '.join(args)} failed in {layer}:\n{r.stderr or r.stdout}")
    return r.stdout.strip() if capture else ""


def tf_output(layer, key, default=None):
    cmd = ["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        if default is not None:
            return default
        sys.exit(f"could not read output '{key}' from {layer}: {r.stderr.strip()}")
    return r.stdout.strip()


def layer_deployed(layer):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "state", "list"],
                       capture_output=True, text=True)
    return r.returncode == 0 and bool(r.stdout.strip())


def wait_deployed(session, dist_id, timeout=900):
    """Block until CloudFront reports the distribution Deployed.

    A configuration switch is not in effect until this returns. Running a
    measurement against a still-deploying distribution would sample a mix of
    the old and new configuration at different edges.
    """
    cf = session.client("cloudfront")
    start = time.time()
    last = None
    while time.time() - start < timeout:
        d = cf.get_distribution(Id=dist_id)["Distribution"]
        status = d["Status"]
        if status != last:
            print(f"    distribution {status} ({time.time() - start:.0f}s)")
            last = status
        if status == "Deployed":
            return d
        time.sleep(15)
    sys.exit(f"distribution {dist_id} did not reach Deployed within {timeout}s")


def verify(session, dist, expect_acl, label):
    """Confirm what is live matches what was asked for."""
    live_acl = dist["DistributionConfig"].get("WebACLId", "")
    ok = live_acl == expect_acl
    print(f"    web ACL live : {live_acl or '(none)'}")
    print(f"    expected     : {expect_acl or '(none)'}")
    if not ok:
        sys.exit(f"VERIFY FAILED for {label}: distribution has '{live_acl}', expected '{expect_acl}'")

    # Caching disabled is a controlled variable. Assert it every switch rather
    # than trusting it was set once - a cached response would silently turn a
    # latency measurement into a measurement of the cache.
    behavior = dist["DistributionConfig"]["DefaultCacheBehavior"]
    cf = session.client("cloudfront")
    policy = cf.get_cache_policy(Id=behavior["CachePolicyId"])["CachePolicy"]
    pname = policy["CachePolicyConfig"]["Name"]
    print(f"    cache policy : {pname}")
    if "CachingDisabled" not in pname:
        sys.exit(f"VERIFY FAILED: cache policy is '{pname}', expected Managed-CachingDisabled")
    print("    [OK] configuration verified live")


def show(session):
    print("Current deployment\n" + "-" * 62)
    for layer in ("00-core", "10-cloudfront", "20-waf-managed", "30-waf-rate", "35-waf-antiddos"):
        state = "deployed" if layer_deployed(layer) else "not deployed"
        flag = "   <-- COSTS $20/month while deployed" if layer == "35-waf-antiddos" and state == "deployed" else ""
        print(f"  {layer:<18} {state}{flag}")
    if layer_deployed("10-cloudfront"):
        print(f"\n  active configuration : {tf_output('10-cloudfront', 'config_label', '?')}")
        print(f"  cloudfront endpoint  : https://{tf_output('10-cloudfront', 'domain_name', '?')}")
    if layer_deployed("00-core"):
        print(f"  api gateway endpoint : {tf_output('00-core', 'api_invoke_url', '?')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("config", nargs="?", choices=list(ACL_LAYER), help="configuration to apply")
    ap.add_argument("--show", action="store_true", help="report what is currently deployed")
    a = ap.parse_args()

    session = boto3.Session(profile_name=PROFILE)

    if a.show or not a.config:
        show(session)
        return

    cfg = a.config
    print(f"==> switching to {cfg}\n")

    # C1 bypasses CloudFront entirely: traffic goes straight to API Gateway.
    # The distribution is left as it is rather than destroyed, because
    # rebuilding it takes minutes and its presence does not affect C1 traffic.
    if cfg == "C1":
        endpoint = tf_output("00-core", "api_invoke_url")
        print(f"    endpoint     : {endpoint}")
        print("    CloudFront and WAF are bypassed, not removed.")
        print("    NOTE: API Gateway throttling and Shield Standard remain active")
        print("          in C1 and are recorded as confounds (task T017).")
        write_state(cfg, endpoint, "")
        return

    layer = ACL_LAYER[cfg]
    acl_arn = ""
    if layer:
        if not layer_deployed(layer):
            print(f"    {layer} not deployed - applying it first")
            if cfg in COSTLY:
                print("    !! this layer costs $20/month prorated hourly - destroy it")
                print("       as soon as the C5 runs finish (risk R12)")
            tf(layer, "init", "-input=false")
            tf(layer, "apply", "-input=false", "-auto-approve")
        acl_arn = tf_output(layer, "web_acl_arn")

    print(f"    applying distribution update...")
    tf("10-cloudfront", "apply", "-input=false", "-auto-approve",
       f"-var=web_acl_arn={acl_arn}", f"-var=config_label={cfg}")

    dist_id = tf_output("10-cloudfront", "distribution_id")
    dist = wait_deployed(session, dist_id)
    verify(session, dist, acl_arn, cfg)

    endpoint = f"https://{tf_output('10-cloudfront', 'domain_name')}"
    print(f"    endpoint     : {endpoint}")
    write_state(cfg, endpoint, acl_arn)


def write_state(cfg, endpoint, acl_arn):
    """Record the active configuration so the runner can stamp run manifests."""
    p = REPO / "data" / "processed" / "active-config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "configuration": cfg,
        "endpoint": endpoint,
        "web_acl_arn": acl_arn,
        "switched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2))
    print(f"    recorded     : {p.relative_to(REPO)}")


if __name__ == "__main__":
    main()
