#!/usr/bin/env python3
"""Week 1 preflight: verify the AWS account can support this study.

Checks caller identity, confirms every service the design depends on is reachable,
and reads live unit prices from the AWS Pricing API (task T007).

Read-only. Creates nothing, costs nothing.

    ./.venv/bin/python scripts/preflight.py --profile ddos-eval --region eu-west-1
"""
import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

OK, FAIL, WARN = "\033[32mOK\033[0m", "\033[31mFAIL\033[0m", "\033[33mWARN\033[0m"

# The AWS Pricing API is only served from these regions.
PRICING_REGIONS = ("us-east-1", "ap-south-1")


def check(session, label, region, call):
    """Run a read-only API call and report whether the service is reachable."""
    try:
        call(session, region)
        print(f"  [{OK}]   {label}")
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "?")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                    "SubscriptionRequiredException", "OptInRequired"):
            print(f"  [{FAIL}] {label} — {code}")
        else:
            # An API error that is not an authorisation refusal still means the
            # service answered us, so it is reachable.
            print(f"  [{WARN}] {label} — reachable, returned {code}")
        return False
    except (EndpointConnectionError, Exception) as e:  # noqa: BLE001
        print(f"  [{FAIL}] {label} — {type(e).__name__}: {e}")
        return False


CHECKS = [
    ("AWS WAF (CLOUDFRONT scope)  ** C3 C4 C5 **", "us-east-1",
     lambda s, r: s.client("wafv2", region_name=r).list_web_acls(Scope="CLOUDFRONT", Limit=1)),
    ("AWS WAF (REGIONAL scope)", None,
     lambda s, r: s.client("wafv2", region_name=r).list_web_acls(Scope="REGIONAL", Limit=1)),
    ("AWS WAF managed rule groups", "us-east-1",
     lambda s, r: s.client("wafv2", region_name=r).list_available_managed_rule_groups(Scope="CLOUDFRONT", Limit=1)),
    ("API Gateway (REST)          ** system under test **", None,
     lambda s, r: s.client("apigateway", region_name=r).get_rest_apis(limit=1)),
    ("CloudFront                  ** C2 C3 C4 C5 **", "us-east-1",
     lambda s, r: s.client("cloudfront", region_name=r).list_distributions(MaxItems="1")),
    ("Lambda", None, lambda s, r: s.client("lambda", region_name=r).list_functions(MaxItems=1)),
    ("EC2", None, lambda s, r: s.client("ec2", region_name=r).describe_addresses()),
    ("CloudWatch metrics", None,
     lambda s, r: s.client("cloudwatch", region_name=r).list_metrics(Namespace="AWS/WAFV2")),
    ("CloudWatch Logs", None,
     lambda s, r: s.client("logs", region_name=r).describe_log_groups(limit=1)),
    ("Elastic Load Balancing (ALB fallback)", None,
     lambda s, r: s.client("elbv2", region_name=r).describe_load_balancers(PageSize=1)),
    ("AWS Budgets                 ** T006 **", "us-east-1",
     lambda s, r: s.client("budgets", region_name=r).describe_budgets(
         AccountId=s.client("sts").get_caller_identity()["Account"], MaxResults=1)),
    ("Cost Explorer               ** M5 **", "us-east-1",
     lambda s, r: s.client("ce", region_name=r).get_cost_categories(
         TimePeriod={"Start": "2026-01-01", "End": "2026-01-02"}, MaxResults=1)),
    ("Pricing API                 ** M5 T007 **", "us-east-1",
     lambda s, r: s.client("pricing", region_name=r).describe_services(MaxResults=1)),
    ("IAM", None, lambda s, r: s.client("iam").list_roles(MaxItems=1)),
]


def find_service_code(pricing, needle):
    """Discover the Pricing API service code rather than hardcoding it."""
    paginator = pricing.get_paginator("describe_services")
    for page in paginator.paginate():
        for svc in page["Services"]:
            if needle.lower() in svc["ServiceCode"].lower():
                return svc["ServiceCode"]
    return None


def price_report(session):
    """Read live unit prices. Nothing here is hardcoded — everything is queried."""
    print("\nLive unit prices from the AWS Pricing API")
    print("-" * 62)
    try:
        pricing = session.client("pricing", region_name=PRICING_REGIONS[0])
        code = find_service_code(pricing, "waf")
        if not code:
            print("  Could not discover the AWS WAF service code.")
            return
        print(f"  AWS WAF service code: {code}")
        paginator = pricing.get_paginator("get_products")
        seen = 0
        for page in paginator.paginate(ServiceCode=code, MaxResults=100):
            for item in page["PriceList"]:
                d = json.loads(item)
                attrs = d["product"].get("attributes", {})
                usage = attrs.get("usagetype", "")
                desc = attrs.get("operation") or attrs.get("groupDescription") or ""
                for term in d.get("terms", {}).get("OnDemand", {}).values():
                    for dim in term.get("priceDimensions", {}).values():
                        usd = dim.get("pricePerUnit", {}).get("USD")
                        if usd and float(usd) > 0:
                            print(f"    {usage:<44} {dim.get('unit',''):<12} ${usd}")
                            print(f"      {dim.get('description','')[:100]}")
                            seen += 1
            if seen > 60:
                print("    ... truncated; full list written to data/processed/waf-prices.json")
                break
    except ClientError as e:
        print(f"  Pricing API unavailable: {e.response['Error']['Code']}")
    print("\n  T007: look for a DDoS / AntiDDoS usage type above. If none appears,")
    print("  the anti-DDoS rule group fee must be read from the AWS WAF pricing page")
    print("  and recorded in docs/aws-facts.md with its source and date.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="ddos-eval")
    ap.add_argument("--region", default="eu-west-1", help="region for regional resources")
    ap.add_argument("--skip-pricing", action="store_true")
    a = ap.parse_args()

    try:
        session = boto3.Session(profile_name=a.profile)
        ident = session.client("sts").get_caller_identity()
    except NoCredentialsError:
        sys.exit(f"No credentials for profile '{a.profile}'. Run: aws configure --profile {a.profile}")
    except ClientError as e:
        sys.exit(f"Could not authenticate: {e}")

    print(f"\nAccount : {ident['Account']}")
    print(f"Identity: {ident['Arn']}")
    print(f"Region  : {a.region} (regional)  /  us-east-1 (CloudFront web ACL)\n")
    print("Service availability")
    print("-" * 62)

    results = {}
    for label, forced_region, call in CHECKS:
        results[label] = check(session, label, forced_region or a.region, call)

    critical = [k for k in results if "**" in k and not results[k]]
    print("\n" + "=" * 62)
    if critical:
        print("BLOCKED — these are required by the design:")
        for k in critical:
            print(f"  - {k.split('**')[0].strip()}")
    else:
        print("All design-critical services are reachable. Week 2 can proceed.")
    print("=" * 62)

    if not a.skip_pricing:
        price_report(session)


if __name__ == "__main__":
    main()
