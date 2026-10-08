"""Environment configuration, loaded from .env with working defaults.

WHAT BELONGS HERE, AND WHAT DELIBERATELY DOES NOT
-------------------------------------------------

This file holds settings that differ between *people and accounts* — the AWS
profile name, the region, the resource prefix. Someone cloning this repository
changes these and nothing else.

Three categories are deliberately kept OUT, because putting them here would
damage the study rather than help it:

1. EXPERIMENT PARAMETERS stay in Terraform variables.
   The rate limit, evaluation window, Lambda memory and instance type are
   independent variables of the experiment. They are declared in the .tf files
   with their rationale beside them, under version control, so a result can be
   traced to the exact settings that produced it. Moving them into a gitignored
   .env would mean the numbers in the dissertation depend on values nobody
   reading the repository can see.

2. RESOURCE IDENTIFIERS are read live from Terraform outputs.
   Distribution ids, web ACL ARNs and endpoint URLs change on every rebuild.
   Caching them in a file guarantees they eventually go stale and a collector
   silently queries a resource that no longer exists — which, as Week 5 showed,
   returns an empty series rather than an error.

3. CREDENTIALS never appear in this repository at all.
   They live in ~/.aws/credentials under a named profile. This file records
   only which profile to use.

So .env answers "whose account and where", and Terraform answers "what was the
experiment". That separation is what makes the artefact reproducible.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader.

    Deliberately not python-dotenv: one fewer dependency for anyone
    reproducing the work, and the format needed here is trivial. Values
    already present in the environment win, so a one-off override like
    AWS_PROFILE=other still works without editing the file.
    """
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(REPO / ".env")


# --- whose account, and where ----------------------------------------------

AWS_PROFILE = os.environ.get("AWS_PROFILE", "ddos-eval")

# Regional resources: Lambda, API Gateway, EC2, their CloudWatch metrics.
AWS_REGION = os.environ.get("AWS_REGION", "eu-west-1")

# NOT a choice. AWS requires CLOUDFRONT-scope web ACLs, their logs and
# CloudFront's own metrics to live in us-east-1, whatever region the rest of
# the stack uses. Overridable only so the constant is not scattered as a
# literal across ten files.
AWS_GLOBAL_REGION = os.environ.get("AWS_GLOBAL_REGION", "us-east-1")

# Prefix on every resource name. Change it to run a second, isolated copy of
# the whole study in the same account without collisions.
NAME_PREFIX = os.environ.get("NAME_PREFIX", "ddos-eval")

# Cost guardrail, used by scripts/setup_budget.py.
BUDGET_AMOUNT_USD = float(os.environ.get("BUDGET_AMOUNT_USD", "50"))
BUDGET_EMAIL = os.environ.get("BUDGET_EMAIL", "")


# --- derived names, so they are defined once -------------------------------

LAMBDA_FUNCTION = f"{NAME_PREFIX}-target"
API_NAME = f"{NAME_PREFIX}-api"
API_STAGE = os.environ.get("API_STAGE", "exp")

WEB_ACL_NAMES = {
    "C3": f"{NAME_PREFIX}-managed",
    "C4": f"{NAME_PREFIX}-rate",
    "C5": f"{NAME_PREFIX}-antiddos",
}

WAF_LOG_GROUPS = {cfg: f"aws-waf-logs-{name}" for cfg, name in WEB_ACL_NAMES.items()}

# Terraform layer that owns each configuration's web ACL.
LAYER_FOR_CONFIG = {
    "C3": "20-waf-managed",
    "C4": "30-waf-rate",
    "C5": "35-waf-antiddos",
}


def session():
    """A boto3 session on the configured profile.

    Every script goes through this rather than constructing its own, so
    changing profile is a one-line edit in .env instead of fifteen edits
    across the codebase.
    """
    import boto3
    return boto3.Session(profile_name=AWS_PROFILE)


def summary() -> str:
    return (f"profile={AWS_PROFILE}  region={AWS_REGION}  "
            f"global={AWS_GLOBAL_REGION}  prefix={NAME_PREFIX}")


if __name__ == "__main__":
    print(summary())
    print(f"  lambda    : {LAMBDA_FUNCTION}")
    print(f"  api       : {API_NAME} stage {API_STAGE}")
    print(f"  web ACLs  : {WEB_ACL_NAMES}")
    print(f"  budget    : ${BUDGET_AMOUNT_USD} -> {BUDGET_EMAIL or '(not set)'}")
