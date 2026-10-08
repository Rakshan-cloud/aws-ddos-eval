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


# --- credentials -----------------------------------------------------------
#
# Two supported sources, checked in this order:
#
#   1. Explicit keys in .env   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#   2. A named profile         AWS_PROFILE -> ~/.aws/credentials
#
# .env sits INSIDE the repository, so option 1 is protected only by
# .gitignore. A pre-commit hook (./scripts/install-hooks.sh) refuses any
# commit containing .env or an AWS key pattern, so that protection is
# enforced rather than merely intended. Install it once after cloning.

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_SESSION_TOKEN = os.environ.get("AWS_SESSION_TOKEN", "")

USING_EXPLICIT_KEYS = bool(AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)


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
    if USING_EXPLICIT_KEYS:
        return boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            aws_session_token=AWS_SESSION_TOKEN or None,
            region_name=AWS_REGION,
        )
    return boto3.Session(profile_name=AWS_PROFILE)


def terraform_env() -> dict:
    """Environment for Terraform subprocesses.

    Terraform resolves AWS credentials itself and never reads .env, so
    whichever source is configured has to be passed through explicitly.
    """
    env = dict(os.environ)
    if USING_EXPLICIT_KEYS:
        # Explicit keys win. A stale AWS_PROFILE left in the environment would
        # otherwise shadow them and Terraform would act on the wrong account.
        env.pop("AWS_PROFILE", None)
        env["AWS_ACCESS_KEY_ID"] = AWS_ACCESS_KEY_ID
        env["AWS_SECRET_ACCESS_KEY"] = AWS_SECRET_ACCESS_KEY
        if AWS_SESSION_TOKEN:
            env["AWS_SESSION_TOKEN"] = AWS_SESSION_TOKEN
    else:
        env["AWS_PROFILE"] = AWS_PROFILE
    env.setdefault("AWS_REGION", AWS_REGION)
    return env


def summary() -> str:
    # Never prints the secret. Four characters either side of the key id is
    # enough to confirm which credential is loaded without exposing it.
    if USING_EXPLICIT_KEYS:
        src = f"keys from .env ({AWS_ACCESS_KEY_ID[:4]}...{AWS_ACCESS_KEY_ID[-4:]})"
    else:
        src = f"profile {AWS_PROFILE}"
    return (f"credentials={src}  region={AWS_REGION}  "
            f"global={AWS_GLOBAL_REGION}  prefix={NAME_PREFIX}")


if __name__ == "__main__":
    print(summary())
    print(f"  lambda    : {LAMBDA_FUNCTION}")
    print(f"  api       : {API_NAME} stage {API_STAGE}")
    print(f"  web ACLs  : {WEB_ACL_NAMES}")
    print(f"  budget    : ${BUDGET_AMOUNT_USD} -> {BUDGET_EMAIL or '(not set)'}")
