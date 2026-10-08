#!/usr/bin/env python3
"""Copy AWS credentials from ~/.aws/credentials into .env.

Reads the named profile and appends the keys to .env. The values are moved
machine-to-machine: they are never printed, logged, or passed on a command
line where they would land in shell history.

    ./.venv/bin/python scripts/env_from_profile.py
    ./.venv/bin/python scripts/env_from_profile.py --profile other
"""
import argparse
import configparser
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENV = REPO / ".env"

ap = argparse.ArgumentParser()
ap.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "ddos-eval"))
a = ap.parse_args()

cred_file = Path.home() / ".aws" / "credentials"
if not cred_file.exists():
    raise SystemExit(f"{cred_file} not found. Run: aws configure --profile {a.profile}")

cp = configparser.ConfigParser()
cp.read(cred_file)
if a.profile not in cp:
    raise SystemExit(f"profile [{a.profile}] not in {cred_file}")

sec = cp[a.profile]
key_id = sec.get("aws_access_key_id", "")
secret = sec.get("aws_secret_access_key", "")
token = sec.get("aws_session_token", "")
if not key_id or not secret:
    raise SystemExit(f"profile [{a.profile}] has no key pair")

text = ENV.read_text() if ENV.exists() else ""

# Replace existing entries rather than appending duplicates: _load_dotenv uses
# setdefault, so the FIRST occurrence wins and a stale duplicate above a fresh
# one would silently shadow it.
def upsert(body: str, k: str, v: str) -> str:
    line = f"{k}={v}"
    if re.search(rf"^{k}=", body, re.M):
        return re.sub(rf"^{k}=.*$", line, body, flags=re.M)
    return body.rstrip("\n") + "\n" + line + "\n"

if "# --- credentials" not in text:
    text = text.rstrip("\n") + (
        "\n\n# --- credentials ------------------------------------------------\n"
        "# Copied from ~/.aws/credentials by scripts/env_from_profile.py.\n"
        "# This file is gitignored AND blocked by the pre-commit hook.\n")

for k, v in (("AWS_ACCESS_KEY_ID", key_id),
             ("AWS_SECRET_ACCESS_KEY", secret),
             ("AWS_SESSION_TOKEN", token)):
    text = upsert(text, k, v)

ENV.write_text(text)
ENV.chmod(0o600)   # owner-only, matching ~/.aws/credentials

print(f"copied profile [{a.profile}] into {ENV.name}")
print(f"  key id : {key_id[:4]}...{key_id[-4:]}")
print(f"  secret : set ({len(secret)} chars, not shown)")
print(f"  token  : {'set' if token else 'none (long-lived key)'}")
print(f"  perms  : {oct(ENV.stat().st_mode)[-3:]}")
