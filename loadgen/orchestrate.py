#!/usr/bin/env python3
"""Drive one measurement run across both generator hosts.

The attacker and the legitimate client must run on SEPARATE hosts, because AWS
WAF rate-based rules aggregate per source address. Running both from one
machine would make the attacker's blocking fall on the legitimate client too,
and M2 would read zero by construction (decision D3).

They must also measure the SAME window, or the burst would land outside the
legitimate client's observation period. Both hosts are therefore given the same
absolute start time and wait for it.

Code reaches the hosts over SSM rather than SSH: no inbound ports, no key
material to manage, and the transfer is auditable in CloudTrail.

    ./.venv/bin/python -m loadgen.orchestrate --scenario S2 --rep 1
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
REMOTE = "/opt/ddos-eval"


def tf_output(layer, key):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"could not read {key} from {layer}: {r.stderr.strip()}")
    return r.stdout.strip()


def code_bundle() -> str:
    """Tar the generator package and base64 it for inline SSM transfer.

    Small enough (tens of KB) to pass as a command parameter, which avoids
    creating an S3 bucket purely to move a few files.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted((REPO / "loadgen").glob("*.py")):
            tar.add(p, arcname=f"loadgen/{p.name}")
        tar.add(REPO / "loadgen" / "scenarios.yaml", arcname="loadgen/scenarios.yaml")
    return base64.b64encode(buf.getvalue()).decode()


def send(ssm, instance_id, commands, timeout=1200):
    r = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands, "executionTimeout": [str(timeout)]},
    )
    return r["Command"]["CommandId"]


def wait(ssm, command_id, instance_id, timeout=1800):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(2)
            continue
        if r["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            return r
        time.sleep(5)
    raise SystemExit(f"command {command_id} did not finish within {timeout}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=["S1", "S2", "S3", "S4"])
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--lead-seconds", type=int, default=90,
                    help="headroom for deployment and warm-up before the agreed start")
    a = ap.parse_args()

    session = boto3.Session(profile_name="ddos-eval")
    ssm = session.client("ssm", region_name="eu-west-1")

    hosts = {
        "attacker": tf_output("40-harness", "attacker_instance_id"),
        "legit": tf_output("40-harness", "legit_instance_id"),
    }
    ips = {
        "attacker": tf_output("40-harness", "attacker_public_ip"),
        "legit": tf_output("40-harness", "legit_public_ip"),
    }
    if ips["attacker"] == ips["legit"]:
        raise SystemExit("ABORT: both hosts report the same public address. "
                         "Per-IP aggregation would blur the two sources (D3).")

    bucket = tf_output("40-harness", "results_bucket")
    cfg = json.loads((REPO / "data" / "processed" / "active-config.json").read_text())
    print(f"=== {cfg['configuration']}-{a.scenario}-R{a.rep} ===")
    print(f"  attacker : {hosts['attacker']}  {ips['attacker']}")
    print(f"  legit    : {hosts['legit']}  {ips['legit']}")
    print(f"  endpoint : {cfg['endpoint']}")

    # --- deploy ----------------------------------------------------------
    bundle = code_bundle()
    active = json.dumps(cfg)
    deploy = [
        f"mkdir -p {REMOTE}/data/processed {REMOTE}/data/raw",
        f"cd {REMOTE}",
        f"echo '{bundle}' | base64 -d | tar xzf -",
        f"cat > data/processed/active-config.json <<'JSON'\n{active}\nJSON",
        "python3.12 -m pip install --quiet --user aiohttp pyyaml 2>/dev/null || true",
        "python3.12 -c 'import aiohttp, yaml; print(\"deps ok\")'",
    ]
    print("\n  deploying code to both hosts...")
    cmds = {role: send(ssm, iid, deploy, timeout=600) for role, iid in hosts.items()}
    for role, cid in cmds.items():
        r = wait(ssm, cid, hosts[role], timeout=900)
        ok = r["Status"] == "Success"
        print(f"    {role:<9} {r['Status']}  {r['StandardOutputContent'].strip()[-40:]}")
        if not ok:
            print(f"      stderr: {r['StandardErrorContent'][:300]}")
            raise SystemExit("deployment failed")

    # --- run, synchronised ------------------------------------------------
    start_at = time.time() + a.lead_seconds
    print(f"\n  agreed start: {time.strftime('%H:%M:%S', time.localtime(start_at))} "
          f"(in {a.lead_seconds}s)")

    dry = "--dry-run" if a.dry_run else ""
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True).stdout.strip() or "unknown"
    run_cmds = {}
    for role, iid in hosts.items():
        # The hosts have neither git nor terraform, so the values the manifest
        # needs for reproducibility are injected here, where they are known.
        cmd = [
            f"cd {REMOTE}",
            f"export DDOS_EVAL_GIT_SHA={sha}",
            f"export DDOS_EVAL_ATTACKER_PUBLIC_IP={ips['attacker']}",
            f"export DDOS_EVAL_LEGIT_PUBLIC_IP={ips['legit']}",
            f"export DDOS_EVAL_WEB_ACL_ARN='{cfg.get('web_acl_arn', '')}'",
            f"python3.12 -m loadgen.runner --scenario {a.scenario} --rep {a.rep} "
            f"--role {role} --host {role} --start-at {start_at:.0f} {dry} 2>&1",
        ]
        run_cmds[role] = send(ssm, iid, cmd, timeout=2400)

    print("  running on both hosts...")
    results = {}
    for role, cid in run_cmds.items():
        r = wait(ssm, cid, hosts[role], timeout=2400)
        results[role] = r
        print(f"\n  --- {role} ({r['Status']}) ---")
        for line in r["StandardOutputContent"].strip().splitlines():
            print(f"    {line}")
        if r["Status"] != "Success":
            print(f"    stderr: {r['StandardErrorContent'][:500]}")

    # --- retrieve via S3 ---------------------------------------------------
    # NOT inline over SSM: a command result is truncated at about 24 KB and a
    # single run produces roughly 700 KB of records. S3 also means the data
    # stops living only on an instance, which matters because an instance can
    # be replaced by an AMI update (see pinned_ami_id).
    print("\n  uploading records to S3...")
    for role, iid in hosts.items():
        cid = send(ssm, iid, [
            f"aws s3 cp {REMOTE}/data/raw/ s3://{bucket}/raw/ --recursive --region eu-west-1",
            f"rm -f {REMOTE}/data/raw/*",
        ], timeout=600)
        r = wait(ssm, cid, iid, timeout=900)
        print(f"    {role}: {r['Status']}")
        if r["Status"] != "Success":
            print(f"      {r['StandardErrorContent'][:300]}")

    print("  downloading from S3...")
    RAW = REPO / "data" / "raw"
    RAW.mkdir(parents=True, exist_ok=True)
    s3 = session.client("s3", region_name="eu-west-1")
    got = 0
    for obj in s3.list_objects_v2(Bucket=bucket, Prefix="raw/").get("Contents", []):
        name = obj["Key"].split("/")[-1]
        if not name:
            continue
        s3.download_file(bucket, obj["Key"], str(RAW / name))
        got += 1
    print(f"    {got} files -> {RAW.relative_to(REPO)}")


if __name__ == "__main__":
    main()
