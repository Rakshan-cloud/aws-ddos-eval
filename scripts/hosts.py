#!/usr/bin/env python3
"""Start or stop the generator hosts.

These are the only hourly-billed resources in the study. They run during run
blocks and are stopped otherwise. Stopping also releases the auto-assigned
public IPv4 addresses, which are themselves billed per hour.

Because the addresses change across a stop/start cycle, the new pair is
printed on every start and must be recorded in the run manifests for that
block. The runner does this automatically by reading Terraform outputs.

    ./.venv/bin/python scripts/hosts.py status
    ./.venv/bin/python scripts/hosts.py start
    ./.venv/bin/python scripts/hosts.py stop
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]


def ids():
    out = {}
    for role in ("attacker", "legit"):
        r = subprocess.run(
            ["terraform", f"-chdir={REPO}/infra/40-harness", "output", "-raw",
             f"{role}_instance_id"], capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("Harness not deployed. Run: ./scripts/infra.sh apply 40-harness")
        out[role] = r.stdout.strip()
    return out


def describe(ec2, inst):
    r = ec2.describe_instances(InstanceIds=list(inst.values()))
    by_id = {i["InstanceId"]: i for res in r["Reservations"] for i in res["Instances"]}
    rows = []
    for role, iid in inst.items():
        i = by_id[iid]
        rows.append((role, iid, i["State"]["Name"], i.get("PublicIpAddress", "-")))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["status", "start", "stop"])
    a = ap.parse_args()

    session = boto3.Session(profile_name="ddos-eval")
    ec2 = session.client("ec2", region_name="eu-west-1")
    inst = ids()

    if a.action in ("start", "stop"):
        fn = ec2.start_instances if a.action == "start" else ec2.stop_instances
        fn(InstanceIds=list(inst.values()))
        print(f"{a.action}ing both hosts...")
        waiter = ec2.get_waiter("instance_running" if a.action == "start" else "instance_stopped")
        waiter.wait(InstanceIds=list(inst.values()))
        if a.action == "start":
            # Refresh Terraform state so the new addresses reach run manifests.
            subprocess.run(["terraform", f"-chdir={REPO}/infra/40-harness",
                            "refresh", "-input=false"], capture_output=True)
            time.sleep(2)

    print(f"\n  {'role':<10}{'instance':<22}{'state':<12}{'public ip'}")
    print("  " + "-" * 58)
    rows = describe(ec2, inst)
    for role, iid, state, ip in rows:
        print(f"  {role:<10}{iid:<22}{state:<12}{ip}")

    running = [r for r in rows if r[2] == "running"]
    if running:
        addrs = {r[3] for r in running}
        if len(running) == 2 and len(addrs) < 2:
            print("\n  WARNING: both hosts share a public address. Per-IP rate")
            print("  aggregation would blur the two sources and invalidate M2.")
        elif len(running) == 2:
            print("\n  Source addresses are distinct, as decision D3 requires.")
        print("  Billing: hourly while running. Stop them when the run block ends.")
    else:
        print("\n  Both stopped. No hourly charge.")


if __name__ == "__main__":
    main()
