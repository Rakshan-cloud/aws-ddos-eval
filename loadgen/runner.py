#!/usr/bin/env python3
"""Task T030 - orchestrate one measurement run and write its manifest.

A run is: warm-up (discarded), the 600-second measurement window with both
sources active, then a cool-down long enough for AWS's rate counters to decay.

The manifest is as important as the data. Managed rule groups are versioned
and AWS updates them, so a result without its rule-group version cannot be
compared to another run or reproduced by anyone else.

    ./.venv/bin/python -m loadgen.runner --scenario S2 --rep 1
    ./.venv/bin/python -m loadgen.runner --scenario S1 --rep 1 --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import time
from pathlib import Path

import aiohttp
import yaml

from .generator import Generator

REPO = Path(__file__).resolve().parents[1]
SCENARIOS = REPO / "loadgen" / "scenarios.yaml"
RAW = REPO / "data" / "raw"


def git_sha() -> str:
    r = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def tf_output(layer: str, key: str, default=None):
    r = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}", "output", "-raw", key],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else default


def active_config() -> dict:
    p = REPO / "data" / "processed" / "active-config.json"
    if not p.exists():
        raise SystemExit("No active configuration. Run switch/apply_config.py first.")
    return json.loads(p.read_text())


def rule_group_versions(cfg: str) -> dict:
    """Capture which managed rule group versions were in force.

    Without this a Week 6 result and a Week 7 result are not comparable, because
    AWS can update a managed rule group underneath the experiment.
    """
    layer = {"C3": "20-waf-managed", "C4": "30-waf-rate", "C5": "35-waf-antiddos"}.get(cfg)
    if not layer:
        return {}
    arn = tf_output(layer, "web_acl_arn")
    if not arn:
        return {}
    try:
        import boto3
        waf = boto3.Session(profile_name="ddos-eval").client("wafv2", region_name="us-east-1")
        name = tf_output(layer, "web_acl_name")
        acl = waf.get_web_acl(Name=name, Scope="CLOUDFRONT",
                              Id=arn.rsplit("/", 1)[-1])["WebACL"]
        out = {}
        for rule in acl.get("Rules", []):
            stmt = rule.get("Statement", {}).get("ManagedRuleGroupStatement")
            if stmt:
                out[stmt["Name"]] = stmt.get("Version") or "default"
        return {"web_acl": name, "capacity_wcu": acl.get("Capacity"), "rule_groups": out}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


async def execute(scenario_id: str, rep: int, dry_run: bool, source_override: str | None):
    spec = yaml.safe_load(SCENARIOS.read_text())
    meta, legit_spec = spec["meta"], spec["legitimate"]
    scen = spec["scenarios"][scenario_id]
    cfg = active_config()

    window = meta["window_seconds"] if not dry_run else 30
    warmup = meta["warmup_seconds"] if not dry_run else 5
    ceiling = meta["peak_rate_ceiling"]

    # --- rate ceiling assertion (AWS acceptable-use position) --------------
    attacker_peak = 0.0
    if scen["attacker"]["enabled"]:
        attacker_peak = max(p["rate"] for p in scen["attacker"]["phases"])
    peak = attacker_peak + legit_spec["rate"]
    if peak > ceiling:
        raise SystemExit(
            f"ABORT: scenario {scenario_id} peaks at {peak} req/s, above the "
            f"{ceiling} req/s ceiling in scenarios.yaml. That ceiling is the "
            f"AWS acceptable-use and ethics position (docs/aws-aup-compliance.md).")

    run_id = f"{cfg['configuration']}-{scenario_id}-R{rep}"
    print(f"=== {run_id} ===")
    print(f"  endpoint   : {cfg['endpoint']}")
    print(f"  peak rate  : {peak} req/s (ceiling {ceiling})")
    print(f"  window     : {window}s, warm-up {warmup}s")

    legit = Generator(cfg["endpoint"], "legit")
    attacker = Generator(cfg["endpoint"], "attacker")

    # --- payload delivery assertion (ADR 0002, ADR 0003) -------------------
    problems = attacker.verify_delivery()
    if problems:
        for p in problems:
            print(f"  PAYLOAD REWRITE: {p}")
        raise SystemExit(
            "ABORT: at least one payload would not be transmitted as written. "
            "A rewritten payload yields a result that looks clean and is wrong.")
    from .payloads import S4_PAYLOADS
    print(f"  payloads   : {len(S4_PAYLOADS)} classes verified unaltered")

    t0_mono, t0_wall = time.monotonic(), time.time()
    conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=600)
    timeout = aiohttp.ClientTimeout(total=20)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s_legit, \
               aiohttp.ClientSession(timeout=timeout) as s_att:

        print(f"  warm-up    : {warmup}s (discarded)")
        await asyncio.gather(legit.warmup(s_legit, warmup), attacker.warmup(s_att, warmup))
        legit.records.clear()
        attacker.records.clear()

        t0_mono, t0_wall = time.monotonic(), time.time()
        print(f"  running    : {time.strftime('%H:%M:%S')}")

        tasks = [legit.run_phase(s_legit, legit_spec["rate"], window,
                                 legit_spec["payload"], "window", t0_mono, t0_wall)]
        if scen["attacker"]["enabled"]:
            async def attacker_phases():
                for i, ph in enumerate(scen["attacker"]["phases"]):
                    d = ph["duration_seconds"] if not dry_run else max(5, window // 3)
                    await attacker.run_phase(s_att, ph["rate"], d,
                                             scen["attacker"]["payload"],
                                             f"p{i}-r{ph['rate']}", t0_mono, t0_wall)
            tasks.append(attacker_phases())
        await asyncio.gather(*tasks)

    elapsed = time.monotonic() - t0_mono
    recs = legit.to_dicts() + attacker.to_dicts()

    # --- achieved rate, reported not assumed -------------------------------
    n_legit = len(legit.records)
    achieved = n_legit / elapsed if elapsed else 0
    drift = abs(achieved - legit_spec["rate"]) / legit_spec["rate"] * 100

    manifest = {
        "run_id": run_id,
        "configuration": cfg["configuration"],
        "scenario": scenario_id,
        "replication": rep,
        "dry_run": dry_run,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0_wall)),
        "elapsed_seconds": round(elapsed, 2),
        "endpoint": cfg["endpoint"],
        "web_acl_arn": cfg.get("web_acl_arn", ""),
        "git_sha": git_sha(),
        "peak_rate_req_s": peak,
        "legit_target_rate": legit_spec["rate"],
        "legit_achieved_rate": round(achieved, 3),
        "legit_rate_drift_pct": round(drift, 2),
        "counts": {
            "legit": n_legit,
            "attacker": len(attacker.records),
            "total": len(recs),
        },
        "source_ips": {
            "attacker": tf_output("40-harness", "attacker_public_ip", source_override or "local"),
            "legit": tf_output("40-harness", "legit_public_ip", source_override or "local"),
        },
        "generator_host": source_override or "local",
        "waf": rule_group_versions(cfg["configuration"]),
    }

    RAW.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(t0_wall))
    base = RAW / f"{run_id}-{stamp}"
    base.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2))
    with base.with_suffix(".records.jsonl").open("w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")

    from collections import Counter
    print(f"  done       : {len(recs)} records in {elapsed:.0f}s")
    print(f"  legit rate : {achieved:.3f} req/s target {legit_spec['rate']} "
          f"(drift {drift:.1f}%)")
    for src, g in (("legit", legit), ("attacker", attacker)):
        if g.records:
            c = Counter(r.status for r in g.records)
            print(f"  {src:<9}  : {dict(c)}")
    print(f"  written    : {base.name}.{{manifest.json,records.jsonl}}")

    if drift > 5:
        print(f"  WARNING: rate drift {drift:.1f}% exceeds 5%. The scenario as executed")
        print("           differs from the scenario as specified. Investigate before")
        print("           counting this run.")
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=["S1", "S2", "S3", "S4"])
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true",
                    help="30s window instead of 600s, for validating the pipeline")
    ap.add_argument("--host", default=None, help="label for the generator host")
    a = ap.parse_args()
    asyncio.run(execute(a.scenario, a.rep, a.dry_run, a.host))


if __name__ == "__main__":
    main()
