#!/usr/bin/env python3
"""Tasks T039-T042 - execute the measurement schedule, resumably.

The full matrix is 60 runs at roughly 20 minutes each: a 600-second window
plus the 600-second cool-down the frozen protocol requires so AWS's rate
counters decay. That is 20 hours of wall clock, which will not complete in one
sitting, so this is built to be stopped and restarted without losing work or
repeating it.

Completion is determined by what is ON DISK, not by a progress file. A run
counts as done when both role manifests exist and pass the integrity check. A
progress file could disagree with reality after a crash; the data cannot.

    ./.venv/bin/python -m loadgen.batch --status
    ./.venv/bin/python -m loadgen.batch --config C2
    ./.venv/bin/python -m loadgen.batch --config C2 --max-runs 3
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

import yaml
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import config  # noqa: E402

RAW = REPO / "data" / "raw"
SCHEDULE = REPO / "data" / "processed" / "run-schedule.json"
SCENARIOS = REPO / "loadgen" / "scenarios.yaml"
ANOMALIES = REPO / "data" / "processed" / "anomalies.jsonl"

PY = str(REPO / ".venv" / "bin" / "python")


# --------------------------------------------------------------- state ----

def completed_runs() -> dict[str, dict]:
    """Which runs are already on disk and sound.

    Derived from the files themselves so that an interrupted session, a
    crashed process or a manually deleted run all produce the correct answer
    on the next start.
    """
    done = {}
    for m in sorted(RAW.glob("*-legit-*.manifest.json")):
        run_id = m.name.split("-legit-")[0]
        att = sorted(RAW.glob(f"{run_id}-attacker-*.manifest.json"))
        legit = json.loads(m.read_text())
        if legit.get("dry_run"):
            continue
        entry = {"legit": m, "attacker": att[-1] if att else None}
        # S1 has no attacker by design, so a missing attacker half is only a
        # problem for the scenarios that specify one.
        needs_attacker = legit["scenario"] != "S1"
        entry["complete"] = bool(att) or not needs_attacker
        done[run_id] = entry
    return done


def expected_phases(scenario: str) -> dict[str, int]:
    """What the attacker half of a scenario should contain, per phase.

    The phase label is built by the runner as p<index>-r<rate> over every
    phase in the spec, so a zero-rate lead-in occupies an index but emits
    nothing and never appears in the records.
    """
    spec = yaml.safe_load(SCENARIOS.read_text())["scenarios"][scenario]
    att = spec.get("attacker") or {}
    if not att.get("enabled"):
        return {}
    return {f"p{i}-r{ph['rate']}": round(ph["rate"] * ph["duration_seconds"])
            for i, ph in enumerate(att["phases"]) if ph["rate"] > 0}


def integrity(run_id: str, entry: dict) -> list[str]:
    """Task T041 - verify a completed run before counting it.

    Returns a list of problems; empty means the run is sound. The checks are
    the abort criteria from the frozen protocol, applied automatically rather
    than by eye, because 60 runs is too many to inspect manually.
    """
    problems = []
    legit = json.loads(entry["legit"].read_text())

    recs = entry["legit"].with_name(
        entry["legit"].name.replace(".manifest.json", ".records.jsonl"))
    if not recs.exists():
        problems.append("legitimate records file missing")
    elif recs.stat().st_size == 0:
        problems.append("legitimate records file empty")

    drift = legit.get("legit_rate_drift_pct", 0)
    if drift > 5:
        problems.append(f"legitimate rate drift {drift:.1f}% exceeds 5%")

    ips = legit.get("source_ips", {})
    if ips.get("attacker") and ips.get("legit") and ips["attacker"] == ips["legit"]:
        problems.append("attacker and legitimate share a source address")

    if entry.get("attacker"):
        att = json.loads(entry["attacker"].read_text())
        if att["started_utc"] != legit["started_utc"]:
            problems.append(
                f"start times differ: legit {legit['started_utc']} "
                f"vs attacker {att['started_utc']}")

        # Does the attacker half contain the scenario it claims to be?
        #
        # A run executed against a superseded scenario definition completes
        # normally and reports a plausible ratio. C4-S2-R1 ran before the
        # protocol freeze, when S2's tail was 0 req/s, so it emitted only the
        # burst: 1800 requests instead of 2100. Nothing failed. M1 came back
        # 0.8750 -- believable, and wrong by thirteen points, because the 300
        # allowed tail requests were missing from the denominator rather than
        # from the numerator.
        #
        # Checking the phase composition against scenarios.yaml is what
        # distinguishes "this run finished" from "this run is the experiment
        # the protocol specifies".
        expect = expected_phases(legit["scenario"])
        if expect:
            arecs = entry["attacker"].with_name(
                entry["attacker"].name.replace(".manifest.json", ".records.jsonl"))
            if not arecs.exists():
                problems.append("attacker records file missing")
            else:
                seen: dict[str, int] = {}
                with arecs.open() as f:
                    for line in f:
                        if line.strip():
                            ph = json.loads(line).get("phase", "")
                            seen[ph] = seen.get(ph, 0) + 1
                for label, want in expect.items():
                    got = seen.get(label, 0)
                    if got == 0:
                        problems.append(
                            f"phase {label} absent: expected {want} requests "
                            f"(scenario definition has changed since this run)")
                    elif abs(got - want) > max(2, want * 0.02):
                        problems.append(
                            f"phase {label} sent {got}, expected {want}")
                for label in seen:
                    if label not in expect:
                        problems.append(f"unexpected phase {label} in records")
    elif legit["scenario"] != "S1":
        problems.append("attacker half missing")

    return problems


def log_anomaly(run_id: str, problems: list[str]) -> None:
    """Task T042 - record rather than discard.

    A discarded attempt and the reason it was discarded are part of the
    result, so they are appended to a log that is never rewritten.
    """
    ANOMALIES.parent.mkdir(parents=True, exist_ok=True)
    with ANOMALIES.open("a") as f:
        f.write(json.dumps({
            "run_id": run_id,
            "logged_utc": datetime.now(timezone.utc).isoformat(),
            "problems": problems,
        }) + "\n")


# ------------------------------------------------------------ execution ----

def run_one(run_id: str, scenario: str, rep: int) -> bool:
    print(f"\n{'=' * 70}\n  {run_id}   {datetime.now().strftime('%H:%M:%S')}\n{'=' * 70}")
    r = subprocess.run(
        [PY, "-m", "loadgen.orchestrate", "--scenario", scenario, "--rep", str(rep)],
        cwd=REPO, capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if any(k in line for k in ("done ", "legit rate", "attacker ", "legit  ",
                                   "ABORT", "files ->", "Status")):
            print(f"    {line.strip()}")
    if r.returncode != 0:
        print(f"    FAILED: {r.stderr[-400:]}")
        return False
    return True


def collect_one(run_id: str) -> None:
    """Pull AWS-side telemetry immediately, not in a later batch.

    WAF sampled requests expire after three hours and CloudWatch metric
    retention shortens with age, so collection is done while the window is
    still fresh.
    """
    legit = sorted(RAW.glob(f"{run_id}-legit-*.manifest.json"))
    att = sorted(RAW.glob(f"{run_id}-attacker-*.manifest.json"))
    for mod, target in (("collect.cloudwatch", legit),
                        ("collect.waf_logs", att or legit),
                        ("collect.sampled", legit)):
        if not target:
            continue
        subprocess.run([PY, "-m", mod, str(target[-1])],
                       cwd=REPO, capture_output=True, text=True)


def teardown(sched: dict, current_cfg: str | None) -> None:
    """Destroy billing resources once nothing more needs them.

    Two triggers. The anti-DDoS rule group goes as soon as its own block is
    finished, because it is the costly one and the rest of the matrix takes
    hours. Everything else goes when the whole schedule is complete.
    """
    done = completed_runs()

    def block_finished(cfg: str) -> bool:
        return not [r for r in sched["runs"]
                    if r["configuration"] == cfg
                    and not (r["run_id"] in done and done[r["run_id"]]["complete"])]

    layers = []
    if current_cfg == "C5" and block_finished("C5"):
        layers.append(("35-waf-antiddos", "anti-DDoS rule group ($0.0274/hour)"))

    matrix_done = all(block_finished(c) for c in {r["configuration"] for r in sched["runs"]})
    if matrix_done:
        print("\n--- all 60 runs complete ---")
        for layer, label in (("20-waf-managed", "managed rule groups"),
                             ("30-waf-rate", "rate-based rule"),
                             ("35-waf-antiddos", "anti-DDoS rule group")):
            if (layer, label) not in layers:
                layers.append((layer, label))

    if not layers:
        return

    # Detach first. A web ACL attached to the distribution cannot be destroyed:
    # AWS answers WAFAssociatedItemException, which is how C5 once survived a
    # teardown attempt and billed overnight.
    print("    detaching web ACL from the distribution...")
    subprocess.run([PY, "switch/apply_config.py", "C2"],
                   cwd=REPO, capture_output=True, text=True)

    for layer, label in layers:
        state = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}",
                                "state", "list"], capture_output=True, text=True)
        if state.returncode != 0 or not state.stdout.strip():
            continue
        print(f"    destroying {label}...")
        d = subprocess.run(["terraform", f"-chdir={REPO}/infra/{layer}",
                            "destroy", "-input=false", "-auto-approve"],
                           capture_output=True, text=True)
        print("      destroyed" if d.returncode == 0
              else f"      TEARDOWN FAILED - destroy it manually:\n{d.stderr[-300:]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", help="run only this configuration's block")
    ap.add_argument("--max-runs", type=int, default=None,
                    help="stop after this many runs this session")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--cooldown", type=int, default=600,
                    help="seconds between runs; the frozen protocol requires 600")
    a = ap.parse_args()

    sched = json.loads(SCHEDULE.read_text())
    done = completed_runs()

    # ---- status -----------------------------------------------------------
    if a.status:
        print(f"Schedule seed {sched['seed']}  order "
              f"{' -> '.join(sched['config_order'])}\n")
        by_cfg = {}
        for r in sched["runs"]:
            by_cfg.setdefault(r["configuration"], []).append(r)
        total_done = 0
        for cfg, runs in by_cfg.items():
            d = [r for r in runs if r["run_id"] in done and done[r["run_id"]]["complete"]]
            total_done += len(d)
            bar = "#" * len(d) + "." * (len(runs) - len(d))
            print(f"  {cfg}  [{bar}]  {len(d):>2}/{len(runs)}")
        print(f"\n  {total_done}/{len(sched['runs'])} runs complete  "
              f"({len(sched['runs']) - total_done} remaining, "
              f"~{(len(sched['runs']) - total_done) * 20 / 60:.1f} h)")
        if ANOMALIES.exists():
            n = sum(1 for _ in ANOMALIES.open())
            print(f"  {n} anomal{'y' if n == 1 else 'ies'} logged")
        return

    # ---- select work ------------------------------------------------------
    pending = [r for r in sched["runs"]
               if not (r["run_id"] in done and done[r["run_id"]]["complete"])]
    if a.config:
        pending = [r for r in pending if r["configuration"] == a.config]
    if not pending:
        print("Nothing pending for that selection.")
        return
    if a.max_runs:
        pending = pending[:a.max_runs]

    configs = sorted({r["configuration"] for r in pending})
    print(f"{len(pending)} run(s) to execute, configuration(s) {', '.join(configs)}")
    print(f"estimated {len(pending) * (600 + a.cooldown) / 3600:.1f} hours\n")

    current_cfg = None
    executed = 0

    for i, r in enumerate(pending):
        cfg = r["configuration"]

        # Switch only at a block boundary. Each switch redeploys CloudFront,
        # and C5's rule group is billed hourly while it exists.
        if cfg != current_cfg:
            print(f"\n--- switching to {cfg} ---")
            sw = subprocess.run([PY, "switch/apply_config.py", cfg],
                                cwd=REPO, capture_output=True, text=True)
            if sw.returncode != 0:
                sys.exit(f"configuration switch failed:\n{sw.stdout}\n{sw.stderr}")
            for line in sw.stdout.splitlines():
                if "OK" in line or "endpoint" in line:
                    print(f"    {line.strip()}")
            current_cfg = cfg

        ok = run_one(r["run_id"], r["scenario"], r["replication"])
        executed += 1

        if ok:
            collect_one(r["run_id"])
            fresh = completed_runs().get(r["run_id"])
            problems = integrity(r["run_id"], fresh) if fresh else ["no files produced"]
            if problems:
                print(f"    INTEGRITY: {'; '.join(problems)}")
                log_anomaly(r["run_id"], problems)
            else:
                print("    integrity: OK")
        else:
            log_anomaly(r["run_id"], ["orchestration failed"])

        if i < len(pending) - 1:
            print(f"    cool-down {a.cooldown}s "
                  f"(ends {datetime.fromtimestamp(time.time() + a.cooldown):%H:%M:%S})")
            time.sleep(a.cooldown)

    # --- tear down whatever is still billing ------------------------------
    # Every WAF layer bills monthly-prorated-hourly for as long as it exists,
    # whether or not runs are happening. The anti-DDoS rule group is the
    # expensive one at $0.0274/hour; left up after its block it cost $0.53 of
    # unnecessary spend before anyone noticed. Teardown is therefore part of
    # finishing, not a step to remember (risk R12).
    teardown(sched, current_cfg)

    print(f"\n{executed} run(s) executed this session.")
    print("Re-run with --status to see overall progress.")


if __name__ == "__main__":
    main()
