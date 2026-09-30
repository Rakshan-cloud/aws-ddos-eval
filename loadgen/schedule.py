#!/usr/bin/env python3
"""Task T031 - generate the randomised run order for the whole experiment.

5 configurations x 4 scenarios x 3 replications = 60 runs.

Two competing constraints:

  RANDOMISE, because running every C1 cell on Monday and every C4 cell on
  Friday would confound the configuration with time of day, AWS edge load and
  anything else that varies across a week.

  BLOCK BY CONFIGURATION, because switching configuration means redeploying a
  CloudFront distribution, and C5 in particular costs $20/month prorated
  hourly, so it must be applied once, tested, and destroyed.

The resolution is a RANDOMISED BLOCK design: configuration order is shuffled,
and within each configuration the 12 runs are shuffled. This removes ordering
bias between scenarios and replications while keeping configuration switches
to five. It is a standard compromise and is stated as such in the methodology.

    ./.venv/bin/python -m loadgen.schedule --seed 20261012
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "data" / "processed" / "run-schedule.json"

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
SCENARIOS = ["S1", "S2", "S3", "S4"]
REPS = [1, 2, 3]

# Minutes. A run is a 600s window plus a 600s cool-down so AWS's rate-based
# counters decay fully before the next run starts.
RUN_MIN = 10
COOLDOWN_MIN = 10
SWITCH_MIN = 5    # CloudFront redeploy plus verification


def build(seed: int) -> dict:
    rng = random.Random(seed)

    config_order = CONFIGS[:]
    rng.shuffle(config_order)

    runs = []
    for cfg in config_order:
        cells = [(s, r) for s in SCENARIOS for r in REPS]
        rng.shuffle(cells)
        for scen, rep in cells:
            runs.append({
                "seq": len(runs) + 1,
                "run_id": f"{cfg}-{scen}-R{rep}",
                "configuration": cfg,
                "scenario": scen,
                "replication": rep,
            })

    total_min = (len(runs) * (RUN_MIN + COOLDOWN_MIN)) + (len(CONFIGS) * SWITCH_MIN)

    return {
        "seed": seed,
        "design": "randomised block: configuration order shuffled, cells shuffled within block",
        "n_runs": len(runs),
        "config_order": config_order,
        "estimated_wall_clock_hours": round(total_min / 60, 1),
        "notes": [
            "Execute in seq order. Switch configuration only at a block boundary.",
            "C5 costs $20/month prorated hourly: apply immediately before its block, "
            "destroy immediately after (risk R12).",
            "Minimum 10-minute cool-down between runs so rate-based counters decay.",
            "Re-running a cell for any reason keeps its run_id and appends a suffix, "
            "so the discarded attempt stays in the record.",
        ],
        "runs": runs,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261012,
                    help="fixed so the schedule is reproducible and citable")
    ap.add_argument("--show", type=int, default=12, help="how many runs to print")
    a = ap.parse_args()

    sched = build(a.seed)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(sched, indent=2))

    print(f"seed              : {sched['seed']}")
    print(f"runs              : {sched['n_runs']}")
    print(f"configuration order: {' -> '.join(sched['config_order'])}")
    print(f"estimated duration : {sched['estimated_wall_clock_hours']} hours\n")
    print(f"first {a.show} runs:")
    for r in sched["runs"][:a.show]:
        print(f"  {r['seq']:>3}  {r['run_id']}")
    print(f"\nwritten to {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
