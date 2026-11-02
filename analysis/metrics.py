#!/usr/bin/env python3
"""Task T048 - compute M1 to M5 for every run into one tidy dataset.

One row per run, one column per quantity, every figure traceable to the file
it came from. Everything downstream -- the statistics, the matrix, the
figures -- reads this and nothing else, so there is a single definition of
each metric rather than one per script.

The five metrics, and where each comes from:

    M1  blocked-request ratio   WAF full logs, attacker address only,
                                measurement window only
    M2  legitimate success      client records from the legitimate host
    M3  error behaviour         client records, both hosts, by status
    M4  latency percentiles     client records, legitimate host, 200s only
    M5  protection cost         AWS Pricing API list prices, by configuration

Two timings are derived here as well, because they belong to a run rather
than to a cell: block ONSET and RELEASE, measured from the attacker's own
record stream (see docs/protocol-v1.0.md).

    ./.venv/bin/python -m analysis.metrics
    ./.venv/bin/python -m analysis.metrics --csv
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RAW = REPO / "data" / "raw"
OUT = REPO / "data" / "processed"
SCEN = REPO / "loadgen" / "scenarios.yaml"


def pct(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile.

    Deliberately not an interpolating percentile: a latency percentile should
    be a value that was actually observed, so that p95 is a request that
    really took that long rather than an average of two that did not.
    """
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * q / 100))]


def load_records(run_id: str, role: str) -> tuple[dict | None, list[dict]]:
    ms = sorted(RAW.glob(f"{run_id}-{role}-*.manifest.json"))
    if not ms:
        return None, []
    m = ms[-1]
    recs = m.with_name(m.name.replace(".manifest.json", ".records.jsonl"))
    if not recs.exists():
        return json.loads(m.read_text()), []
    return (json.loads(m.read_text()),
            [json.loads(l) for l in recs.read_text().splitlines() if l])


def burst_bounds(scenario: str) -> tuple[float, float, bool] | None:
    """Start and end of the above-threshold phase, and whether a tail follows.

    Read from scenarios.yaml rather than hardcoded, so that onset and release
    stay anchored to the protocol if the protocol ever moves.

    The third value decides whether RELEASE is measurable at all. Release is
    the gap between the flood stopping and the last block, so it can only be
    observed if the attacker is still sending afterwards. S3 floods until the
    window closes, so its last block is simply its last request: computing
    release there yields about -0.2s, which is not a fast release but an
    absence of measurement.
    """
    import yaml
    spec = yaml.safe_load(SCEN.read_text())["scenarios"][scenario]
    att = spec.get("attacker") or {}
    if not att.get("enabled"):
        return None
    phases = att["phases"]
    t = 0.0
    for i, ph in enumerate(phases):
        if ph["rate"] >= 5.0:          # at or above the 100-per-60s threshold
            has_tail = any(p["rate"] > 0 for p in phases[i + 1:])
            return t, t + ph["duration_seconds"], has_tail
        t += ph["duration_seconds"]
    return None


def m1_from_waf(run_id: str) -> tuple[float | None, str]:
    for role in ("attacker", "legit"):
        for m in sorted(RAW.glob(f"{run_id}-{role}-*.manifest.json")):
            wf = m.with_name(m.name.replace(".manifest.json", ".waflogs.json"))
            if not wf.exists():
                continue
            s = json.loads(wf.read_text()).get("summary", {})
            if s.get("M1_blocked_ratio") is not None:
                return s["M1_blocked_ratio"], "WAF full logs"
    return None, ""


def cost_table() -> dict[str, float]:
    p = OUT / "cost-model.json"
    if not p.exists():
        return {}
    model = json.loads(p.read_text())["model"]["by_configuration"]
    return {k: v.get("total_monthly_usd") for k, v in model.items()}


def compute(run_id: str, costs: dict[str, float]) -> dict | None:
    lman, legit = load_records(run_id, "legit")
    aman, attacker = load_records(run_id, "attacker")
    if lman is None:
        return None

    cfg, scen = lman["configuration"], lman["scenario"]
    row: dict = {
        "run_id": run_id,
        "configuration": cfg,
        "scenario": scen,
        "replication": lman["replication"],
        "started_utc": lman["started_utc"],
        "git_sha": lman.get("git_sha"),
    }

    # --- M1 ---------------------------------------------------------------
    # C1 and C2 have no web ACL, so nothing evaluates a request and there are
    # no logs to read. M1 is zero BY DEFINITION there, not by measurement, and
    # the two cases are recorded differently so the distinction survives into
    # the results chapter.
    if not attacker:
        # S1 sends no attack traffic at all, so there is no denominator. This
        # is not a missing measurement; the quantity does not exist for this
        # cell, and reporting it as 0.0 would assert that nothing was blocked
        # out of something.
        row["M1_blocked_ratio"], row["M1_source"] = None, "not applicable (no attacker traffic)"
    elif cfg in ("C1", "C2"):
        row["M1_blocked_ratio"], row["M1_source"] = 0.0, "no web ACL (zero by definition)"
    else:
        m1, src = m1_from_waf(run_id)
        if m1 is None and attacker:
            blocked = sum(1 for r in attacker if r["status"] == 403)
            m1, src = blocked / len(attacker), "client-observed 403 (fallback)"
        row["M1_blocked_ratio"], row["M1_source"] = m1, src or "unavailable"

    # --- M2 ---------------------------------------------------------------
    ok = sum(1 for r in legit if r["status"] == 200)
    row["M2_success_ratio"] = ok / len(legit) if legit else None

    # --- M3 ---------------------------------------------------------------
    def bucket(recs, prefix):
        out = {f"{prefix}_2xx": 0, f"{prefix}_403": 0, f"{prefix}_429": 0,
               f"{prefix}_4xx_other": 0, f"{prefix}_5xx": 0, f"{prefix}_error": 0}
        for r in recs:
            s = r["status"]
            if s == 200:
                out[f"{prefix}_2xx"] += 1
            elif s == 403:
                out[f"{prefix}_403"] += 1
            elif s == 429:
                out[f"{prefix}_429"] += 1
            elif isinstance(s, int) and 400 <= s < 500:
                out[f"{prefix}_4xx_other"] += 1
            elif isinstance(s, int) and 500 <= s < 600:
                out[f"{prefix}_5xx"] += 1
            else:
                out[f"{prefix}_error"] += 1
        return out

    row.update(bucket(legit, "legit"))
    row.update(bucket(attacker, "attacker"))

    # --- M4 ---------------------------------------------------------------
    # Legitimate traffic only, successful requests only. A blocked request's
    # latency measures how fast the edge says no, which is not what M4 is for.
    lat = [r["latency_ms"] for r in legit if r["status"] == 200]
    for q in (50, 95, 99):
        v = pct(lat, q)
        row[f"M4_p{q}_ms"] = round(v, 2) if v is not None else None
    row["M4_mean_ms"] = round(statistics.mean(lat), 2) if lat else None
    row["M4_n"] = len(lat)

    # --- M5 ---------------------------------------------------------------
    # A configuration-level constant rather than a per-run measurement: the
    # cost of the protection, not the cost of this ten-minute run. Carried on
    # every row so the matrix can report all five metrics from one table.
    row["M5_monthly_usd"] = costs.get(cfg)

    # --- onset and release ------------------------------------------------
    bounds = burst_bounds(scen)
    row["onset_s"] = row["release_s"] = None
    if bounds and attacker:
        b_start, b_end, has_tail = bounds
        blocked_t = [r["t_mono_ms"] / 1000.0 for r in attacker if r["status"] == 403]
        if blocked_t:
            row["onset_s"] = round(min(blocked_t) - b_start, 1)
            if has_tail:
                row["release_s"] = round(max(blocked_t) - b_end, 1)

    row["legit_requests"] = len(legit)
    row["attacker_requests"] = len(attacker)
    row["rate_drift_pct"] = lman.get("legit_rate_drift_pct")
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", action="store_true", help="also write a CSV")
    a = ap.parse_args()

    costs = cost_table()
    run_ids = sorted({m.name.split("-legit-")[0]
                      for m in RAW.glob("*-legit-*.manifest.json")})
    rows = [r for r in (compute(rid, costs) for rid in run_ids) if r]
    if not rows:
        raise SystemExit("no runs found in data/raw")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "metrics-per-run.json").write_text(json.dumps(rows, indent=2))

    if a.csv:
        cols = list(rows[0].keys())
        with (OUT / "metrics-per-run.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)

    missing = [r["run_id"] for r in rows if r["M1_blocked_ratio"] is None]
    print(f"{len(rows)} runs -> metrics-per-run.json"
          + (", metrics-per-run.csv" if a.csv else ""))
    print(f"  configurations : {sorted({r['configuration'] for r in rows})}")
    print(f"  scenarios      : {sorted({r['scenario'] for r in rows})}")
    print(f"  M1 unavailable : {missing or 'none'}")
    onset = [r['onset_s'] for r in rows if r['onset_s'] is not None]
    print(f"  onset measured : {len(onset)} runs")


if __name__ == "__main__":
    main()
