#!/usr/bin/env python3
"""Task T034 - pull AWS WAF full logs and join them to client records.

This is the PRIMARY source for M1 (blocked-request ratio). Sampled requests
cannot serve that purpose: AWS caps them at 100 per rule over three hours, so
they are a sample with no denominator.

The join is what makes the analysis defensible. Every client record carries the
URI it sent and the moment it sent it; every WAF record carries the URI AWS
received, the action taken, and the rule that fired. Matching them proves the
request AWS evaluated is the request the generator intended to send -- the
exact failure that ADR 0002 and ADR 0003 were written about.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
from collections import Counter
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]

LOG_GROUPS = {
    "C3": "aws-waf-logs-ddos-eval-managed",
    "C4": "aws-waf-logs-ddos-eval-rate",
    "C5": "aws-waf-logs-ddos-eval-antiddos",
}


def fetch_logs(cfg: str, start: dt.datetime, end: dt.datetime) -> list[dict]:
    group = LOG_GROUPS.get(cfg)
    if not group:
        return []  # C1 and C2 have no web ACL, so no WAF logs exist

    logs = boto3.Session(profile_name="ddos-eval").client("logs", region_name="us-east-1")
    kwargs = {
        "logGroupName": group,
        "startTime": int(start.timestamp() * 1000),
        "endTime": int(end.timestamp() * 1000),
        "limit": 10000,
    }
    out = []
    token = None
    while True:
        if token:
            kwargs["nextToken"] = token
        try:
            r = logs.filter_log_events(**kwargs)
        except logs.exceptions.ResourceNotFoundException:
            return []
        out.extend(json.loads(e["message"]) for e in r["events"])
        token = r.get("nextToken")
        if not token or len(out) >= 50000:
            break
    return out


def summarise(records: list[dict], attacker_ip: str | None = None) -> dict:
    """Reduce raw WAF records to the quantities M1 and the S4 breakdown need.

    M1 is defined as the share of FLOOD-CLASS requests blocked. Computing it
    over every evaluated request puts the legitimate client in the denominator
    and understates the ratio: the pilot measured 1,575 of 1,800 attacker
    requests blocked (87.5%), but 1,575 of 2,460 total (64.0%).

    The second number is not wrong, it answers a different question. Both are
    reported, with the attacker-only figure as M1.
    """
    by_ip = Counter()
    actions_attacker = Counter()
    actions = Counter()
    labels = Counter()
    terminating = Counter()
    by_uri = {}

    for rec in records:
        action = rec.get("action", "?")
        actions[action] += 1
        ip = rec.get("httpRequest", {}).get("clientIp", "")
        by_ip[ip] += 1
        if attacker_ip and ip == attacker_ip:
            actions_attacker[action] += 1

        uri = rec.get("httpRequest", {}).get("uri", "")
        q = rec.get("httpRequest", {}).get("args", "")
        full = f"{uri}?{q}" if q else uri
        by_uri.setdefault(full, Counter())[action] += 1

        for lb in rec.get("labels", []):
            labels[lb.get("name", "?")] += 1

        trm = rec.get("terminatingRuleId", "")
        if trm and trm != "Default_Action":
            terminating[trm] += 1
        for grp in rec.get("ruleGroupList", []):
            t = (grp.get("terminatingRule") or {}).get("ruleId")
            if t:
                terminating[t] += 1

    evaluated = sum(actions.values())
    blocked = actions.get("BLOCK", 0)
    att_eval = sum(actions_attacker.values())
    att_blocked = actions_attacker.get("BLOCK", 0)

    return {
        "evaluated": evaluated,
        "actions": dict(actions),
        "blocked_ratio_all_traffic": round(blocked / evaluated, 4) if evaluated else None,
        "attacker_ip": attacker_ip,
        "attacker_evaluated": att_eval,
        "attacker_actions": dict(actions_attacker),
        "M1_blocked_ratio": round(att_blocked / att_eval, 4) if att_eval else None,
        "by_client_ip": dict(by_ip.most_common()),
        "terminating_rules": dict(terminating.most_common()),
        "labels": dict(labels.most_common()),
        "by_uri": {u: dict(c) for u, c in sorted(by_uri.items())},
    }


def join_to_client(waf: list[dict], client_path: Path) -> dict:
    """Match WAF records to client records by URI.

    Request ids cannot be used: AWS WAF logs do not carry the API Gateway
    request id, and a blocked request never reaches API Gateway at all. URI is
    the field both sides share, and it is also the field the harness defects
    corrupted -- so matching on it is exactly the check that matters.
    """
    client = [json.loads(l) for l in client_path.read_text().splitlines() if l]
    client_uris = Counter(r["path"] for r in client)
    waf_uris = Counter()
    for rec in waf:
        uri = rec.get("httpRequest", {}).get("uri", "")
        q = rec.get("httpRequest", {}).get("args", "")
        waf_uris[f"{uri}?{q}" if q else uri] += 1

    only_client = {u: n for u, n in client_uris.items() if u not in waf_uris}
    only_waf = {u: n for u, n in waf_uris.items() if u not in client_uris}

    return {
        "client_records": len(client),
        "waf_records": len(waf),
        "distinct_uris_client": len(client_uris),
        "distinct_uris_waf": len(waf_uris),
        "uris_only_in_client": only_client,
        "uris_only_in_waf": only_waf,
        "uri_match": not only_client and not only_waf,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--pad", type=int, default=180)
    a = ap.parse_args()

    mpath = Path(a.manifest)
    manifest = json.loads(mpath.read_text())
    cfg = manifest["configuration"]

    start = dt.datetime.strptime(manifest["started_utc"], "%Y-%m-%dT%H:%M:%SZ")
    start = start.replace(tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(seconds=manifest["elapsed_seconds"])

    waf = fetch_logs(cfg, start - dt.timedelta(seconds=a.pad),
                     end + dt.timedelta(seconds=a.pad))

    print(f"{manifest['run_id']}  configuration {cfg}")
    if not waf:
        print("  no WAF logs -- expected for C1 and C2, which have no web ACL")
        summary, join = {"evaluated": 0, "note": "no web ACL in this configuration"}, {}
    else:
        attacker_ip = manifest.get("source_ips", {}).get("attacker")
        summary = summarise(waf, attacker_ip)
        client_path = mpath.with_name(mpath.name.replace(".manifest.json", ".records.jsonl"))
        join = join_to_client(waf, client_path) if client_path.exists() else {}

        print(f"  evaluated     : {summary['evaluated']}  {summary['actions']}")
        print(f"  by client ip  : {summary['by_client_ip']}")
        print(f"  attacker ip   : {summary['attacker_ip']}")
        print(f"  attacker      : {summary['attacker_evaluated']}  {summary['attacker_actions']}")
        print(f"  M1 (attacker) : {summary['M1_blocked_ratio']}")
        print(f"  all traffic   : {summary['blocked_ratio_all_traffic']}  (different question)")
        if summary["terminating_rules"]:
            print("  rules fired   :")
            for r, n in list(summary["terminating_rules"].items())[:8]:
                print(f"      {n:>5}  {r}")
        if summary["labels"]:
            print(f"  labels        : {len(summary['labels'])} distinct")
            for lb, n in list(summary["labels"].items())[:8]:
                print(f"      {n:>5}  {lb}")
        if join:
            print(f"  join          : {join['waf_records']} WAF vs "
                  f"{join['client_records']} client records")
            print(f"  URI match     : {'OK - every URI appears on both sides' if join['uri_match'] else 'MISMATCH'}")
            for label, d in (("only in client", join["uris_only_in_client"]),
                             ("only in WAF", join["uris_only_in_waf"])):
                if d:
                    print(f"    {label}: {d}")

    out = mpath.with_name(mpath.name.replace(".manifest.json", ".waflogs.json"))
    out.write_text(json.dumps({"run_id": manifest["run_id"], "configuration": cfg,
                               "summary": summary, "join": join}, indent=2))
    print(f"\nwritten to {out.resolve().relative_to(REPO)}")


if __name__ == "__main__":
    main()
