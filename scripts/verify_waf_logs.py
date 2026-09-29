#!/usr/bin/env python3
"""Task T023 verification - are WAF full logs actually arriving?

M1 (blocked-request ratio) is computed from these logs, not from sampled
requests, which are capped at 100 per rule over 3 hours and have no
denominator. If logging is silently not working, M1 has no source at all --
so this is checked now rather than discovered in Week 8.

Also confirms the `labels` field is populated, which is what lets the analysis
report WHICH rule fired for each S4 payload class.
"""
import json
import sys
import time
from collections import Counter
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
LOG_GROUPS = {
    "C3 managed rules": "aws-waf-logs-ddos-eval-managed",
    "C4 rate-based": "aws-waf-logs-ddos-eval-rate",
}

s = boto3.Session(profile_name="ddos-eval")
logs = s.client("logs", region_name="us-east-1")
since = int((time.time() - 3600) * 1000)

for label, group in LOG_GROUPS.items():
    print(f"\n{label}  ({group})")
    print("-" * 74)
    try:
        streams = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime",
            descending=True, limit=5)["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        print("  log group does not exist")
        continue

    if not streams:
        print("  no log streams - nothing has been logged yet")
        continue

    events = []
    for st in streams:
        r = logs.get_log_events(
            logGroupName=group, logStreamName=st["logStreamName"],
            startTime=since, limit=500, startFromHead=False)
        events.extend(r["events"])

    if not events:
        print("  streams exist but no events in the last hour")
        continue

    actions = Counter()
    labels = Counter()
    rules = Counter()
    for e in events:
        rec = json.loads(e["message"])
        actions[rec.get("action", "?")] += 1
        for lb in rec.get("labels", []):
            labels[lb.get("name", "?")] += 1
        trm = rec.get("terminatingRuleId", "")
        if trm and trm != "Default_Action":
            rules[trm] += 1
        for m in rec.get("ruleGroupList", []):
            t = (m.get("terminatingRule") or {}).get("ruleId")
            if t:
                rules[t] += 1

    print(f"  {len(events)} records in the last hour")
    print(f"  actions      : {dict(actions)}")
    if rules:
        print("  rules that terminated a request:")
        for r, n in rules.most_common(10):
            print(f"      {n:>4}  {r}")
    if labels:
        print(f"  labels present: {len(labels)} distinct")
        for lb, n in labels.most_common(8):
            print(f"      {n:>4}  {lb}")
    else:
        print("  NO LABELS - the per-rule S4 breakdown would not be possible")
