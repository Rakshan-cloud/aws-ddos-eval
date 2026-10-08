#!/usr/bin/env python3
"""Task T006 — create the AWS Budget guardrail before anything is deployed.

Creates a monthly cost budget with alerts at 50%, 80% and 100% of actual spend,
plus a forecast alert at 100%. Idempotent: re-running updates the existing budget.

    ./.venv/bin/python scripts/setup_budget.py
        (amount and email come from .env unless overridden)
"""
import argparse
import sys

import boto3
from botocore.exceptions import ClientError

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))
import config

BUDGET_NAME = f"{config.NAME_PREFIX}-monthly"


def notification(threshold, ntype="ACTUAL"):
    return {
        "NotificationType": ntype,
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": threshold,
        "ThresholdType": "PERCENTAGE",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--amount", type=float, default=config.BUDGET_AMOUNT_USD,
                    help="monthly ceiling in USD; defaults to BUDGET_AMOUNT_USD in .env")
    ap.add_argument("--email", default=config.BUDGET_EMAIL,
                    help="where alerts are sent; defaults to BUDGET_EMAIL in .env")
    a = ap.parse_args()

    if not a.email:
        sys.exit("No alert address. Set BUDGET_EMAIL in .env or pass --email.")

    session = config.session()
    account = session.client("sts").get_caller_identity()["Account"]
    budgets = session.client("budgets", region_name=config.AWS_GLOBAL_REGION)

    budget = {
        "BudgetName": BUDGET_NAME,
        "BudgetLimit": {"Amount": str(a.amount), "Unit": "USD"},
        "TimeUnit": "MONTHLY",
        "BudgetType": "COST",
    }
    subscribers = [{"SubscriptionType": "EMAIL", "Address": a.email}]
    notifications = [
        {"Notification": notification(50.0), "Subscribers": subscribers},
        {"Notification": notification(80.0), "Subscribers": subscribers},
        {"Notification": notification(100.0), "Subscribers": subscribers},
        {"Notification": notification(100.0, "FORECASTED"), "Subscribers": subscribers},
    ]

    try:
        budgets.create_budget(
            AccountId=account, Budget=budget,
            NotificationsWithSubscribers=notifications,
        )
        print(f"Created budget '{BUDGET_NAME}': ${a.amount:.2f}/month, alerts to {a.email}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "DuplicateRecordException":
            sys.exit(f"Could not create budget: {e}")
        budgets.update_budget(AccountId=account, NewBudget=budget)
        print(f"Budget '{BUDGET_NAME}' already existed — limit set to ${a.amount:.2f}")
        sync_subscribers(budgets, account, a.email)


def sync_subscribers(budgets, account, email):
    """Make `email` the only subscriber on every notification of this budget.

    update_budget does not touch notifications, so an existing budget keeps its
    old subscribers unless they are replaced explicitly.
    """
    existing = budgets.describe_notifications_for_budget(
        AccountId=account, BudgetName=BUDGET_NAME)["Notifications"]
    wanted = {"SubscriptionType": "EMAIL", "Address": email}

    for note in existing:
        subs = budgets.describe_subscribers_for_notification(
            AccountId=account, BudgetName=BUDGET_NAME, Notification=note)["Subscribers"]
        if wanted not in subs:
            budgets.create_subscriber(
                AccountId=account, BudgetName=BUDGET_NAME,
                Notification=note, Subscriber=wanted)
            print(f"  + added {email} to the "
                  f"{note['NotificationType'].lower()} {note['Threshold']:.0f}% alert")
        # Remove every other address, so alerts go only where intended.
        for sub in subs:
            if sub != wanted:
                budgets.delete_subscriber(
                    AccountId=account, BudgetName=BUDGET_NAME,
                    Notification=note, Subscriber=sub)
                print(f"  - removed {sub['Address']} from the "
                      f"{note['NotificationType'].lower()} {note['Threshold']:.0f}% alert")

    print("\nAlerts at 50%, 80% and 100% of actual spend, plus a 100% forecast alert.")
    print("Check your inbox — AWS sends a confirmation for each subscription.")
    print("\nNOTE: budget alerts notify, they do not stop spending. They are a smoke")
    print("alarm, not a sprinkler. Destroy resources when a run block finishes.")


if __name__ == "__main__":
    main()
