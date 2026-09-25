# scripts/

One-off operational scripts. Not part of the measurement pipeline.

| Script | Task | What it does |
|---|---|---|
| `preflight.py` | T005 / T007 | Read-only. Verifies the account can support the study, and reads live unit prices from the Pricing API. Creates nothing. |
| `setup_budget.py` | T006 | Creates the monthly AWS Budget with alerts at 50/80/100% plus a forecast alert. Idempotent. |

Run `preflight.py` **first**, and before every new phase of the project — service
availability and prices both change.

```bash
./.venv/bin/python scripts/preflight.py    --profile ddos-eval --region eu-west-1
./.venv/bin/python scripts/setup_budget.py --profile ddos-eval --amount 50 --email you@example.com
```
