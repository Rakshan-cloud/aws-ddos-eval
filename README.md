# aws-ddos-eval

Research artefact for the MSc dissertation *Evaluating the Effectiveness of AWS-Native DDoS
Mitigation under Controlled Application-Layer Request Floods*.

**Deekonda Rakshan (x25180754)** — MSc Cloud Computing, National College of Ireland

---

## What this measures

Five protection configurations of a small AWS web service, under four controlled
low-rate traffic scenarios, replicated three times each — **60 runs**, five metrics each.

| | Configuration |
|---|---|
| **C1** | Unprotected — API Gateway REST API, direct |
| **C2** | CloudFront only |
| **C3** | CloudFront + AWS WAF managed rule groups |
| **C4** | CloudFront + AWS WAF rate-based rule |
| **C5** | CloudFront + `AWSManagedRulesAntiDDoSRuleSet` |

| | Scenario |
|---|---|
| **S1** | Normal — steady 1 req/s legitimate only |
| **S2** | Burst — 10 req/s for 180 s, measures rate-rule onset and release |
| **S3** | Repeated-source sustained — 5 req/s for 600 s |
| **S4** | Signature-bearing — payloads matching named managed rules, held below the rate threshold |

| | Metric |
|---|---|
| **M1** | Blocked-request ratio |
| **M2** | Legitimate-traffic success rate |
| **M3** | 4xx/5xx error behaviour |
| **M4** | p95 latency, client-measured |
| **M5** | Protection cost |

**This is not a DDoS simulation.** Peak rate is 11 req/s from two non-distributed hosts
against the researcher's own resources. See [`docs/aws-aup-compliance.md`](docs/aws-aup-compliance.md).

---

## Repository layout

```
infra/00-core/          Lambda + API Gateway REST API (the system under test)
infra/10-cloudfront/    CloudFront distribution, caching disabled
infra/20-waf-managed/   CLOUDFRONT-scope web ACL, managed rule groups        → C3
infra/30-waf-rate/      CLOUDFRONT-scope web ACL, rate-based rule            → C4
infra/35-waf-antiddos/  CLOUDFRONT-scope web ACL, anti-DDoS rule group       → C5
infra/40-harness/       Two EC2 generator hosts with distinct Elastic IPs
infra/99-budget/        AWS Budget alarm and cost allocation tags

switch/                 Move between C1–C5, wait for propagation, verify
loadgen/                Traffic generator, scenario definitions, run orchestrator
collect/                CloudWatch, WAF logs, sampled requests, cost collectors
analysis/               Metric computation, statistics, results matrix, figures

data/raw/               Immutable per-run output
data/processed/         Joined and derived dataset
results/                Figures and tables for the dissertation
docs/                   Design, decisions, ethics, verified AWS facts, thesis
```

---

## Documents

| File | What it is |
|---|---|
| [`docs/design-freeze.md`](docs/design-freeze.md) | The frozen experiment specification. Read this first. |
| [`docs/aws-facts.md`](docs/aws-facts.md) | Every AWS behaviour the design relies on, with its source. |
| [`docs/adr/0001-design-decisions.md`](docs/adr/0001-design-decisions.md) | Why Terraform, why eu-west-1, why two hosts, why C5. |
| [`docs/aws-aup-compliance.md`](docs/aws-aup-compliance.md) | Why this is not a DDoS simulation. |
| [`docs/ethics-declaration-draft.md`](docs/ethics-declaration-draft.md) | Draft NCI ethics declaration. |
| [`docs/project-plan.xlsx`](docs/project-plan.xlsx) | 12-week plan, task tracker, run tracker, budget. |
| `docs/week-NN-report.md` | Weekly progress reports. |

---

## Setup

```bash
python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt
aws configure --profile ddos-eval      # never commit credentials
export AWS_PROFILE=ddos-eval
```

### Toolchain versions (verified 2026-09-22)

| Tool | Version |
|---|---|
| AWS CLI | 2.36.50 |
| Terraform | 1.16.3 |
| Python | 3.12.14 |
| boto3 | 1.43.99 |
| pandas | 3.0.6 |
| httpx | 0.28.1 |
| scipy | 1.18.1 |
| matplotlib | 3.11.2 |

---

## Ground rules for this codebase

1. **No hardcoded AWS prices.** `collect/costs.py` reads unit prices from the AWS Pricing
   API and cross-checks against Cost Explorer.
2. **No hardcoded AWS resource IDs.** Managed cache policies, rule group versions and ARNs
   are looked up at apply time, never pasted in.
3. **No AWS behaviour assumed.** If the design depends on it, it is verified and recorded
   in `docs/aws-facts.md` with a source.
4. **M1 never comes from sampled requests.** Sampled requests are capped at 100 per rule
   over three hours — a sample has no denominator. Full WAF logs are the source of truth.
5. **After the Week 5 freeze, the design does not change.** A change invalidates every
   completed run.
