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

## Setup — clone and run

```bash
git clone git@github.com:Rakshan-cloud/aws-ddos-eval.git
cd aws-ddos-eval

python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt

cp .env.example .env
./scripts/install-hooks.sh    # IMPORTANT - installs the credential guard

aws configure --profile ddos-eval
./.venv/bin/python config.py  # prints the resolved configuration
```

### Credentials

Two supported sources, checked in this order:

1. **Explicit keys in `.env`** — `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
   To copy them across from an existing profile without exposing them:
   `./.venv/bin/python scripts/env_from_profile.py`
2. **A named profile** — leave the keys blank and set `AWS_PROFILE`.

`.env` lives inside the repository, so option 1 is protected only by
`.gitignore` — which is advisory, since `git add -f` defeats it. **Run
`./scripts/install-hooks.sh` once.** It installs a pre-commit hook that
inspects what is actually staged and refuses any commit containing a `.env`
file, an AWS key pattern, Terraform state or a `.pem`. Verified blocking both
cases.

`.env` holds only what differs between people and accounts: the AWS profile
name, region, resource prefix and budget alert address. Credentials stay in
`~/.aws/credentials` and never enter the repository.

**Experiment parameters are deliberately NOT in `.env`.** The rate limit,
evaluation window, Lambda memory and instance type are Terraform variables in
`infra/*/main.tf`, under version control with their rationale beside them,
because a published result must be traceable to the exact settings that
produced it. Resource identifiers are not there either — distribution ids and
web ACL ARNs are read live from Terraform outputs, since a cached identifier
eventually goes stale and a collector then queries a resource that no longer
exists, which returns an empty series rather than an error.

So `.env` answers *whose account and where*; Terraform answers *what was the
experiment*.

```bash
./scripts/infra.sh apply 00-core        # deploy, layer by layer
./scripts/infra.sh status               # what is live
./scripts/infra.sh destroy 00-core      # tear down
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
