#!/usr/bin/env bash
# Terraform wrapper for the study's infrastructure layers.
#
#   ./scripts/infra.sh plan    00-core
#   ./scripts/infra.sh apply   00-core
#   ./scripts/infra.sh status  00-core
#   ./scripts/infra.sh destroy 00-core
#   ./scripts/infra.sh status              # every layer
#
# Teardown is the project's main cost control (risk R12), so `destroy` is a
# first-class operation here rather than an afterthought.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AWS_PROFILE="${AWS_PROFILE:-ddos-eval}"

LAYERS=(00-core 10-cloudfront 20-waf-managed 30-waf-rate 35-waf-antiddos 40-harness 99-budget)

usage() { sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 1; }

have_tf() { [[ -n "$(find "$REPO/infra/$1" -maxdepth 1 -name '*.tf' -print -quit 2>/dev/null)" ]]; }

run_tf() {
  local layer="$1" action="$2"
  local dir="$REPO/infra/$layer"

  if ! have_tf "$layer"; then
    echo "  $layer: not built yet"
    return 0
  fi

  terraform -chdir="$dir" init -input=false -upgrade >/dev/null

  case "$action" in
    plan)    terraform -chdir="$dir" plan -input=false ;;
    apply)   terraform -chdir="$dir" apply -input=false -auto-approve ;;
    destroy) terraform -chdir="$dir" destroy -input=false -auto-approve ;;
    status)
      local n
      n="$(terraform -chdir="$dir" state list 2>/dev/null | wc -l | tr -d ' ')"
      if [[ "$n" == "0" ]]; then
        echo "  $layer: no resources deployed"
      else
        echo "  $layer: $n resources deployed"
        terraform -chdir="$dir" output 2>/dev/null | sed 's/^/      /'
      fi
      ;;
  esac
}

[[ $# -ge 1 ]] || usage
ACTION="$1"; shift

case "$ACTION" in
  plan|apply|destroy)
    [[ $# -eq 1 ]] || usage
    echo "==> $ACTION $1   (profile: $AWS_PROFILE)"
    run_tf "$1" "$ACTION"
    ;;
  status)
    targets=("${@:-${LAYERS[@]}}")
    echo "==> status   (profile: $AWS_PROFILE)"
    for l in "${targets[@]}"; do run_tf "$l" status; done
    ;;
  *) usage ;;
esac
