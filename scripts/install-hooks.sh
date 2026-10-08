#!/usr/bin/env bash
# Install the repository's git hooks. Run once after cloning.
#
# Git does not version its own hooks, so they have to be pointed at
# explicitly. This sets core.hooksPath, which survives further clones of the
# working copy and needs no symlinks.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git config core.hooksPath scripts/githooks
echo "hooks installed: $(git config core.hooksPath)"
echo
echo "The pre-commit hook refuses any commit containing:"
echo "  - a .env file (except .env.example)"
echo "  - an AWS access key id or secret in staged content"
echo "  - Terraform state or .pem files"
echo
echo "This matters because .env lives inside the repository and .gitignore"
echo "alone is advisory - 'git add -f' defeats it. The hook checks what is"
echo "actually staged."
