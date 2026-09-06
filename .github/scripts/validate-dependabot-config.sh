#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .github/dependabot.yml ]]; then
  echo "ERROR: .github/dependabot.yml not found." >&2
  echo "  Deleting it stops Dependabot for every ecosystem here." >&2
  echo "  If that is intended, remove this workflow in the same change." >&2
  exit 1
fi
check-jsonschema --builtin-schema vendor.dependabot .github/dependabot.yml
