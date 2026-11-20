#!/usr/bin/env bash
# Smoke-test the CLI container image: exit codes 0/1/3, non-root, no network.
# Usage: scripts/container-smoke.sh <image>
set -uo pipefail
img="${1:?usage: container-smoke.sh <image>}"
dir="$(cd "$(dirname "$0")/.." && pwd)/.github/container-smoke"
fail=0

run() { # run <expected-exit> <fixture>
  docker run --rm --network none --read-only --cap-drop ALL \
    -v "$dir:/work:ro" -w /work "$img" --family identity "$2" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$1" ]; then echo "ok   $2 exit=$got"; else echo "FAIL $2 exit=$got want=$1"; fail=1; fi
}

run 0 clean.json
run 1 findings.json
run 3 unanalyzable.json

uid="$(docker run --rm --network none --entrypoint id "$img" -u)"
if [ "$uid" != "0" ]; then echo "ok   runs as uid=$uid"; else echo "FAIL runs as root"; fail=1; fi

exit "$fail"
