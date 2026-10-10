#!/usr/bin/env bash
# Shared assertion for the Action self-test (.github/workflows/action-selftest.yml).
#
# Asserts BOTH the step outcome AND the action's `exit-code` output (and, optionally,
# `analysis-status` and a SARIF ruleId) for one `uses: ./` case, and appends a row to the
# job summary. Inputs arrive as environment variables so no step output is ever
# interpolated into a shell command line:
#
#   CASE            case name (for messages / summary row)
#   OUTCOME         steps.<id>.outcome
#   CODE            steps.<id>.outputs.exit-code
#   STATUS          steps.<id>.outputs.analysis-status      (only checked when WANT_STATUS set)
#   WANT_OUTCOME    success | failure
#   WANT_CODE       0 | 1 | 2 | 3 | 4
#   WANT_STATUS     optional: complete | partial | failed
#   SARIF           optional: SARIF file to inspect
#   WANT_RULE       optional: a ruleId that MUST be present in SARIF
#
# A non-zero WANT_CODE with an observed exit-code of 0 is reported as FAIL-OPEN explicitly.
set -euo pipefail

fail() { echo "${CASE}: $*"; exit 1; }

row() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "| ${CASE} | ${OUTCOME} | ${CODE:-} | ${STATUS:-} |" >> "$GITHUB_STEP_SUMMARY"
  fi
}
row

test "${OUTCOME}" = "${WANT_OUTCOME}" \
  || fail "expected step outcome '${WANT_OUTCOME}', got '${OUTCOME}'"

if [ "${WANT_CODE}" != "0" ]; then
  test "${CODE:-}" != "0" || fail "FAIL-OPEN - expected exit-code ${WANT_CODE} but the action reported 0 (green)"
fi
test "${CODE:-}" = "${WANT_CODE}" \
  || fail "expected exit-code ${WANT_CODE}, got '${CODE:-}'"

if [ -n "${WANT_STATUS:-}" ]; then
  test "${STATUS:-}" = "${WANT_STATUS}" \
    || fail "expected analysis-status ${WANT_STATUS}, got '${STATUS:-}'"
fi

if [ -n "${WANT_RULE:-}" ]; then
  test -n "${SARIF:-}" && test -f "${SARIF}" || fail "SARIF file '${SARIF:-}' was not generated"
  jq -e --arg r "${WANT_RULE}" '[.runs[].results[] | select(.ruleId == $r)] | length > 0' "${SARIF}" > /dev/null \
    || fail "SARIF missing expected ruleId ${WANT_RULE}"
fi

echo "${CASE}: OK (outcome=${OUTCOME}, exit-code=${CODE:-}${STATUS:+, status=${STATUS}})"
