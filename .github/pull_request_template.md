## What and why

<!-- One logical change. Which security property does it preserve or add? -->

## Checklist

- [ ] Fail closed: nothing that used to be UNKNOWN / exit 3 can now read CLEAN
- [ ] Exit contract unchanged (0 clean, 1 findings, 2 usage, 3 could-not-analyze, 4 internal), or the change is called out above
- [ ] Test that proves the change (failing first where possible)
- [ ] Gate green from `tools/iam-blast-radius/` (see CONTRIBUTING.md), or `scripts/ci-local.sh`
- [ ] New finding id: catalog, detector, fixture matrix, golden corpus
- [ ] CHANGELOG entry under the unreleased version
- [ ] Synthetic fixtures only: no real account ids, ARNs or names
- [ ] ASCII only
