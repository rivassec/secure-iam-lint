import json
import os
from iamlint import rules


def load_policy(file_name):
    path = os.path.join(os.path.dirname(__file__), "../examples", file_name)
    with open(path) as f:
        return json.load(f)


def test_star_permissions():
    policy = load_policy("bad-policy-extended.json")
    findings = rules.check_star_permissions(policy)
    assert any("Action includes '*'" in f for f in findings)
    assert any("Resource includes '*'" in f for f in findings)


def test_allow_without_condition():
    policy = load_policy("bad-policy-extended.json")
    findings = rules.check_allow_without_condition(policy)
    assert any("Allow without any Condition" in f for f in findings)
    assert len(findings) >= 2


def test_passrole_with_wildcard():
    policy = load_policy("bad-policy-extended.json")
    findings = rules.check_passrole_with_wildcard(policy)
    assert any("iam:PassRole with wildcard" in f for f in findings)


def test_notaction_notresource():
    policy = load_policy("bad-policy-extended.json")
    findings = rules.check_notaction_notresource(policy)
    assert any("uses NotAction" in f for f in findings)
    assert any("uses NotResource" in f for f in findings)


def test_all_checks_combined():
    policy = load_policy("bad-policy-extended.json")
    findings = rules.run_all_checks(policy)
    assert len(findings) >= 6
