# iamlint/rules.py

SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def check_star_permissions(policy):
    """Flag overly permissive wildcards in Action or Resource."""
    findings = []
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(resources, list):
            resources = [resources]

        if "*" in actions:
            findings.append(
                f"{SEVERITY['HIGH']} Statement {idx}: Action includes '*' (overly permissive)"
            )
        if "*" in resources:
            findings.append(
                f"{SEVERITY['HIGH']} Statement {idx}: Resource includes '*' (overly permissive)"
            )
    return findings


def check_allow_without_condition(policy):
    """Warn on Allow statements that lack any conditions."""
    findings = []
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if stmt.get("Effect") == "Allow" and "Condition" not in stmt:
            findings.append(
                f"{SEVERITY['MEDIUM']} Statement {idx}: Allow without any Condition block"
            )
    return findings


def check_passrole_with_wildcard(policy):
    """Flag use of iam:PassRole with Resource: '*' (privilege escalation risk)."""
    findings = []
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if not isinstance(actions, list):
            actions = [actions]
        if not isinstance(resources, list):
            resources = [resources]

        if any("iam:PassRole" in a for a in actions) and "*" in resources:
            findings.append(
                f"{SEVERITY['CRITICAL']} Statement {idx}: iam:PassRole with wildcard resource"
            )
    return findings


def check_notaction_notresource(policy):
    """Warn about use of NotAction or NotResource, which are often misunderstood."""
    findings = []
    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if "NotAction" in stmt:
            findings.append(
                f"{SEVERITY['MEDIUM']} Statement {idx}: uses NotAction (may be overly permissive)"
            )
        if "NotResource" in stmt:
            findings.append(
                f"{SEVERITY['MEDIUM']} Statement {idx}: uses NotResource (may be overly permissive)"
            )
    return findings


def run_all_checks(policy):
    """Run all registered rule checks and collect findings."""
    checks = [
        check_star_permissions,
        check_allow_without_condition,
        check_passrole_with_wildcard,
        check_notaction_notresource,
    ]

    findings = []
    for check in checks:
        findings.extend(check(policy))
    return findings
