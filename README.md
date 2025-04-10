<<<<<<< HEAD
![CI](https://github.com/rivassec/secure-iam-lint/actions/workflows/test.yml/badge.svg)
=======
![CI](https://github.com/coldbootsec/secure-iam-lint/actions/workflows/test.yml/badge.svg)
>>>>>>> 5f06748 (Ensure tests/ directory is tracked by Git)
# secure-iam-lint

`secure-iam-lint` is a lightweight CLI tool that scans AWS IAM policy files for common misconfigurations. It flags overly permissive actions like wildcards, missing conditions, and patterns that could lead to privilege escalation.

This tool is built for DevSecOps workflows. It works great in CI pipelines, local dev environments, and anywhere you want to catch risky IAM practices early.

## Features

- Flags use of `Action: "*"` and `Resource: "*"`
- Warns on `Allow` statements missing `Condition` blocks
- Detects use of `iam:PassRole` with wildcard resources
- Identifies `NotAction` and `NotResource` usage
- CLI output designed to be readable and useful
- Fully testable, modular Python structure

## Installation

Clone the repo and install it in editable mode (use a virtual environment):

```bash
git clone https://github.com/yourusername/secure-iam-lint.git
cd secure-iam-lint
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
iam-lint examples/bad-policy-extended.json
```

Example output:

```
Findings:
 - HIGH Statement 0: Action includes '*' (overly permissive)
 - HIGH Statement 0: Resource includes '*' (overly permissive)
 - MEDIUM Statement 1: Allow without any Condition block
 - CRITICAL Statement 2: iam:PassRole with wildcard resource
 - MEDIUM Statement 3: uses NotAction (may be overly permissive)
 - MEDIUM Statement 3: uses NotResource (may be overly permissive)
```

Use `--verbose` if you want extra detail during scans.

## Running Tests

Install `pytest` and run the suite:

```bash
pip install pytest
pytest tests/
```

## Project Structure

```
secure-iam-lint/
├── iamlint/               # CLI and rule logic
├── examples/              # Sample IAM policies to test
├── tests/                 # Pytest-based test suite
├── iam_lint.py            # CLI entry point
├── setup.py               # Install/config metadata
└── README.md
```

## Roadmap

Coming soon:

- JSON and SARIF output modes
- Fail thresholds (e.g. `--fail-on HIGH`)
- Docker support for CI use
- Configurable rule sets

## Why This Exists

IAM policy reviews are tedious and easy to get wrong. This tool helps you catch obvious problems early — especially useful for engineers reviewing IaC templates or pushing changes in regulated environments.

