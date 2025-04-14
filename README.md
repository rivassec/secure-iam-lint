# secure-iam-lint

[![Checkov Scan](https://github.com/rivassec/secure-iam-lint/actions/workflows/checkov.yml/badge.svg?branch=main)](https://github.com/rivassec/secure-iam-lint/actions/workflows/checkov.yml)
[![Run Tests](https://github.com/rivassec/secure-iam-lint/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/rivassec/secure-iam-lint/actions/workflows/test.yml)
[![Trivy Scan](https://github.com/rivassec/secure-iam-lint/actions/workflows/trivy.yml/badge.svg?branch=main)](https://github.com/rivassec/secure-iam-lint/actions/workflows/trivy.yml)
[![License](https://img.shields.io/github/license/rivassec/secure-iam-lint.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

`secure-iam-lint` is a lightweight CLI scanner for AWS IAM policies. It flags common misconfigurations such as wildcard permissions, missing conditions, and escalation risks. Ideal for CI pipelines and local dev workflows, it helps catch risky IAM patterns early.

## Features

- Flags use of `Action: "*"` and `Resource: "*"`
- Warns on `Allow` statements missing `Condition` blocks
- Detects `iam:PassRole` with wildcard resources
- Identifies `NotAction` and `NotResource` usage
- CLI output designed for readability
- Modular, testable Python structure

## Installation

Clone and install in editable mode (recommended for development):

```bash
git clone https://github.com/rivassec/secure-iam-lint.git
cd secure-iam-lint
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

> PyPI installation is planned for a future release.

## Usage

```bash
iam-lint examples/bad-policy-extended.json
```

### Example Output

```
Findings:
 - HIGH Statement 0: Action includes '*' (overly permissive)
 - HIGH Statement 0: Resource includes '*' (overly permissive)
 - MEDIUM Statement 1: Allow without any Condition block
 - CRITICAL Statement 2: iam:PassRole with wildcard resource
 - MEDIUM Statement 3: uses NotAction (may be overly permissive)
 - MEDIUM Statement 3: uses NotResource (may be overly permissive)
```

Use `--verbose` for additional output.

## Running Tests

Install `pytest` and run:

```bash
pip install pytest
pytest tests/
```

## Project Structure

```
secure-iam-lint/
├── iamlint/               # CLI and rule logic
├── examples/              # Sample IAM policies
├── tests/                 # Pytest-based suite
├── iam_lint.py            # CLI entry point
├── setup.py               # Install/config metadata
└── README.md
```

## Roadmap

Planned features:

- JSON and SARIF output formats
- Severity-based fail thresholds (`--fail-on HIGH`)
- Docker container for CI use
- Configurable rule sets

## Motivation

IAM policy reviews are tedious and error-prone. This tool helps engineers detect obvious risks early — especially in IaC-driven or regulated environments.

## Contributing

Issues and pull requests are welcome. If you have a new rule idea or see a false positive, feel free to open a discussion.

## License

MIT License. See the [LICENSE](LICENSE) file for details.

