import argparse
import json
import sys

from iamlint.rules import run_all_checks


def load_policy(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load policy: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="IAM Policy Linter - scan AWS IAM policies for risky configurations"
    )
    parser.add_argument("policy_file", help="Path to IAM policy JSON file to scan")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()
    policy = load_policy(args.policy_file)

    findings = run_all_checks(policy)

    if not findings:
        print("[INFO] No critical findings detected.")
    else:
        print("\n[!] Findings:")
        for f in findings:
            print(f" - {f}")

    if args.verbose:
        print("\n[DEBUG] Scan complete. Checked rules:", len(findings))


if __name__ == "__main__":
    main()
