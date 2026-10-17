"""
main.py
CLI entry point for HTTP Security Header Auditor.
"""

import argparse
import sys
from core.auditor import SecurityAuditor


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated HTTP Security Header & Cookie Hardening Auditor"
    )
    parser.add_argument(
        "-u", "--url",
        dest="target_url",
        required=True,
        help="Target domain or full URL to inspect (e.g., example.com)"
    )
    parser.add_argument(
        "-t", "--timeout",
        dest="timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (Default: 10)"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        type=str,
        default=None,
        help="Path to export the JSON report (e.g., report.json)"
    )

    args = parser.parse_args()

    auditor = SecurityAuditor(
        target_url=args.target_url,
        timeout=args.timeout,
        output_file=args.output_file
    )
    results = auditor.audit()

    if not results:
        sys.exit(1)


if __name__ == "__main__":
    main()