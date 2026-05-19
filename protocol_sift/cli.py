from __future__ import annotations

import argparse
from pathlib import Path

from .sentinel import run_investigation


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Protocol SIFT Sentinel.")
    parser.add_argument("--evidence", default="evidence", help="Evidence folder")
    parser.add_argument("--out", default="output", help="Output folder")
    args = parser.parse_args()

    report = run_investigation(Path(args.evidence), Path(args.out))
    print(f"Incident: {report['incident_title']}")
    print(f"Severity: {report['severity']} | Confidence: {report['confidence']}")
    print(f"Primary hypothesis: {report['primary_hypothesis']}")
    print(f"Evidence items: {len(report['evidence'])}")
    print(f"Markdown report: {Path(args.out) / 'incident_report.md'}")


if __name__ == "__main__":
    main()

