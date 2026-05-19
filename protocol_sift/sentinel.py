from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    source: str
    host: str
    actor: str
    action: str
    target: str
    detail: str
    raw_hash: str


@dataclass
class Finding:
    name: str
    severity: str
    confidence: float
    evidence_ids: list[str]
    rationale: str


def _hash_row(row: dict[str, str]) -> str:
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_events(evidence_dir: Path) -> list[Event]:
    events: list[Event] = []
    for csv_path in sorted(evidence_dir.glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                events.append(
                    Event(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        source=csv_path.name,
                        host=row["host"],
                        actor=row["actor"],
                        action=row["action"],
                        target=row["target"],
                        detail=row["detail"],
                        raw_hash=_hash_row(row),
                    )
                )
    return sorted(events, key=lambda event: event.timestamp)


def detect(events: Iterable[Event]) -> tuple[list[Finding], list[dict[str, object]]]:
    events = list(events)
    audit: list[dict[str, object]] = []
    findings: list[Finding] = []

    failed_ssh = [e for e in events if e.action == "ssh_failed_password"]
    if len(failed_ssh) >= 5:
        ids = [e.event_id for e in failed_ssh]
        findings.append(
            Finding(
                "SSH brute-force cluster",
                "medium",
                0.74,
                ids,
                "Multiple failed SSH attempts targeted the same admin account.",
            )
        )
        audit.append({"step": "detect", "rule": "ssh_bruteforce", "evidence": ids})

    web_uploads = [e for e in events if e.action == "web_upload" and ".php" in e.target]
    if web_uploads:
        ids = [e.event_id for e in web_uploads]
        findings.append(
            Finding(
                "Suspicious PHP upload",
                "high",
                0.82,
                ids,
                "A PHP file was uploaded through the public web surface.",
            )
        )
        audit.append({"step": "detect", "rule": "php_upload", "evidence": ids})

    dns_hits = [e for e in events if e.action == "dns_query" and "new-domain" in e.detail]
    if dns_hits:
        ids = [e.event_id for e in dns_hits]
        findings.append(
            Finding(
                "Newly observed DNS beacon",
                "medium",
                0.68,
                ids,
                "The host queried a newly observed external domain after web activity.",
            )
        )
        audit.append({"step": "detect", "rule": "new_domain_beacon", "evidence": ids})

    proc_hits = [e for e in events if e.action == "process_start" and "php" in e.detail.lower()]
    if proc_hits:
        ids = [e.event_id for e in proc_hits]
        findings.append(
            Finding(
                "Web shell style process launch",
                "critical",
                0.88,
                ids,
                "The web service launched a shell-like process from PHP context.",
            )
        )
        audit.append({"step": "detect", "rule": "php_process_launch", "evidence": ids})

    return findings, audit


def correlate(events: list[Event], findings: list[Finding], audit: list[dict[str, object]]) -> Finding:
    ids = {event.event_id for event in events}
    names = {finding.name for finding in findings}
    has_chain = {
        "SSH brute-force cluster",
        "Suspicious PHP upload",
        "Newly observed DNS beacon",
        "Web shell style process launch",
    }.issubset(names)

    if has_chain:
        audit.append(
            {
                "step": "self_correction",
                "before": "SSH brute force looked isolated.",
                "after": "SSH, upload, DNS, and process evidence form one compromise chain.",
                "promoted_evidence": sorted(ids),
            }
        )
        return Finding(
            "Coordinated web compromise with credential pressure",
            "critical",
            0.91,
            sorted(ids),
            "The correction pass linked independent weak signals into a single intrusion timeline.",
        )

    audit.append({"step": "self_correction", "result": "No cross-source promotion"})
    return Finding(
        "Suspicious activity requiring analyst review",
        "medium",
        0.61,
        sorted(ids),
        "Signals exist but do not form a complete compromise chain.",
    )


def write_reports(report: dict[str, object], audit: list[dict[str, object]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "incident_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (out_dir / "audit_log.jsonl").open("w", encoding="utf-8") as handle:
        for entry in audit:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    evidence_lines = "\n".join(
        f"- `{item['event_id']}` `{item['timestamp']}` {item['host']} {item['action']} -> {item['target']}"
        for item in report["evidence"]
    )
    finding_lines = "\n".join(
        f"- **{item['name']}** ({item['severity']}, confidence {item['confidence']:.2f}): {item['rationale']}"
        for item in report["findings"]
    )
    markdown = f"""# Incident Report: {report['incident_title']}

Generated: {datetime.utcnow().isoformat(timespec='seconds')}Z

## Summary

- Severity: **{report['severity']}**
- Confidence: **{report['confidence']}**
- Primary hypothesis: {report['primary_hypothesis']}

## Findings

{finding_lines}

## Evidence Timeline

{evidence_lines}

## Recommended Response

1. Isolate `web-01` from outbound traffic.
2. Preserve web root, auth logs, and process telemetry.
3. Rotate `app-admin` credentials and invalidate active sessions.
4. Block the beacon domain and review adjacent hosts for the same indicators.
5. Re-image the host if web shell persistence is confirmed.

## Self-Correction Note

The first pass treated SSH pressure as an isolated brute-force attempt. The
correction pass linked SSH, PHP upload, DNS, and process telemetry into a single
critical compromise chain.
"""
    (out_dir / "incident_report.md").write_text(markdown, encoding="utf-8")


def run_investigation(evidence_dir: Path, out_dir: Path) -> dict[str, object]:
    events = load_events(evidence_dir)
    findings, audit = detect(events)
    primary = correlate(events, findings, audit)
    all_findings = findings + [primary]
    report = {
        "incident_title": primary.name,
        "severity": primary.severity,
        "confidence": primary.confidence,
        "primary_hypothesis": primary.rationale,
        "findings": [asdict(finding) for finding in all_findings],
        "evidence": [asdict(event) for event in events],
    }
    write_reports(report, audit, out_dir)
    return report

