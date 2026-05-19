# Protocol SIFT Sentinel

Protocol SIFT Sentinel is an autonomous incident-response triage agent for the
FIND EVIL! challenge. It reads mixed endpoint, web, SSH, and DNS evidence,
builds a timeline, correlates weak signals into incident hypotheses, performs a
self-correction pass, and emits a judge-friendly incident report with an audit
trail.

The project is inspired by SANS SIFT and the Protocol SIFT mindset: preserve
evidence, trace every conclusion to observable facts, and make the agent show
its work before recommending containment.

## What It Does

1. Loads evidence from CSV/JSONL logs.
2. Normalizes events into a single timeline.
3. Detects brute force, web shell, suspicious DNS, and credential misuse.
4. Correlates events into a ranked incident hypothesis.
5. Runs a self-correction pass that challenges early assumptions.
6. Produces Markdown and JSON reports with evidence IDs and SHA-256 hashes.

## Quick Start

```powershell
python -m protocol_sift.cli --evidence evidence --out output
```

Generated artifacts:

- `output/incident_report.md`
- `output/incident_report.json`
- `output/audit_log.jsonl`

## Demo Scenario

The bundled evidence simulates a small intrusion:

- SSH brute-force attempts against `app-admin`.
- A successful login from the same ASN.
- Web upload of a suspicious `invoice.php`.
- DNS beaconing to a newly seen domain.
- A process launch consistent with a PHP web shell.

The first pass initially treats the SSH event as isolated. The correction pass
links it to the web shell and DNS activity, then upgrades the finding to a
coordinated compromise.

## Agent Design

```text
Evidence loader
  -> normalizer
  -> detector pass
  -> correlation graph
  -> self-correction pass
  -> report writer
```

The agent does not hide uncertainty. Every finding includes confidence,
supporting evidence IDs, and the reason it was promoted or rejected.

## Built With

- Python 3.11 standard library
- Deterministic evidence correlation rules
- Markdown and JSON report generation
- SHA-256 evidence hashing

## Hackathon Fit

This submission focuses on a practical autonomous IR workflow: the agent can
triage noisy evidence, revise its own conclusion, and hand responders an audit
ready report rather than a black-box answer.

