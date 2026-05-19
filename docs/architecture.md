# Architecture Diagram

Protocol SIFT Sentinel uses a direct agent-extension pattern: a deterministic
triage loop wraps SIFT-style evidence processing with validation and
self-correction before report generation.

```text
Case evidence
  |-- auth.csv
  |-- web.csv
  |-- edr.csv
  `-- dns.csv
        |
        v
Evidence loader
  - read-only CSV parsing
  - SHA-256 row hashing
        |
        v
Normalizer
  - common Event schema
  - sorted timeline
        |
        v
Detector pass
  - ssh_bruteforce
  - php_upload
  - new_domain_beacon
  - php_process_launch
        |
        v
Correlation graph
  - shared host
  - time proximity
  - actor/source continuity
        |
        v
Self-correction pass
  - challenges isolated findings
  - promotes only cross-source chains
  - writes before/after audit record
        |
        v
Outputs
  - incident_report.md
  - incident_report.json
  - audit_log.jsonl
```

## Security Boundaries

- Evidence is read-only. The agent has no deletion, mutation, or containment
  action exposed in the code path.
- Evidence rows are hashed before analysis, so report claims can be tied back to
  preserved inputs.
- Recommendations are written as human-review actions, not executed
  automatically.
- The self-correction pass cannot invent evidence. It can only promote a
  hypothesis using observed event IDs.

## Architectural Guardrails

- Hard-coded detector functions operate on typed `Event` objects instead of raw
  shell output.
- The report writer serializes findings from structured objects.
- The audit log records each rule and the evidence IDs it used.

## Prompt-Based Guardrails

None are required for the current prototype. A future LLM-enabled version would
use prompts only for summarization, while keeping evidence loading, typed
parsing, and destructive-action prevention in code.

