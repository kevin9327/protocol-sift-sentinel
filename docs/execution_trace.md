# Execution Trace

Representative run:

```text
Incident: Coordinated web compromise with credential pressure
Severity: critical | Confidence: 0.91
Primary hypothesis: The correction pass linked independent weak signals into a single intrusion timeline.
Evidence items: 12
Markdown report: output\incident_report.md
```

Audit records:

```jsonl
{"evidence":["AUTH-001","AUTH-002","AUTH-003","AUTH-004","AUTH-005"],"rule":"ssh_bruteforce","step":"detect"}
{"evidence":["WEB-002"],"rule":"php_upload","step":"detect"}
{"evidence":["DNS-001"],"rule":"new_domain_beacon","step":"detect"}
{"evidence":["EDR-001"],"rule":"php_process_launch","step":"detect"}
{"after":"SSH, upload, DNS, and process evidence form one compromise chain.","before":"SSH brute force looked isolated.","promoted_evidence":["AUTH-001","AUTH-002","AUTH-003","AUTH-004","AUTH-005","AUTH-006","DNS-001","EDR-001","EDR-002","WEB-001","WEB-002","WEB-003"],"step":"self_correction"}
```

