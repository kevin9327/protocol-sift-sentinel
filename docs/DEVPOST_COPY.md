# Devpost Copy

## Project Title

Protocol SIFT Sentinel

## Elevator Pitch

An autonomous incident-response triage agent that correlates messy host, web,
SSH, DNS, and EDR evidence into an audit-ready compromise report.

## Story

Protocol SIFT Sentinel was built for the FIND EVIL! challenge as a practical
security agent rather than a generic chatbot. It ingests evidence, preserves
hashes, builds a timeline, detects suspicious behaviors, and then challenges
its own first-pass conclusion before writing a report.

The key agentic behavior is self-correction. The first pass sees SSH brute force
as a medium-severity event. After correlation, the agent links SSH pressure,
PHP upload, DNS beaconing, and web-shell process telemetry into one critical
compromise chain.

## Built With

Python, SANS SIFT-inspired workflow design, Protocol SIFT methodology,
deterministic evidence correlation, Markdown reports, JSON audit logs.

## Try It

Hosted demo:

https://kevin9327.github.io/protocol-sift-sentinel/

Repository:

https://github.com/kevin9327/protocol-sift-sentinel

Video demo:

https://youtu.be/pKnt5Ij1VkA

```powershell
python -m protocol_sift.cli --evidence evidence --out output
```
