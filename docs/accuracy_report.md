# Accuracy Report

## Ground Truth

The bundled case data intentionally represents a coordinated compromise of
`web-01`:

- SSH brute-force pressure against `app-admin`.
- A successful SSH login from the same source ASN.
- Upload and execution of `invoice.php`.
- PHP-spawned shell behavior.
- DNS beaconing to `evil-sync.example`.

## Expected Outcome

The agent should classify the final incident as a critical web compromise with
credential pressure and should cite evidence across auth, web, EDR, and DNS
sources.

## Observed Outcome

Running:

```powershell
python -m protocol_sift.cli --evidence evidence --out output
```

produces:

- Incident: `Coordinated web compromise with credential pressure`
- Severity: `critical`
- Confidence: `0.91`
- Evidence count: `12`
- Audit log includes a `self_correction` record.

## Self-Correction Evidence

Initial interpretation:

```text
SSH brute force looked isolated.
```

Corrected interpretation:

```text
SSH, upload, DNS, and process evidence form one compromise chain.
```

## Known Limitations

- The prototype uses deterministic sample evidence rather than full SIFT disk or
  memory images.
- It demonstrates the autonomous reasoning loop and report integrity, but does
  not yet wrap the complete SIFT Workstation toolset.
- It does not execute containment actions; recommendations remain
  analyst-approved.

