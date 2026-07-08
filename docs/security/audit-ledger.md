# Audit Ledger

The API audit ledger supports two backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for verification runs and audit events.

Production and staging must not use `memory`; `create_audit_ledger()` rejects that
configuration at startup. Use:

```text
HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=jsonl
HALLU_DEFENSE_AUDIT_LEDGER_PATH=var/audit/audit-ledger.jsonl
```

## Minimization

The JSONL backend writes a redacted copy of verification runs and audit events.
Sensitive-looking keys and text containing secret-like terms are replaced with
`[REDACTED]` before storage. The API still keeps tenant and trace identifiers so
exports remain useful for investigation without turning audit into raw payload logs.

## Validation

`scripts/ci/check_audit_ledger_config.py` validates the configuration surface and CI
wiring. `apps/api/tests/test_audit_ledger.py` verifies append-only persistence,
reload, tenant filtering, redaction, production startup rejection for `memory`, and
fail-closed handling for corrupt records.
