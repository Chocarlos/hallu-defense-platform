# Contributing

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e "apps/api[dev]"
npm install
```

## Validation

Run the broad checks before handing off:

```powershell
make lint
make typecheck
make test
make build
make contracts
make openapi
make security-check
make evals-smoke
```

If `make` is unavailable on the host, run the equivalent commands documented in `docs/WORKLOG.md`.

## Traceability

Every meaningful change must update `docs/TRACEABILITY_MATRIX.md` when it affects a requirement. Use only these statuses:

- `not_started`
- `designed`
- `implemented`
- `tested`
- `documented`
- `accepted`

Do not use `accepted` unless the requirement has implementation, tests, documentation, and recorded validation evidence.

## Public Contracts

Public contract changes must update:

- Pydantic models in `apps/api`.
- TypeScript types in `packages/contracts`.
- JSON Schemas in `packages/contracts/schemas`.
- OpenAPI output in `docs/api/openapi.yaml`.
- Contract tests.

