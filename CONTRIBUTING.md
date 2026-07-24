# Contributing

## Licensing of contributions

Hallu Defense Platform is licensed under the [Apache License, Version 2.0](LICENSE).

By intentionally submitting a contribution for inclusion in this repository, you confirm that you have the right to submit it. Unless you explicitly designate the submission in writing as "Not a Contribution" before it is incorporated, the contribution is provided under Apache-2.0, consistent with Section 5 of the license.

Do not submit copied or adapted source code, documentation, datasets, media, or other material unless its origin, license compatibility, and required attribution are documented. See the [licensing and attribution policy](docs/legal/licensing.md).

## Development setup

Use Python 3.12, Node.js 24.18.0, and npm 11.16.0 as declared by the repository.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e "apps/api[dev]"
npm ci
```

Linux or macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e "apps/api[dev]"
npm ci
```

Do not regenerate a lock merely to accommodate a different local runtime. Correct the runtime first.

## Validation

Run the broad checks before handing off:

```bash
make lint
make typecheck
make test
make build
make contracts
make openapi-check
make security-check
make evals-smoke
git diff --check
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

## Public contracts

Public contract changes must update:

- Pydantic models in `apps/api`.
- TypeScript types in `packages/contracts`.
- JSON Schemas in `packages/contracts/schemas`.
- OpenAPI output in `docs/api/openapi.yaml`.
- Contract tests.
