# Contract Examples

Each public JSON Schema has:

- one valid payload under `valid/`
- one invalid payload under `invalid/`

`scripts/ci/check_json_schemas.py` validates that all valid examples pass and all invalid examples fail under JSON Schema Draft 2020-12.
