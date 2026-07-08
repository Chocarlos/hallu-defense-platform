from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "packages" / "contracts" / "schemas"
EXAMPLES_DIR = ROOT / "packages" / "contracts" / "examples"
TS_CONTRACTS_FILE = ROOT / "packages" / "contracts" / "src" / "index.ts"

TS_SCHEMA_NAME_OVERRIDES = {
    "ClaimVerdict": "verdict",
}


def load_schemas() -> dict[str, dict[str, object]]:
    schema_files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    if not schema_files:
        raise SystemExit(f"No JSON schemas found in {SCHEMA_DIR}")

    schemas: dict[str, dict[str, object]] = {}
    for schema_file in schema_files:
        with schema_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        required_keys = {"$schema", "$id", "title", "type"}
        missing = required_keys.difference(payload)
        if missing:
            raise SystemExit(f"{schema_file} is missing required keys: {sorted(missing)}")
        Draft202012Validator.check_schema(payload)
        schemas[schema_file.stem.removesuffix(".schema")] = payload
    return schemas


def build_registry(schemas: dict[str, dict[str, object]]) -> Registry:
    resources = []
    for schema in schemas.values():
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str):
            raise SystemExit(f"Schema is missing string $id: {schema}")
        resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def validate_examples(schemas: dict[str, dict[str, object]], registry: Registry) -> tuple[int, int]:
    valid_count = validate_examples_in_dir(
        EXAMPLES_DIR / "valid",
        schemas,
        registry,
        should_pass=True,
    )
    invalid_count = validate_examples_in_dir(
        EXAMPLES_DIR / "invalid",
        schemas,
        registry,
        should_pass=False,
    )
    return valid_count, invalid_count


def validate_typescript_schema_coverage(schemas: dict[str, dict[str, object]]) -> int:
    if not TS_CONTRACTS_FILE.exists():
        raise SystemExit(f"TypeScript contracts file not found: {TS_CONTRACTS_FILE}")

    source = TS_CONTRACTS_FILE.read_text(encoding="utf-8")
    interface_names = sorted(set(re.findall(r"^export interface ([A-Za-z0-9_]+)", source, re.MULTILINE)))
    expected_schema_names = {
        TS_SCHEMA_NAME_OVERRIDES.get(interface_name, camel_to_kebab(interface_name))
        for interface_name in interface_names
    }
    missing = sorted(expected_schema_names.difference(schemas))
    if missing:
        raise SystemExit(
            "Missing JSON Schema files for exported TypeScript interfaces: "
            + ", ".join(missing)
        )
    return len(interface_names)


def camel_to_kebab(name: str) -> str:
    first_pass = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", first_pass).lower()


def validate_examples_in_dir(
    examples_dir: Path,
    schemas: dict[str, dict[str, object]],
    registry: Registry,
    *,
    should_pass: bool,
) -> int:
    if not examples_dir.exists():
        raise SystemExit(f"Examples directory not found: {examples_dir}")

    count = 0
    for example_file in sorted(examples_dir.glob("*.json")):
        schema_name = example_file.stem
        schema = schemas.get(schema_name)
        if schema is None:
            raise SystemExit(f"No schema found for example {example_file}")

        payload = json.loads(example_file.read_text(encoding="utf-8"))
        validator = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        errors = sorted(validator.iter_errors(payload), key=lambda error: error.json_path)

        if should_pass and errors:
            first = errors[0]
            raise SystemExit(f"Valid example failed {example_file}: {first.json_path} {first.message}")
        if not should_pass and not errors:
            raise SystemExit(f"Invalid example unexpectedly passed: {example_file}")
        count += 1
    return count


def main() -> None:
    schemas = load_schemas()
    registry = build_registry(schemas)
    valid_count, invalid_count = validate_examples(schemas, registry)
    interface_count = validate_typescript_schema_coverage(schemas)

    print(
        f"Validated {len(schemas)} JSON schema files, "
        f"{valid_count} valid examples, {invalid_count} invalid examples, "
        f"and {interface_count} TypeScript interfaces."
    )


if __name__ == "__main__":
    main()
