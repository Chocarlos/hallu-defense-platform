from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - fallback for minimal environments
    yaml = None

from hallu_defense.main import app

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs" / "api" / "openapi.yaml"


def build_openapi_schema() -> dict[str, object]:
    schema = app.openapi()
    if not isinstance(schema, dict):
        raise TypeError("FastAPI returned a non-object OpenAPI schema.")
    return schema


def render_openapi(schema: Mapping[str, object]) -> str:
    if yaml is not None:
        return yaml.safe_dump(dict(schema), sort_keys=False, allow_unicode=False)
    return json.dumps(schema, indent=2) + "\n"


def write_openapi(output_path: Path = OUTPUT) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_openapi(build_openapi_schema()), encoding="utf-8")


def main() -> None:
    write_openapi()
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
