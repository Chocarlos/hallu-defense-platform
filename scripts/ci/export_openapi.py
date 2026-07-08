from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

from hallu_defense.main import app

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs" / "api" / "openapi.yaml"


def build_openapi_schema() -> dict[str, object]:
    schema = app.openapi()
    if not isinstance(schema, dict):
        raise TypeError("FastAPI returned a non-object OpenAPI schema.")
    return schema


def render_openapi(schema: Mapping[str, object]) -> str:
    return yaml.safe_dump(dict(schema), sort_keys=False, allow_unicode=False)


def write_openapi(output_path: Path = OUTPUT) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_openapi(build_openapi_schema()), encoding="utf-8")


def main() -> None:
    write_openapi()
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
