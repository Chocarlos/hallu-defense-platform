from __future__ import annotations

import difflib
import importlib
from pathlib import Path

export_openapi = importlib.import_module(
    "scripts.ci.export_openapi" if __package__ else "export_openapi"
)
OUTPUT = export_openapi.OUTPUT
build_openapi_schema = export_openapi.build_openapi_schema
render_openapi = export_openapi.render_openapi


def check_openapi_document(output_path: Path = OUTPUT) -> None:
    if not output_path.exists():
        raise SystemExit(f"OpenAPI artifact is missing: {output_path}")

    committed = output_path.read_text(encoding="utf-8")
    generated = render_openapi(build_openapi_schema())
    if committed == generated:
        print(f"OpenAPI artifact is up to date: {output_path}")
        return

    diff = "\n".join(
        difflib.unified_diff(
            committed.splitlines(),
            generated.splitlines(),
            fromfile=str(output_path),
            tofile="generated OpenAPI",
            lineterm="",
        )
    )
    raise SystemExit(
        "OpenAPI artifact is out of date. Run `python scripts/ci/export_openapi.py` "
        "and commit docs/api/openapi.yaml.\n"
        f"{diff}"
    )


def main() -> None:
    check_openapi_document()


if __name__ == "__main__":
    main()
