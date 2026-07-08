from __future__ import annotations

import json
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - fallback for minimal environments
    yaml = None

from hallu_defense.main import app

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs" / "api" / "openapi.yaml"


def main() -> None:
    schema = app.openapi()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        if yaml is not None:
            yaml.safe_dump(schema, handle, sort_keys=False, allow_unicode=False)
        else:
            json.dump(schema, handle, indent=2)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()

