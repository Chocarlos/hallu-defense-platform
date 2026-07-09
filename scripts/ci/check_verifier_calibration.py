from __future__ import annotations

import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.dev.generate_verifier_calibration import (  # noqa: E402
    OUTPUT_PATH,
    build_report,
    render_report,
)


class VerifierCalibrationDriftError(RuntimeError):
    pass


def validate_committed_artifact(path: Path = OUTPUT_PATH) -> None:
    if not path.exists():
        raise VerifierCalibrationDriftError(f"Verifier calibration artifact is missing: {path}")

    expected = render_report(build_report())
    actual = path.read_text(encoding="utf-8")
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=str(path),
                tofile="regenerated verifier calibration",
            )
        )
        raise VerifierCalibrationDriftError(
            "Verifier calibration artifact is stale. "
            "Run scripts/dev/generate_verifier_calibration.py.\n"
            + diff
        )


def main() -> None:
    try:
        validate_committed_artifact()
    except VerifierCalibrationDriftError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    print("Verifier calibration artifact is up to date.")


if __name__ == "__main__":
    main()
