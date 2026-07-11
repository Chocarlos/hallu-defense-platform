from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPA_TEST_TARGET = "infra/opa"
OPA_ROOT = ROOT / OPA_TEST_TARGET


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def require_opa_tree() -> None:
    if not OPA_ROOT.is_dir():
        raise SystemExit(f"Required OPA policy directory is missing: {OPA_TEST_TARGET}")


def main() -> None:
    run([sys.executable, "-m", "pytest", "apps/api/tests", "-k", "policy"])
    require_opa_tree()

    opa = shutil.which("opa")
    if opa is None:
        print("opa not found on PATH; running local static Rego policy checks instead.")
        run([sys.executable, "scripts/ci/check_rego_policy.py"])
        return

    run([opa, "version"])
    run([opa, "check", "--strict", OPA_TEST_TARGET])
    run([opa, "test", OPA_TEST_TARGET])


if __name__ == "__main__":
    main()
