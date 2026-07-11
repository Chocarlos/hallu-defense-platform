from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

PIP_AUDIT_MODULE = "pip_audit"
ROOT = Path(__file__).resolve().parents[2]
RUNTIME_LOCK = ROOT / "requirements" / "python" / "runtime-linux-py312.lock"
DEV_LOCK = ROOT / "requirements" / "python" / "dev-linux-py312.lock"
BUILD_TOOLS_LOCK = ROOT / "requirements" / "python" / "build-tools-linux-py312.lock"
SANDBOX_LOCK = ROOT / "requirements" / "python" / "sandbox-linux-py312.lock"
AUDIT_LOCKS = (
    ("runtime", RUNTIME_LOCK),
    ("dev", DEV_LOCK),
    ("build-tools", BUILD_TOOLS_LOCK),
    ("sandbox", SANDBOX_LOCK),
)


def audit_command(
    python_executable: str = sys.executable,
    *,
    lock_path: Path = RUNTIME_LOCK,
) -> list[str]:
    return [
        python_executable,
        "-m",
        PIP_AUDIT_MODULE,
        "--requirement",
        str(lock_path),
        "--disable-pip",
        "--progress-spinner",
        "off",
    ]


def audit_python_environment(python_executable: str = sys.executable) -> int:
    if importlib.util.find_spec(PIP_AUDIT_MODULE) is None:
        print("pip-audit is not installed. Install the API dev dependencies first.")
        return 2

    failed = False
    for label, lock_path in AUDIT_LOCKS:
        print(f"Auditing exact {label} lock: {lock_path.relative_to(ROOT)}")
        completed = subprocess.run(
            audit_command(python_executable, lock_path=lock_path),
            cwd=ROOT,
            check=False,
        )
        failed = completed.returncode != 0 or failed
    return 1 if failed else 0


def main() -> None:
    raise SystemExit(audit_python_environment())


if __name__ == "__main__":
    main()
