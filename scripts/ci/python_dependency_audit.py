from __future__ import annotations

import importlib.util
import subprocess
import sys

PIP_AUDIT_MODULE = "pip_audit"


def audit_command(python_executable: str = sys.executable) -> list[str]:
    return [
        python_executable,
        "-m",
        PIP_AUDIT_MODULE,
        "--progress-spinner",
        "off",
    ]


def audit_python_environment(python_executable: str = sys.executable) -> int:
    if importlib.util.find_spec(PIP_AUDIT_MODULE) is None:
        print("pip-audit is not installed. Install the API dev dependencies first.")
        return 2

    completed = subprocess.run(audit_command(python_executable), check=False)
    return completed.returncode


def main() -> None:
    raise SystemExit(audit_python_environment())


if __name__ == "__main__":
    main()
