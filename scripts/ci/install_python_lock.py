from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
PYTHON_VERSION = (3, 12, 13)
LOCKS = {
    "runtime": ROOT / "requirements" / "python" / "runtime-linux-py312.lock",
    "dev": ROOT / "requirements" / "python" / "dev-linux-py312.lock",
    "build-tools": (
        ROOT / "requirements" / "python" / "build-tools-linux-py312.lock"
    ),
    "sandbox": ROOT / "requirements" / "python" / "sandbox-linux-py312.lock",
}


class LockTargetError(RuntimeError):
    pass


def validate_lock_target() -> None:
    if platform.python_implementation() != "CPython":
        raise LockTargetError("Hashed Python locks target CPython only.")
    if sys.version_info[:3] != PYTHON_VERSION:
        raise LockTargetError(
            "Hashed Python locks target exactly Python "
            f"{'.'.join(map(str, PYTHON_VERSION))}."
        )
    if sys.platform != "linux":
        raise LockTargetError(
            "Hashed Python locks target Linux; use the pinned Linux builder from Windows."
        )


def install_lock(profile: str, *, wheelhouse: Path | None = None) -> None:
    validate_lock_target()
    lock_path = LOCKS[profile]
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--require-hashes",
        "--no-deps",
    ]
    if wheelhouse is not None:
        command.extend(["--no-index", f"--find-links={wheelhouse}"])
    command.extend(["-r", str(lock_path)])
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    check = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=ROOT,
        check=False,
    )
    if check.returncode != 0:
        raise SystemExit(check.returncode)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Install one platform-explicit hashed Python lock."
    )
    parser.add_argument("profile", choices=sorted(LOCKS))
    parser.add_argument("--wheelhouse", type=Path)
    args = parser.parse_args(argv)
    install_lock(args.profile, wheelhouse=args.wheelhouse)


if __name__ == "__main__":
    main()
