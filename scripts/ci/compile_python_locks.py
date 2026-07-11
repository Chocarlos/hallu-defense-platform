from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
PYTHON_VERSION = (3, 12, 13)
PIP_TOOLS_VERSION = "7.5.3"
COMMON_ARGUMENTS = (
    "--generate-hashes",
    "--resolver=backtracking",
    "--allow-unsafe",
    "--strip-extras",
    "--no-header",
    "--no-emit-index-url",
    "--no-emit-trusted-host",
    "--quiet",
)


@dataclass(frozen=True)
class LockTarget:
    output: Path
    source: Path
    extra: str | None = None


LOCK_TARGETS = (
    LockTarget(
        output=ROOT / "requirements" / "python" / "build-tools-linux-py312.lock",
        source=ROOT / "requirements" / "python" / "build-tools.in",
    ),
    LockTarget(
        output=ROOT / "requirements" / "python" / "runtime-linux-py312.lock",
        source=ROOT / "apps" / "api" / "pyproject.toml",
    ),
    LockTarget(
        output=ROOT / "requirements" / "python" / "dev-linux-py312.lock",
        source=ROOT / "apps" / "api" / "pyproject.toml",
        extra="dev",
    ),
    LockTarget(
        output=ROOT / "requirements" / "python" / "sandbox-linux-py312.lock",
        source=ROOT / "requirements" / "python" / "sandbox.in",
    ),
)
LOCK_MANIFEST_PATH = ROOT / "requirements" / "python" / "lock-manifest.json"


class LockCompilationError(RuntimeError):
    pass


def _normalized_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def _lock_sha256(path: Path) -> str:
    return hashlib.sha256(_normalized_bytes(path)).hexdigest()


def _write_lock_manifest() -> None:
    manifest = {
        "schema_version": "python-lock-manifest.v1",
        "target": {
            "implementation": "CPython",
            "python": ".".join(map(str, PYTHON_VERSION)),
            "os": "linux",
        },
        "compiler": {"name": "pip-tools", "version": PIP_TOOLS_VERSION},
        "locks": {
            target.output.name: _lock_sha256(target.output)
            for target in sorted(LOCK_TARGETS, key=lambda item: item.output.name)
        },
    }
    LOCK_MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _compile_command(
    target: LockTarget,
    output: Path,
    *,
    upgrade: bool,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "piptools",
        "compile",
        *COMMON_ARGUMENTS,
    ]
    if target.extra is not None:
        command.append(f"--extra={target.extra}")
    if upgrade:
        command.append("--upgrade")
    command.extend(
        [
            f"--output-file={output}",
            str(target.source.relative_to(ROOT)),
        ]
    )
    return command


def validate_lock_toolchain() -> None:
    observed_python = sys.version_info[:3]
    if observed_python != PYTHON_VERSION:
        raise LockCompilationError(
            "Python lock compilation requires exactly "
            f"{'.'.join(map(str, PYTHON_VERSION))}; observed "
            f"{'.'.join(map(str, observed_python))}."
        )
    try:
        observed_pip_tools = importlib.metadata.version("pip-tools")
    except importlib.metadata.PackageNotFoundError as exc:
        raise LockCompilationError(
            "pip-tools is missing; install the Linux Python 3.12 build-tools lock."
        ) from exc
    if observed_pip_tools != PIP_TOOLS_VERSION:
        raise LockCompilationError(
            f"pip-tools must be {PIP_TOOLS_VERSION}; observed {observed_pip_tools}."
        )


def compile_locks(*, check: bool, upgrade: bool = False) -> list[Path]:
    validate_lock_toolchain()
    changed: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="hallu-python-locks-") as raw_temp:
        temp_dir = Path(raw_temp)
        for target in LOCK_TARGETS:
            temporary_output = temp_dir / target.output.name
            if target.output.is_file() and not upgrade:
                shutil.copyfile(target.output, temporary_output)
            completed = subprocess.run(
                _compile_command(target, temporary_output, upgrade=upgrade),
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )
            if completed.returncode != 0:
                diagnostic = completed.stderr.strip() or completed.stdout.strip()
                raise LockCompilationError(
                    f"Could not compile {target.output.relative_to(ROOT)}: {diagnostic}"
                )
            generated = _normalized_bytes(temporary_output)
            if check:
                if not target.output.is_file() or _normalized_bytes(target.output) != generated:
                    changed.append(target.output)
                continue
            target.output.write_bytes(generated)
    if not check:
        _write_lock_manifest()
    return changed


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Compile or verify hashed Python locks.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Resolve newer compatible releases; valid only with --write.",
    )
    args = parser.parse_args(argv)
    if args.check and args.upgrade:
        parser.error("--upgrade is valid only with --write")
    changed = compile_locks(check=args.check, upgrade=args.upgrade)
    if changed:
        rendered = ", ".join(str(path.relative_to(ROOT)) for path in changed)
        raise SystemExit(f"Python lock drift detected: {rendered}")
    action = "Verified" if args.check else "Compiled"
    print(f"{action} hashed Python dependency locks with the pinned toolchain.")


if __name__ == "__main__":
    main()
