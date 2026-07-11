from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[2]
PROJECT_DIR = ROOT / "apps" / "api"
PYTHON_VERSION = (3, 12, 13)
SOURCE_DATE_EPOCH = "1767225600"
EXPECTED_BUILD_TOOLS = {
    "build": "1.5.1",
    "setuptools": "83.0.0",
    "wheel": "0.47.0",
}


class ReproducibleWheelError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_build_environment() -> None:
    observed_python = sys.version_info[:3]
    if observed_python != PYTHON_VERSION:
        raise ReproducibleWheelError(
            "Wheel builds require exactly Python "
            f"{'.'.join(map(str, PYTHON_VERSION))}."
        )
    for package, expected in EXPECTED_BUILD_TOOLS.items():
        try:
            observed = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ReproducibleWheelError(f"Build tool {package} is missing.") from exc
        if observed != expected:
            raise ReproducibleWheelError(
                f"Build tool {package} must be {expected}; observed {observed}."
            )


def _build_once(output_dir: Path) -> Path:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(output_dir),
            str(PROJECT_DIR),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise ReproducibleWheelError(f"Wheel build failed: {diagnostic}")
    wheels = tuple(output_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise ReproducibleWheelError(
            f"Expected exactly one wheel, observed {len(wheels)}."
        )
    return wheels[0]


def build_and_verify(output_dir: Path | None = None) -> tuple[Path, str]:
    validate_build_environment()
    with tempfile.TemporaryDirectory(prefix="hallu-wheel-a-") as raw_a, tempfile.TemporaryDirectory(
        prefix="hallu-wheel-b-"
    ) as raw_b:
        first = _build_once(Path(raw_a))
        second = _build_once(Path(raw_b))
        first_hash = _sha256(first)
        second_hash = _sha256(second)
        if first.name != second.name or first_hash != second_hash:
            raise ReproducibleWheelError(
                "Repeated wheel builds are not byte-for-byte reproducible: "
                f"{first.name}={first_hash}, {second.name}={second_hash}."
            )
        if output_dir is None:
            return first, first_hash
        output_dir.mkdir(parents=True, exist_ok=True)
        destination = output_dir / first.name
        shutil.copyfile(first, destination)
        return destination, first_hash


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Build the API wheel twice and require identical SHA-256 digests."
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    wheel, digest = build_and_verify(args.output_dir)
    rendered_path = wheel if args.output_dir is not None else Path(wheel.name)
    print(f"Reproducible wheel verified: {rendered_path} sha256:{digest}")


if __name__ == "__main__":
    main()
