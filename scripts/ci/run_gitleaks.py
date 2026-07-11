from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / ".gitleaks.toml"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks@"
    "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)
GITLEAKS_LINUX_X64_SHA256 = (
    "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
)
MAX_GITLEAKS_SECONDS = 180

Runner = Callable[..., subprocess.CompletedProcess[str]]


class GitleaksExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitleaksScanResult:
    clean: bool
    engine: str
    version: str


def run_gitleaks(
    source: Path = ROOT,
    *,
    runner: Runner = subprocess.run,
) -> GitleaksScanResult:
    source = source.resolve()
    if not source.is_dir():
        raise GitleaksExecutionError("Gitleaks source must be an existing directory.")
    if not CONFIG_PATH.is_file():
        raise GitleaksExecutionError("The committed Gitleaks config is unavailable.")

    configured_binary = os.getenv("GITLEAKS_BINARY", "").strip()
    binary = configured_binary or shutil.which("gitleaks")
    commands: list[list[str]]
    if binary:
        _verify_native_version(binary, runner=runner)
        commands = [
            [
                binary,
                "dir",
                str(source),
                "--config",
                str(CONFIG_PATH),
                *_scan_arguments(),
            ]
        ]
        if _has_git_history(source):
            commands.append(
                [
                    binary,
                    "git",
                    str(source),
                    "--log-opts=--all",
                    "--config",
                    str(CONFIG_PATH),
                    *_scan_arguments(),
                ]
            )
        engine = "native"
    elif shutil.which("docker"):
        _verify_container_version(runner=runner)
        container_prefix = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--user",
            "65532:65532",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "-v",
            f"{source}:/scan:ro",
            "-v",
            f"{CONFIG_PATH}:/policy/.gitleaks.toml:ro",
            GITLEAKS_IMAGE,
        ]
        commands = [
            [
                *container_prefix,
                "dir",
                "/scan",
                "--config",
                "/policy/.gitleaks.toml",
                *_scan_arguments(),
            ]
        ]
        if _has_git_history(source):
            commands.append(
                [
                    *container_prefix,
                    "git",
                    "/scan",
                    "--log-opts=--all",
                    "--config",
                    "/policy/.gitleaks.toml",
                    *_scan_arguments(),
                ]
            )
        engine = "container"
    else:
        raise GitleaksExecutionError(
            "Gitleaks requires the pinned native binary or Docker runtime."
        )

    clean = True
    for command in commands:
        completed = _run(command, runner=runner)
        if completed.returncode == 1:
            clean = False
        elif completed.returncode != 0:
            raise GitleaksExecutionError(
                "Gitleaks failed before producing a scan decision."
            )
    return GitleaksScanResult(clean, engine, GITLEAKS_VERSION)


def _has_git_history(source: Path) -> bool:
    # A linked worktree uses a .git file while a normal checkout uses a
    # directory. Both are safe to expose read-only to the pinned scanner.
    return (source / ".git").exists()


def _scan_arguments() -> list[str]:
    return [
        "--no-banner",
        "--redact=100",
        "--no-color",
        "--log-level",
        "error",
        "--max-target-megabytes",
        "10",
    ]


def _verify_native_version(binary: str, *, runner: Runner) -> None:
    completed = _run([binary, "version"], runner=runner)
    if completed.returncode != 0 or completed.stdout.strip() != f"v{GITLEAKS_VERSION}":
        raise GitleaksExecutionError("Gitleaks native version does not match the pin.")


def _verify_container_version(*, runner: Runner) -> None:
    completed = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            GITLEAKS_IMAGE,
            "version",
        ],
        runner=runner,
    )
    if completed.returncode != 0 or completed.stdout.strip() != f"v{GITLEAKS_VERSION}":
        raise GitleaksExecutionError("Gitleaks container version does not match the pin.")


def _run(command: Sequence[str], *, runner: Runner) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=MAX_GITLEAKS_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksExecutionError("Gitleaks process could not be completed.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = run_gitleaks(args.source)
    except GitleaksExecutionError as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":")))
        return 2
    print(
        json.dumps(
            {
                "status": "passed" if result.clean else "failed",
                "engine": result.engine,
                "version": result.version,
            },
            separators=(",", ":"),
        )
    )
    return 0 if result.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
