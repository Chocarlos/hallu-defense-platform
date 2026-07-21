from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / ".gitleaks.toml"
FIXTURE_MANIFEST_PATH = ROOT / "requirements" / "gitleaks-synthetic-fixtures.json"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks@"
    "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)
GITLEAKS_LINUX_X64_SHA256 = (
    "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
)
MAX_GITLEAKS_SECONDS = 180
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
RULE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
MANIFEST_SECTIONS = frozenset({"fixtures", "secret_scan_fixtures"})

Runner = Callable[..., subprocess.CompletedProcess[str]]


class GitleaksExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class FixtureFingerprint:
    path: str
    rule_id: str
    match_sha256: str


@dataclass(frozen=True)
class GitleaksScanResult:
    clean: bool
    engine: str
    version: str


def load_fixture_fingerprints(
    section: str,
    *,
    manifest_path: Path = FIXTURE_MANIFEST_PATH,
) -> frozenset[FixtureFingerprint]:
    """Load exact, non-pattern fixture suppressions from the committed manifest."""
    if section not in MANIFEST_SECTIONS:
        raise GitleaksExecutionError("Unknown synthetic fixture manifest section.")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise GitleaksExecutionError(
            "The synthetic fixture fingerprint manifest is unavailable or invalid."
        ) from None
    expected_keys = {"schema_version", "hash_algorithm", *MANIFEST_SECTIONS}
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise GitleaksExecutionError(
            "The synthetic fixture fingerprint manifest has unexpected fields."
        )
    if payload.get("schema_version") != "gitleaks-synthetic-fixtures.v1":
        raise GitleaksExecutionError(
            "The synthetic fixture fingerprint manifest schema is unsupported."
        )
    if payload.get("hash_algorithm") != "sha256":
        raise GitleaksExecutionError(
            "The synthetic fixture fingerprint manifest must use SHA-256."
        )
    entries = payload.get(section)
    if not isinstance(entries, list):
        raise GitleaksExecutionError(
            "The synthetic fixture fingerprint manifest section must be an array."
        )

    fingerprints: set[FixtureFingerprint] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "rule_id",
            "match_sha256",
            "purpose",
        }:
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} has unexpected fields."
            )
        path = entry.get("path")
        rule_id = entry.get("rule_id")
        match_sha256 = entry.get("match_sha256")
        purpose = entry.get("purpose")
        if not isinstance(path, str) or not _is_exact_relative_path(path):
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} must use one exact relative path."
            )
        if not isinstance(rule_id, str) or RULE_ID_RE.fullmatch(rule_id) is None:
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} has an invalid exact rule id."
            )
        if (
            not isinstance(match_sha256, str)
            or FINGERPRINT_RE.fullmatch(match_sha256) is None
        ):
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} has an invalid SHA-256 fingerprint."
            )
        if not isinstance(purpose, str) or not purpose.strip():
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} must document its synthetic purpose."
            )
        fingerprint = FixtureFingerprint(path, rule_id, match_sha256)
        if fingerprint in fingerprints:
            raise GitleaksExecutionError(
                f"Synthetic fixture entry {index} duplicates an exact fingerprint."
            )
        fingerprints.add(fingerprint)
    return frozenset(fingerprints)


def run_gitleaks(
    source: Path = ROOT,
    *,
    runner: Runner = subprocess.run,
    fixture_manifest_path: Path = FIXTURE_MANIFEST_PATH,
) -> GitleaksScanResult:
    source = source.resolve()
    if not source.is_dir():
        raise GitleaksExecutionError("Gitleaks source must be an existing directory.")
    if not CONFIG_PATH.is_file():
        raise GitleaksExecutionError("The committed Gitleaks config is unavailable.")
    fixture_fingerprints = load_fixture_fingerprints(
        "fixtures",
        manifest_path=fixture_manifest_path,
    )

    configured_binary = os.getenv("GITLEAKS_BINARY", "").strip()
    binary = configured_binary or shutil.which("gitleaks")
    with tempfile.TemporaryDirectory(prefix="hallu-gitleaks-") as temporary:
        report_root = Path(temporary)
        commands: list[tuple[list[str], Path, Path]]
        if binary:
            _verify_native_version(binary, runner=runner)
            snapshot_source = _prepare_snapshot_source(source, report_root / "snapshot")
            commands = _native_commands(
                binary,
                source,
                snapshot_source,
                report_root,
            )
            engine = "native"
        elif shutil.which("docker"):
            if (source / ".git").is_file():
                raise GitleaksExecutionError(
                    "The Docker fallback cannot safely resolve linked-worktree Git "
                    "metadata; install the pinned native Gitleaks binary."
                )
            _verify_container_version(runner=runner)
            snapshot_source = _prepare_snapshot_source(source, report_root / "snapshot")
            commands = _container_commands(source, snapshot_source, report_root)
            engine = "container"
        else:
            raise GitleaksExecutionError(
                "Gitleaks requires the pinned native binary or Docker runtime."
            )

        clean = True
        for command, report_path, finding_source in commands:
            completed = _run(command, runner=runner)
            if completed.returncode not in (0, 1):
                raise GitleaksExecutionError(
                    "Gitleaks failed before producing a scan decision."
                )
            findings = _load_report(
                report_path, findings_expected=completed.returncode == 1
            )
            for finding in findings:
                fingerprint = _finding_fingerprint(finding, source=finding_source)
                if fingerprint not in fixture_fingerprints:
                    clean = False
        return GitleaksScanResult(clean, engine, GITLEAKS_VERSION)


def _native_commands(
    binary: str,
    source: Path,
    snapshot_source: Path,
    report_root: Path,
) -> list[tuple[list[str], Path, Path]]:
    snapshot_report = report_root / "snapshot.json"
    commands = [
        (
            [
                binary,
                "dir",
                str(snapshot_source),
                "--config",
                str(CONFIG_PATH),
                *_scan_arguments(str(snapshot_report)),
            ],
            snapshot_report,
            snapshot_source,
        )
    ]
    if _has_git_history(source):
        history_report = report_root / "history.json"
        commands.append(
            (
                [
                    binary,
                    "git",
                    str(source),
                    "--log-opts=--all",
                    "--config",
                    str(CONFIG_PATH),
                    *_scan_arguments(str(history_report)),
                ],
                history_report,
                source,
            )
        )
    return commands


def _container_commands(
    source: Path,
    snapshot_source: Path,
    report_root: Path,
) -> list[tuple[list[str], Path, Path]]:
    snapshot_report = report_root / "snapshot.json"
    snapshot_report.write_text("[]", encoding="utf-8")
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    container_user = (
        ["--user", f"{getuid()}:{getgid()}"]
        if callable(getuid) and callable(getgid)
        else []
    )
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
        *container_user,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "-v",
        f"{snapshot_source}:/scan:ro",
        "-v",
        f"{CONFIG_PATH}:/policy/.gitleaks.toml:ro",
        "-v",
        f"{report_root}:/reports:rw",
        GITLEAKS_IMAGE,
    ]
    commands = [
        (
            [
                *container_prefix,
                "dir",
                "/scan",
                "--config",
                "/policy/.gitleaks.toml",
                *_scan_arguments("/reports/snapshot.json"),
            ],
            snapshot_report,
            snapshot_source,
        )
    ]
    if _has_git_history(source):
        history_report = report_root / "history.json"
        history_report.write_text("[]", encoding="utf-8")
        history_prefix = list(container_prefix)
        source_mount_index = history_prefix.index(f"{snapshot_source}:/scan:ro")
        history_prefix[source_mount_index] = f"{source}:/scan:ro"
        commands.append(
            (
                [
                    *history_prefix,
                    "git",
                    "/scan",
                    "--log-opts=--all",
                    "--config",
                    "/policy/.gitleaks.toml",
                    *_scan_arguments("/reports/history.json"),
                ],
                history_report,
                source,
            )
        )
    return commands


def _prepare_snapshot_source(source: Path, destination: Path) -> Path:
    """Mirror only tracked and non-ignored untracked files for the dir scan."""
    if not _has_git_history(source):
        return source
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise GitleaksExecutionError(
            "Git could not enumerate the worktree snapshot for Gitleaks."
        ) from None
    if completed.returncode != 0:
        raise GitleaksExecutionError(
            "Git could not enumerate the worktree snapshot for Gitleaks."
        )
    destination.mkdir(parents=True)
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            relative = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            raise GitleaksExecutionError(
                "Git returned a non-UTF-8 worktree path for Gitleaks."
            ) from None
        if not _is_safe_relative_path(relative):
            raise GitleaksExecutionError(
                "Git returned an unsafe worktree path for Gitleaks."
            )
        parts = PurePosixPath(relative).parts
        source_path = source.joinpath(*parts)
        target_path = destination.joinpath(*parts)
        if not source_path.exists() and not source_path.is_symlink():
            # A tracked deletion has no current bytes to inspect.
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path.is_symlink():
            try:
                target_path.write_text(os.readlink(source_path), encoding="utf-8")
            except (OSError, UnicodeError):
                raise GitleaksExecutionError(
                    "A worktree symlink could not be mirrored safely for Gitleaks."
                ) from None
            continue
        try:
            resolved_source = source_path.resolve(strict=True)
            resolved_source.relative_to(source)
        except (OSError, ValueError):
            raise GitleaksExecutionError(
                "A worktree file resolves outside the Gitleaks source."
            ) from None
        if not resolved_source.is_file():
            raise GitleaksExecutionError(
                "Git enumerated a non-file worktree entry for Gitleaks."
            )
        try:
            shutil.copyfile(resolved_source, target_path)
        except OSError:
            raise GitleaksExecutionError(
                "A worktree file could not be mirrored for Gitleaks."
            ) from None
    return destination


def _has_git_history(source: Path) -> bool:
    # A linked worktree uses a .git file while a normal checkout uses a
    # directory. Both must receive the full --all history scan.
    return (source / ".git").exists()


def _scan_arguments(report_path: str) -> list[str]:
    # Redaction also mutates JSON Match, so exact fixture hashing requires the
    # unredacted private temp report. Process output is captured and errors are
    # deliberately generic; finding values are never written to CI logs.
    return [
        "--no-banner",
        "--no-color",
        "--ignore-gitleaks-allow",
        "--log-level",
        "error",
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--exit-code",
        "1",
    ]


def _load_report(
    report_path: Path,
    *,
    findings_expected: bool,
) -> list[dict[str, object]]:
    if not report_path.is_file():
        if findings_expected:
            raise GitleaksExecutionError(
                "Gitleaks reported findings without producing its private report."
            )
        return []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise GitleaksExecutionError(
            "Gitleaks produced an invalid private report."
        ) from None
    if not isinstance(report, list) or not all(
        isinstance(item, dict) for item in report
    ):
        raise GitleaksExecutionError("Gitleaks produced an invalid private report.")
    if findings_expected and not report:
        raise GitleaksExecutionError(
            "Gitleaks returned a finding status with an empty private report."
        )
    return report


def _finding_fingerprint(
    finding: dict[str, object],
    *,
    source: Path,
) -> FixtureFingerprint:
    raw_path = finding.get("File")
    rule_id = finding.get("RuleID")
    match = finding.get("Match")
    if (
        not isinstance(raw_path, str)
        or not isinstance(rule_id, str)
        or not isinstance(match, str)
    ):
        raise GitleaksExecutionError("Gitleaks produced an incomplete private finding.")
    path = _normalize_finding_path(raw_path, source=source)
    if path is None or RULE_ID_RE.fullmatch(rule_id) is None:
        raise GitleaksExecutionError("Gitleaks produced an invalid private finding.")
    return FixtureFingerprint(
        path=path,
        rule_id=rule_id,
        match_sha256=hashlib.sha256(match.encode("utf-8")).hexdigest(),
    )


def _normalize_finding_path(raw_path: str, *, source: Path) -> str | None:
    normalized = raw_path.replace("\\", "/")
    if normalized == "/scan":
        return None
    if normalized.startswith("/scan/"):
        normalized = normalized.removeprefix("/scan/")
    candidate = Path(normalized)
    if candidate.is_absolute():
        try:
            resolved_candidate = _resolve_existing_path(candidate)
            resolved_source = _resolve_existing_path(source)
            return resolved_candidate.relative_to(resolved_source).as_posix()
        except (OSError, ValueError):
            return None
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return None
    path = PurePosixPath(normalized)
    if not _is_safe_relative_path(path.as_posix()):
        return None
    return path.as_posix()


def _resolve_existing_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if os.name != "nt":
        return resolved
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    required = kernel32.GetLongPathNameW(str(resolved), None, 0)
    if required == 0:
        raise OSError("Windows could not canonicalize a Gitleaks path.")
    buffer = ctypes.create_unicode_buffer(required)
    written = kernel32.GetLongPathNameW(str(resolved), buffer, required)
    if written == 0 or written >= required:
        raise OSError("Windows could not canonicalize a Gitleaks path.")
    return Path(buffer.value).resolve(strict=True)


def _is_exact_relative_path(value: str) -> bool:
    if any(character in value for character in "*?"):
        return False
    return _is_safe_relative_path(value)


def _is_safe_relative_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _verify_native_version(binary: str, *, runner: Runner) -> None:
    completed = _run([binary, "version"], runner=runner)
    if completed.returncode != 0 or completed.stdout.strip() != GITLEAKS_VERSION:
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
    reported_version = completed.stdout.strip().removeprefix("v")
    if completed.returncode != 0 or reported_version != GITLEAKS_VERSION:
        raise GitleaksExecutionError(
            "Gitleaks container version does not match the pin."
        )


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
        raise GitleaksExecutionError(
            "Gitleaks process could not be completed."
        ) from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = run_gitleaks(args.source)
    except GitleaksExecutionError as exc:
        print(
            json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":"))
        )
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
