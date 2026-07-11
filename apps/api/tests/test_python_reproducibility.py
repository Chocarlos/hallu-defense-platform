from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import build_reproducible_wheel as wheel_builder
from scripts.ci import check_python_reproducibility as reproducibility
from scripts.ci import compile_python_locks as lock_compiler
from scripts.ci import install_python_lock as lock_installer


def test_hashed_lock_parser_accepts_only_exact_hashed_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reproducibility, "ROOT", tmp_path)
    lock_path = tmp_path / "valid.lock"
    lock_path.write_text(
        "demo-package==1.2.3 \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n"
        "other.package==4.5.6 \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n",
        encoding="utf-8",
    )

    parsed = reproducibility.parse_hashed_lock(lock_path)

    assert set(parsed) == {"demo-package", "other-package"}
    assert parsed["demo-package"].version == "1.2.3"
    assert parsed["demo-package"].hashes == ("a" * 64,)


def test_hashed_lock_parser_rejects_unhashed_and_duplicated_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reproducibility, "ROOT", tmp_path)
    lock_path = tmp_path / "invalid.lock"
    lock_path.write_text(
        "demo==1.0 \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n"
        "demo==1.0 \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
        "unhashed==2.0 \\\n",
        encoding="utf-8",
    )

    with pytest.raises(
        reproducibility.ReproducibilityConfigError,
        match="duplicates demo|has no SHA-256 hash",
    ):
        reproducibility.parse_hashed_lock(lock_path)


def test_lock_check_seeds_existing_lock_without_implicit_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "requirements.in"
    output = tmp_path / "runtime.lock"
    source.write_text("demo>=1\n", encoding="utf-8")
    output.write_text("demo==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    target = lock_compiler.LockTarget(output=output, source=source)
    observed_commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        observed_commands.append(command)
        output_argument = next(item for item in command if item.startswith("--output-file="))
        temporary_output = Path(output_argument.partition("=")[2])
        assert temporary_output.read_bytes() == output.read_bytes()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(lock_compiler, "ROOT", tmp_path)
    monkeypatch.setattr(lock_compiler, "LOCK_TARGETS", (target,))
    monkeypatch.setattr(lock_compiler, "validate_lock_toolchain", lambda: None)
    monkeypatch.setattr(lock_compiler.subprocess, "run", fake_run)

    assert lock_compiler.compile_locks(check=True) == []
    assert len(observed_commands) == 1
    assert "--upgrade" not in observed_commands[0]


def test_lock_installer_rejects_non_linux_or_wrong_patch_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lock_installer.sys, "version_info", (3, 12, 12))
    with pytest.raises(lock_installer.LockTargetError, match="exactly Python 3.12.13"):
        lock_installer.validate_lock_target()

    monkeypatch.setattr(lock_installer.sys, "version_info", (3, 12, 13))
    monkeypatch.setattr(lock_installer.sys, "platform", "win32")
    with pytest.raises(lock_installer.LockTargetError, match="target Linux"):
        lock_installer.validate_lock_target()


def test_repeated_wheel_build_rejects_byte_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = 0

    def fake_build_once(output_dir: Path) -> Path:
        nonlocal call_count
        call_count += 1
        wheel = output_dir / "demo-1.0-py3-none-any.whl"
        wheel.write_bytes(f"wheel-{call_count}".encode())
        return wheel

    monkeypatch.setattr(wheel_builder, "validate_build_environment", lambda: None)
    monkeypatch.setattr(wheel_builder, "_build_once", fake_build_once)

    with pytest.raises(
        wheel_builder.ReproducibleWheelError,
        match="not byte-for-byte reproducible",
    ):
        wheel_builder.build_and_verify(tmp_path / "dist")


@pytest.mark.parametrize(
    ("package_mutation", "npmrc", "expected"),
    (
        (
            {"allowScripts": {"sharp": True}},
            "ignore-scripts=true\nstrict-allow-scripts=true",
            "install script",
        ),
        (
            {"packageManager": "npm@latest"},
            "ignore-scripts=true\nstrict-allow-scripts=true",
            "packageManager",
        ),
        ({}, "ignore-scripts=false\nstrict-allow-scripts=true", "fail closed"),
        ({}, "strict-allow-scripts=true", "fail closed"),
        ({}, "strict-allow-scripts=false", "fail closed"),
    ),
)
def test_node_reproducibility_rejects_npm_policy_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_mutation: dict[str, object],
    npmrc: str,
    expected: str,
) -> None:
    package = json.loads(reproducibility.PACKAGE_JSON_PATH.read_text(encoding="utf-8"))
    package.update(package_mutation)
    package_path = tmp_path / "package.json"
    package_path.write_text(json.dumps(package), encoding="utf-8")
    npmrc_path = tmp_path / ".npmrc"
    npmrc_path.write_text(npmrc, encoding="utf-8")
    monkeypatch.setattr(reproducibility, "PACKAGE_JSON_PATH", package_path)
    monkeypatch.setattr(reproducibility, "NPMRC_PATH", npmrc_path)
    errors: list[str] = []

    reproducibility._validate_node_reproducibility(errors)

    assert any(expected in error for error in errors)
