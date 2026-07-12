from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import check_e2e_python_source as mod
from scripts.ci.check_e2e_python_source import (
    PythonSourceMismatchError,
    check_hallu_defense_source_root,
    main,
)

SCRIPT_PATH = Path(mod.__file__)


def test_accepts_module_resolving_under_expected_root(tmp_path: Path) -> None:
    expected_root = tmp_path / "apps" / "api" / "src"
    module_file = expected_root / "hallu_defense" / "__init__.py"
    module_file.parent.mkdir(parents=True)
    fake_module = SimpleNamespace(__file__=str(module_file))

    resolved = check_hallu_defense_source_root(str(expected_root), module=fake_module)

    assert Path(resolved) == module_file.resolve()


def test_rejects_module_resolving_outside_expected_root(tmp_path: Path) -> None:
    expected_root = tmp_path / "apps" / "api" / "src"
    other_checkout = tmp_path / "other-checkout" / "apps" / "api" / "src"
    module_file = other_checkout / "hallu_defense" / "__init__.py"
    expected_root.mkdir(parents=True)
    fake_module = SimpleNamespace(__file__=str(module_file))

    with pytest.raises(PythonSourceMismatchError, match="outside the expected worktree"):
        check_hallu_defense_source_root(str(expected_root), module=fake_module)


def test_rejects_module_without_file_attribute(tmp_path: Path) -> None:
    expected_root = tmp_path / "apps" / "api" / "src"
    expected_root.mkdir(parents=True)
    fake_module = SimpleNamespace()

    with pytest.raises(PythonSourceMismatchError, match="__file__ is unavailable"):
        check_hallu_defense_source_root(str(expected_root), module=fake_module)


def test_main_reports_usage_error_without_exactly_one_argument() -> None:
    assert main([]) == 2
    assert main(["a", "b"]) == 2


def test_rejects_a_relative_expected_source_root() -> None:
    with pytest.raises(PythonSourceMismatchError, match="must be absolute"):
        check_hallu_defense_source_root("apps/api/src")


def test_main_returns_error_for_an_unrelated_expected_root(tmp_path: Path) -> None:
    # Whatever hallu_defense this pytest process already has on sys.path
    # (this repository's real package, per apps/api/pyproject.toml's
    # `pythonpath = ["src"]`), it cannot resolve under an unrelated tmp_path,
    # so this must fail closed either on import or on mismatch.
    assert main([str(tmp_path)]) == 1


def test_cli_end_to_end_accepts_matching_source_root(tmp_path: Path) -> None:
    src_root = tmp_path / "fake-worktree" / "apps" / "api" / "src"
    package_dir = src_root / "hallu_defense"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(src_root)],
        cwd=tmp_path,
        env=_subprocess_env(str(src_root)),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "resolved correctly" in completed.stdout


def test_cli_end_to_end_rejects_mismatched_source_root(tmp_path: Path) -> None:
    src_root = tmp_path / "fake-worktree" / "apps" / "api" / "src"
    package_dir = src_root / "hallu_defense"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    unrelated_root = tmp_path / "unrelated-checkout" / "apps" / "api" / "src"
    unrelated_root.mkdir(parents=True)

    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(unrelated_root)],
        cwd=tmp_path,
        env=_subprocess_env(str(src_root)),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "outside the expected worktree source root" in completed.stderr


def _subprocess_env(python_path: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = python_path
    return env
