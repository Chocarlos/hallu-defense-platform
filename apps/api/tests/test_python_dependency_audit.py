from __future__ import annotations

import subprocess

import pytest

from scripts.ci import python_dependency_audit


def test_python_dependency_audit_command_uses_current_python() -> None:
    command = python_dependency_audit.audit_command("python-test")

    assert command[:3] == ["python-test", "-m", "pip_audit"]
    assert "--requirement" in command
    assert str(python_dependency_audit.RUNTIME_LOCK) in command
    assert "--disable-pip" in command


def test_python_dependency_audit_inventory_covers_every_exact_lock() -> None:
    assert dict(python_dependency_audit.AUDIT_LOCKS) == {
        "runtime": python_dependency_audit.RUNTIME_LOCK,
        "dev": python_dependency_audit.DEV_LOCK,
        "build-tools": python_dependency_audit.BUILD_TOOLS_LOCK,
        "sandbox": python_dependency_audit.SANDBOX_LOCK,
    }


def test_python_dependency_audit_reports_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(python_dependency_audit.importlib.util, "find_spec", lambda _module: None)

    assert python_dependency_audit.audit_python_environment("python-test") == 2


def test_python_dependency_audit_returns_pip_audit_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        cwd: object,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert cwd == python_dependency_audit.ROOT
        assert check is False
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(
        python_dependency_audit.importlib.util,
        "find_spec",
        lambda _module: object(),
    )
    monkeypatch.setattr(python_dependency_audit.subprocess, "run", fake_run)

    assert python_dependency_audit.audit_python_environment("python-test") == 1
    assert calls == [
        python_dependency_audit.audit_command("python-test", lock_path=lock_path)
        for _label, lock_path in python_dependency_audit.AUDIT_LOCKS
    ]


def test_python_dependency_audit_runs_all_locks_after_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        cwd: object,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, check
        calls.append(command)
        return subprocess.CompletedProcess(command, 1 if len(calls) == 1 else 0)

    monkeypatch.setattr(
        python_dependency_audit.importlib.util,
        "find_spec",
        lambda _module: object(),
    )
    monkeypatch.setattr(python_dependency_audit.subprocess, "run", fake_run)

    assert python_dependency_audit.audit_python_environment("python-test") == 1
    assert len(calls) == len(python_dependency_audit.AUDIT_LOCKS)
