from __future__ import annotations

import subprocess

import pytest

from scripts.ci import python_dependency_audit


def test_python_dependency_audit_command_uses_current_python() -> None:
    command = python_dependency_audit.audit_command("python-test")

    assert command == ["python-test", "-m", "pip_audit", "--progress-spinner", "off"]


def test_python_dependency_audit_reports_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(python_dependency_audit.importlib.util, "find_spec", lambda _module: None)

    assert python_dependency_audit.audit_python_environment("python-test") == 2


def test_python_dependency_audit_returns_pip_audit_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], check: bool) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert check is False
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(
        python_dependency_audit.importlib.util,
        "find_spec",
        lambda _module: object(),
    )
    monkeypatch.setattr(python_dependency_audit.subprocess, "run", fake_run)

    assert python_dependency_audit.audit_python_environment("python-test") == 1
    assert calls == [["python-test", "-m", "pip_audit", "--progress-spinner", "off"]]
