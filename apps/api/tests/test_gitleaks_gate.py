from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts.ci.run_gitleaks import GITLEAKS_VERSION, run_gitleaks

LIVE_TEST_ENV = "HALLU_DEFENSE_GITLEAKS_LIVE_TEST"

LEAK_FIXTURES = {
    "aws-access-token": "AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH\n",
    "database-dsn": (
        "DATABASE_URL=postgresql://production:SuperSecretPassword99@db.example/prod\n"
    ),
    "signed-jwt": (
        "AUTH_TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6InByb2Qta2V5In0."
        "eyJzdWIiOiJvcGVyYXRvciIsImV4cCI6NDEwMjQ0NDgwMH0."
        "QWERTYUIOPASDFGHJKLZXCVBNM1234567890\n"
    ),
    "credential-synonym": 'client_secret = "M9pK4vT2xR8qW6nL3sJ7"\n',
    "encrypted-private-key": (
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\n"
        "MIIE6TAbBgkqhkiG9w0BBQMwDgQIAAAAAAAAAAACAggA\n"
        "-----END " + "ENCRYPTED PRIVATE KEY-----\n"
    ),
}


def _live_enabled() -> bool:
    return os.getenv(LIVE_TEST_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def test_gitleaks_runner_scans_worktree_and_complete_git_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".git").mkdir()
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, f"v{GITLEAKS_VERSION}\n", "")
        return subprocess.CompletedProcess(
            command,
            1 if command[1] == "git" else 0,
            "",
            "",
        )

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")
    result = run_gitleaks(tmp_path, runner=runner)

    assert result.clean is False
    assert [command[1] for command in commands[1:]] == ["dir", "git"]
    assert "--log-opts=--all" in commands[-1]


def test_gitleaks_runner_uses_snapshot_only_for_non_git_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = f"v{GITLEAKS_VERSION}\n" if command[1:] == ["version"] else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")
    result = run_gitleaks(tmp_path, runner=runner)

    assert result.clean is True
    assert [command[1] for command in commands[1:]] == ["dir"]


@pytest.mark.skipif(not _live_enabled(), reason="real Gitleaks fixture lane is opt-in")
@pytest.mark.parametrize(("fixture_name", "payload"), LEAK_FIXTURES.items())
def test_real_gitleaks_detects_high_risk_fixture(
    tmp_path: Path,
    fixture_name: str,
    payload: str,
) -> None:
    (tmp_path / f"{fixture_name}.txt").write_text(payload, encoding="utf-8")

    result = run_gitleaks(tmp_path)

    assert result.clean is False


@pytest.mark.skipif(not _live_enabled(), reason="real Gitleaks fixture lane is opt-in")
def test_real_gitleaks_accepts_clean_placeholders(tmp_path: Path) -> None:
    (tmp_path / "clean.env.example").write_text(
        "DATABASE_URL=<set-at-runtime>\nAPI_TOKEN=<redacted>\n",
        encoding="utf-8",
    )

    result = run_gitleaks(tmp_path)

    assert result.clean is True
