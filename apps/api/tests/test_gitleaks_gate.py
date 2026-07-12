from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts.ci.check_gitleaks_config import (
    GitleaksConfigError,
    validate_gitleaks_config,
)
from scripts.ci.run_gitleaks import (
    CONFIG_PATH,
    GITLEAKS_VERSION,
    ROOT,
    GitleaksExecutionError,
    load_fixture_fingerprints,
    run_gitleaks,
)

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


def _write_manifest(
    path: Path,
    *,
    fixtures: list[dict[str, str]] | None = None,
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "gitleaks-synthetic-fixtures.v1",
                "hash_algorithm": "sha256",
                "fixtures": fixtures or [],
                "secret_scan_fixtures": [],
            }
        ),
        encoding="utf-8",
    )


def _write_report(command: list[str], findings: list[dict[str, str]]) -> None:
    report_path = Path(command[command.index("--report-path") + 1])
    report_path.write_text(json.dumps(findings), encoding="utf-8")


def test_gitleaks_runner_scans_worktree_and_complete_git_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(
        ["git", "init", "--quiet", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, f"{GITLEAKS_VERSION}\n", "")
        findings: list[dict[str, str]] = []
        if command[1] == "git":
            findings = [
                {
                    "File": "history.env",
                    "RuleID": "generic-api-key",
                    "Match": "api_key=synthetic-history-value",
                }
            ]
        _write_report(command, findings)
        return subprocess.CompletedProcess(
            command,
            1 if findings else 0,
            "",
            "",
        )

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")
    result = run_gitleaks(tmp_path, runner=runner)

    assert result.clean is False
    assert [command[1] for command in commands[1:]] == ["dir", "git"]
    assert "--log-opts=--all" in commands[-1]
    assert all("--max-target-megabytes" not in command for command in commands)


def test_gitleaks_runner_uses_snapshot_only_for_non_git_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = f"{GITLEAKS_VERSION}\n" if command[1:] == ["version"] else ""
        if command[1:] != ["version"]:
            _write_report(command, [])
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")
    result = run_gitleaks(tmp_path, runner=runner)

    assert result.clean is True
    assert [command[1] for command in commands[1:]] == ["dir"]


def test_gitleaks_docker_fallback_rejects_linked_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".git").write_text("gitdir: C:/outside/worktrees/fixture", encoding="utf-8")
    monkeypatch.delenv("GITLEAKS_BINARY", raising=False)
    monkeypatch.setattr(
        "scripts.ci.run_gitleaks.shutil.which",
        lambda name: "docker" if name == "docker" else None,
    )

    with pytest.raises(GitleaksExecutionError, match="linked-worktree Git metadata"):
        run_gitleaks(tmp_path)


def test_gitleaks_runner_suppresses_only_exact_synthetic_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    manifest = tmp_path / "fixtures.json"
    match = 'client_secret = "synthetic-value-1234"'
    _write_manifest(
        manifest,
        fixtures=[
            {
                "path": "fixture.py",
                "rule_id": "credential-assignment",
                "match_sha256": hashlib.sha256(match.encode()).hexdigest(),
                "purpose": "synthetic exact-match test fixture",
            }
        ],
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, f"{GITLEAKS_VERSION}\n", "")
        _write_report(
            command,
            [
                {
                    "File": "fixture.py",
                    "RuleID": "credential-assignment",
                    "Match": match,
                }
            ],
        )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")

    assert run_gitleaks(source, runner=runner, fixture_manifest_path=manifest).clean is True


@pytest.mark.parametrize(
    ("finding_path", "rule_id", "match_suffix"),
    (
        ("not-the-fixture.py", "credential-assignment", ""),
        ("fixture.py", "generic-api-key", ""),
        ("fixture.py", "credential-assignment", "-modified"),
    ),
)
def test_gitleaks_runner_rejects_any_fingerprint_dimension_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    finding_path: str,
    rule_id: str,
    match_suffix: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    manifest = tmp_path / "fixtures.json"
    match = 'client_secret = "synthetic-value-1234"'
    _write_manifest(
        manifest,
        fixtures=[
            {
                "path": "fixture.py",
                "rule_id": "credential-assignment",
                "match_sha256": hashlib.sha256(match.encode()).hexdigest(),
                "purpose": "synthetic exact-match test fixture",
            }
        ],
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, f"{GITLEAKS_VERSION}\n", "")
        _write_report(
            command,
            [
                {
                    "File": finding_path,
                    "RuleID": rule_id,
                    "Match": f"{match}{match_suffix}",
                }
            ],
        )
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setenv("GITLEAKS_BINARY", "gitleaks")

    assert run_gitleaks(source, runner=runner, fixture_manifest_path=manifest).clean is False


def test_fixture_manifest_rejects_path_patterns(tmp_path: Path) -> None:
    manifest = tmp_path / "fixtures.json"
    _write_manifest(
        manifest,
        fixtures=[
            {
                "path": "apps/**/tests",
                "rule_id": "credential-assignment",
                "match_sha256": "0" * 64,
                "purpose": "invalid broad fixture",
            }
        ],
    )

    with pytest.raises(GitleaksExecutionError, match="exact relative path"):
        load_fixture_fingerprints("fixtures", manifest_path=manifest)


def test_gitleaks_config_rejects_toml_allowlists() -> None:
    with pytest.raises(GitleaksConfigError, match="must not contain.*allowlists"):
        validate_gitleaks_config(
            config_text=(
                CONFIG_PATH.read_text(encoding="utf-8")
                + "\n[[allowlists]]\npaths = ['apps/api/tests/']\n"
            ),
            runner_text=(ROOT / "scripts/ci/run_gitleaks.py").read_text(encoding="utf-8"),
            test_text=Path(__file__).read_text(encoding="utf-8"),
            makefile_text=(ROOT / "Makefile").read_text(encoding="utf-8"),
            ci_workflow_text=(ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
            security_workflow_text=(ROOT / ".github/workflows/security.yml").read_text(
                encoding="utf-8"
            ),
        )


@pytest.mark.live
@pytest.mark.parametrize(("fixture_name", "payload"), LEAK_FIXTURES.items())
def test_real_gitleaks_detects_high_risk_fixture(
    tmp_path: Path,
    fixture_name: str,
    payload: str,
) -> None:
    (tmp_path / f"{fixture_name}.txt").write_text(payload, encoding="utf-8")

    result = run_gitleaks(tmp_path)

    assert result.clean is False


@pytest.mark.live
def test_real_gitleaks_accepts_clean_placeholders(tmp_path: Path) -> None:
    (tmp_path / "clean.env.example").write_text(
        "DATABASE_URL=<set-at-runtime>\nAPI_TOKEN=<redacted>\n",
        encoding="utf-8",
    )

    result = run_gitleaks(tmp_path)

    assert result.clean is True
