from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts.ci.secret_scan import ROOT, scan_tree


def _synthetic_secret_assignment(name: str = "api_key") -> str:
    return f'{name} = "' + ("A" * 20) + '"'


def test_secret_scan_detects_potential_secret_assignment(tmp_path: Path) -> None:
    candidate = tmp_path / "settings.py"
    candidate.write_text(_synthetic_secret_assignment(), encoding="utf-8")

    result = scan_tree(tmp_path)

    assert result.findings == ["settings.py"]
    assert result.unreadable == []
    assert result.ok is False


def test_secret_scan_detects_private_key_marker(tmp_path: Path) -> None:
    key_file = tmp_path / "key.pem"
    key_file.write_text(
        "-----BEGIN " + "PRIVATE KEY-----\nredacted-test-only\n",
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)

    assert result.findings == ["key.pem"]


def test_secret_scan_detects_encrypted_private_key_marker(tmp_path: Path) -> None:
    key_file = tmp_path / "encrypted-key.pem"
    key_file.write_text(
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nfixture-body\n",
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)

    assert result.findings == ["encrypted-key.pem"]


def test_secret_scan_does_not_allowlist_directory_categories(tmp_path: Path) -> None:
    for directory in (".venv", "node_modules", ".claude", ".codex-fable-work"):
        skipped_file = tmp_path / directory / "ignored.py"
        skipped_file.parent.mkdir(parents=True)
        skipped_file.write_text(_synthetic_secret_assignment("token"), encoding="utf-8")

    result = scan_tree(tmp_path)

    assert result.findings == [
        ".claude/ignored.py",
        ".codex-fable-work/ignored.py",
        ".venv/ignored.py",
        "node_modules/ignored.py",
    ]


def test_secret_scan_scans_tracked_file_inside_ignored_directory(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "init", "--quiet", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    (tmp_path / ".gitignore").write_text("dist/\n", encoding="utf-8")
    candidate = tmp_path / "dist" / "payload.txt"
    candidate.parent.mkdir()
    candidate.write_text(_synthetic_secret_assignment(), encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "-f", ".gitignore", "dist/payload.txt"],
        check=True,
        capture_output=True,
    )

    result = scan_tree(tmp_path)

    assert result.findings == ["dist/payload.txt"]


def test_secret_scan_fails_closed_for_non_utf8_files(tmp_path: Path) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"\xff\xfe\x00\x00")

    result = scan_tree(tmp_path)

    assert result.unreadable == ["artifact.bin"]
    assert result.ok is False


def test_secret_scan_fails_closed_for_symlinks(tmp_path: Path) -> None:
    target = tmp_path.parent / "external-secret-fixture.txt"
    target.write_text(_synthetic_secret_assignment(), encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    result = scan_tree(tmp_path)

    assert result.unreadable == ["linked.txt"]
    assert result.ok is False


def test_secret_scan_suppresses_only_exact_path_rule_and_match(tmp_path: Path) -> None:
    payload = _synthetic_secret_assignment()
    fixture = tmp_path / "fixture.py"
    fixture.write_text(payload, encoding="utf-8")
    manifest = tmp_path / "fixtures.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "gitleaks-synthetic-fixtures.v1",
                "hash_algorithm": "sha256",
                "fixtures": [],
                "secret_scan_fixtures": [
                    {
                        "path": "fixture.py",
                        "rule_id": "credential-assignment",
                        "match_sha256": hashlib.sha256(payload.encode()).hexdigest(),
                        "purpose": "synthetic exact-match test fixture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert scan_tree(tmp_path, fixture_manifest_path=manifest).ok is True

    copied = tmp_path / "copied.py"
    copied.write_text(payload, encoding="utf-8")
    result = scan_tree(tmp_path, fixture_manifest_path=manifest)

    assert result.findings == ["copied.py"]


def test_secret_scan_does_not_allow_fixture_marker_substrings(tmp_path: Path) -> None:
    candidate = tmp_path / "settings.py"
    candidate.write_text(
        "to" + 'ken = "fixture-but-not-allowlisted"',
        encoding="utf-8",
    )

    result = scan_tree(tmp_path)

    assert result.findings == ["settings.py"]


def test_secret_scan_current_repository_is_clean() -> None:
    result = scan_tree(ROOT)

    assert result.ok is True
