from __future__ import annotations

from pathlib import Path

from scripts.ci.secret_scan import ROOT, scan_tree, should_skip


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


def test_secret_scan_skips_generated_and_local_tooling_dirs(tmp_path: Path) -> None:
    for directory in (".venv", "node_modules", ".claude", ".codex-fable-work"):
        skipped_file = tmp_path / directory / "ignored.py"
        skipped_file.parent.mkdir(parents=True)
        skipped_file.write_text(_synthetic_secret_assignment("token"), encoding="utf-8")

    result = scan_tree(tmp_path)

    assert result.ok is True
    assert should_skip(Path(".claude") / "worktrees" / "agent" / "ignored.py") is True


def test_secret_scan_skips_lockfiles_and_binary_files(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(_synthetic_secret_assignment("password"), encoding="utf-8")
    (tmp_path / "artifact.bin").write_bytes(b"\xff\xfe\x00\x00")

    result = scan_tree(tmp_path)

    assert result.ok is True


def test_secret_scan_current_repository_is_clean() -> None:
    result = scan_tree(ROOT)

    assert result.ok is True
