from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.ci import patch_keycloak_metadata as patcher


@pytest.mark.posix
def test_patch_keycloak_metadata_removes_legacy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacements: list[tuple[bytes, bytes, str]] = []
    for index, (legacy_name, corrected_name, _) in enumerate(patcher.REPLACEMENTS):
        corrected_content = f"corrected-{index}".encode()
        replacements.append(
            (
                legacy_name,
                corrected_name,
                hashlib.sha256(corrected_content).hexdigest(),
            )
        )
    for relative_path in patcher.METADATA_PATHS:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b":".join(legacy for legacy, _, _ in replacements))
    library = tmp_path / "lib" / "lib" / "main"
    library.mkdir(parents=True, exist_ok=True)
    for index, (legacy_name, corrected_name, _) in enumerate(replacements):
        corrected = library / corrected_name.decode("ascii")
        corrected.write_bytes(f"corrected-{index}".encode())
        (library / legacy_name.decode("ascii")).symlink_to(corrected.name)
    monkeypatch.setattr(patcher, "REPLACEMENTS", tuple(replacements))

    patcher.patch_metadata(tmp_path)

    for legacy_name, _, _ in replacements:
        legacy = library / legacy_name.decode("ascii")
        assert not legacy.exists()
        assert not legacy.is_symlink()
    for relative_path in patcher.METADATA_PATHS:
        content = (tmp_path / relative_path).read_bytes()
        for legacy_name, corrected_name, _ in replacements:
            assert legacy_name not in content
            assert corrected_name in content


def test_patch_keycloak_metadata_rejects_incomplete_model(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="metadata is missing"):
        patcher.patch_metadata(tmp_path)
