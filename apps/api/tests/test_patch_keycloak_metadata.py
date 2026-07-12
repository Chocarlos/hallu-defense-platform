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
    for relative_path in patcher.METADATA_PATHS:
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"prefix:" + patcher.LEGACY_NAME + b":suffix")
    library = tmp_path / "lib" / "lib" / "main"
    library.mkdir(parents=True, exist_ok=True)
    corrected = library / patcher.CORRECTED_NAME.decode("ascii")
    corrected.write_bytes(b"corrected-jackson")
    legacy = library / patcher.LEGACY_NAME.decode("ascii")
    legacy.symlink_to(corrected.name)
    monkeypatch.setattr(
        patcher,
        "CORRECTED_SHA256",
        hashlib.sha256(corrected.read_bytes()).hexdigest(),
    )

    patcher.patch_metadata(tmp_path)

    assert not legacy.exists()
    assert not legacy.is_symlink()
    for relative_path in patcher.METADATA_PATHS:
        content = (tmp_path / relative_path).read_bytes()
        assert patcher.LEGACY_NAME not in content
        assert patcher.CORRECTED_NAME in content


def test_patch_keycloak_metadata_rejects_incomplete_model(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="lacks legacy Jackson path"):
        patcher.patch_metadata(tmp_path)
