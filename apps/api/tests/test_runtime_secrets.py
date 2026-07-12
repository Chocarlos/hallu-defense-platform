from __future__ import annotations

import os
from pathlib import Path

import pytest

import hallu_defense.runtime_secrets as runtime_secrets

from hallu_defense.runtime_secrets import (
    MAX_RUNTIME_SECRET_BYTES,
    RuntimeSecretError,
    load_runtime_secret,
    read_runtime_secret_file,
)


def _secret_file(tmp_path: Path, value: bytes = b"secret-value\n") -> Path:
    path = tmp_path / "runtime-secret"
    path.write_bytes(value)
    os.chmod(path, 0o440)
    return path


def test_runtime_secret_file_is_bounded_and_newline_trimmed(tmp_path: Path) -> None:
    path = _secret_file(tmp_path)

    assert read_runtime_secret_file(str(path), variable_name="SECRET_FILE") == "secret-value"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b" two-lines\n",
        b"first\nsecond",
        b"nul\x00byte",
        b"\xff",
        b"x" * (MAX_RUNTIME_SECRET_BYTES + 1),
    ],
    ids=["empty", "leading-space", "multiline", "nul", "invalid-utf8", "oversize"],
)
def test_runtime_secret_file_rejects_unsafe_payloads(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = _secret_file(tmp_path, payload)

    with pytest.raises(RuntimeSecretError):
        read_runtime_secret_file(str(path), variable_name="SECRET_FILE")


@pytest.mark.parametrize("mode", [0o660, 0o444, 0o640, 0o550])
@pytest.mark.posix
def test_runtime_secret_file_rejects_unsafe_permissions(
    tmp_path: Path,
    mode: int,
) -> None:
    path = _secret_file(tmp_path)
    os.chmod(path, mode)

    with pytest.raises(RuntimeSecretError, match="0400 or 0440"):
        read_runtime_secret_file(str(path), variable_name="SECRET_FILE")


def test_runtime_secret_env_and_file_are_mutually_exclusive(tmp_path: Path) -> None:
    path = _secret_file(tmp_path)

    with pytest.raises(RuntimeSecretError, match="mutually exclusive"):
        load_runtime_secret(
            {"VALUE": "inline", "VALUE_FILE": str(path)},
            value_variable="VALUE",
            file_variable="VALUE_FILE",
        )


def test_runtime_secret_loads_file_without_exposing_value_in_error(tmp_path: Path) -> None:
    path = _secret_file(tmp_path, b"highly-sensitive-value\n")

    assert (
        load_runtime_secret(
            {"VALUE_FILE": str(path)},
            value_variable="VALUE",
            file_variable="VALUE_FILE",
        )
        == "highly-sensitive-value"
    )


@pytest.mark.posix
def test_runtime_secret_rejects_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _secret_file(tmp_path)
    link = tmp_path / "runtime-secret-link"
    link.symlink_to(target)
    monkeypatch.setattr(runtime_secrets, "_is_root_owned", lambda _metadata: True)

    with pytest.raises(RuntimeSecretError, match="regular file or a Kubernetes projected"):
        read_runtime_secret_file(str(link), variable_name="SECRET_FILE")


@pytest.mark.posix
def test_runtime_secret_accepts_read_only_kubernetes_projected_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount = tmp_path / "projected"
    version = mount / "..2026_07_10_12_00_00.000000001"
    version.mkdir(parents=True)
    target = version / "vault-token"
    target.write_text("projected-secret\n", encoding="utf-8")
    os.chmod(target, 0o440)
    (mount / "..data").symlink_to(version.name, target_is_directory=True)
    (mount / "vault-token").symlink_to("..data/vault-token")
    monkeypatch.setattr(runtime_secrets, "_is_root_owned", lambda _metadata: True)
    monkeypatch.setattr(
        runtime_secrets,
        "_path_is_on_read_only_mount",
        lambda _path: True,
    )

    assert (
        read_runtime_secret_file(
            str(mount / "vault-token"),
            variable_name="SECRET_FILE",
        )
        == "projected-secret"
    )


@pytest.mark.posix
def test_runtime_secret_rejects_projected_layout_on_writable_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount = tmp_path / "projected"
    version = mount / "..2026_07_10_12_00_00.000000001"
    version.mkdir(parents=True)
    target = version / "vault-token"
    target.write_text("projected-secret\n", encoding="utf-8")
    os.chmod(target, 0o440)
    (mount / "..data").symlink_to(version.name, target_is_directory=True)
    (mount / "vault-token").symlink_to("..data/vault-token")
    monkeypatch.setattr(runtime_secrets, "_is_root_owned", lambda _metadata: True)
    monkeypatch.setattr(
        runtime_secrets,
        "_path_is_on_read_only_mount",
        lambda _path: False,
    )

    with pytest.raises(RuntimeSecretError, match="read-only mount"):
        read_runtime_secret_file(
            str(mount / "vault-token"),
            variable_name="SECRET_FILE",
        )
