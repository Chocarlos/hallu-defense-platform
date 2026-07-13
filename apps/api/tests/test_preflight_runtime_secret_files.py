from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import scripts.dev.preflight_runtime_secret_files as preflight


def _environment(tmp_path: Path) -> dict[str, str]:
    return {
        name: str((tmp_path / f"secret-{index}").resolve())
        for index, name in enumerate(preflight.SECRET_FILE_ENVIRONMENTS)
    }


def _metadata(*, mode: int = 0o440, uid: int = 0, gid: int = 10001) -> os.stat_result:
    return os.stat_result((stat.S_IFREG | mode, 0, 0, 1, uid, gid, 12, 0, 0, 0))


def _directory_metadata(*, mode: int = 0o750, uid: int = 0, gid: int = 10001) -> os.stat_result:
    return os.stat_result((stat.S_IFDIR | mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


def _safe_lstat(path: Path, *, secret_parent: Path) -> os.stat_result:
    if path == secret_parent:
        return _directory_metadata()
    if path.name.startswith("secret-"):
        return _metadata()
    return _directory_metadata(mode=0o755, gid=0)


def test_preflight_requires_root_owned_group_readable_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: _safe_lstat(path, secret_parent=tmp_path.resolve()),
    )
    one_line_reads: list[str] = []

    def record_one_line_read(
        _path: str,
        *,
        variable_name: str,
    ) -> str:
        one_line_reads.append(variable_name)
        return "x"

    monkeypatch.setattr(preflight, "read_runtime_secret_file", record_one_line_read)

    validated = preflight.validate_runtime_secret_paths(_environment(tmp_path))

    assert len(validated) == 5
    assert set(one_line_reads) == preflight.ONE_LINE_SECRET_FILE_ENVIRONMENTS
    assert "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH" not in one_line_reads


def test_preflight_accepts_multiline_ca_without_one_line_secret_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environ = _environment(tmp_path)
    for variable_name, raw_path in environ.items():
        payload = (
            "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n"
            if variable_name == "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH"
            else "one-line-secret\n"
        )
        Path(raw_path).write_text(payload, encoding="utf-8")
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: _safe_lstat(path, secret_parent=tmp_path.resolve()),
    )
    one_line_reads: list[str] = []

    def record_one_line_read(_path: str, *, variable_name: str) -> str:
        one_line_reads.append(variable_name)
        return "one-line-secret"

    monkeypatch.setattr(preflight, "read_runtime_secret_file", record_one_line_read)

    validated = preflight.validate_runtime_secret_paths(environ)

    assert len(validated) == len(preflight.SECRET_FILE_ENVIRONMENTS)
    assert set(one_line_reads) == preflight.ONE_LINE_SECRET_FILE_ENVIRONMENTS
    assert "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH" not in one_line_reads


def test_preflight_validates_both_postgres_dsns_against_host_ca(
    tmp_path: Path,
) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    dsn = (
        "postgresql://runtime@db.example.test/app"
        "?sslmode=verify-full&sslrootcert=/run/hallu-defense/postgres/ca.crt"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable"
    )
    runtime_dsn = (tmp_path / "runtime-dsn").resolve()
    migration_dsn = (tmp_path / "migration-dsn").resolve()
    runtime_dsn.write_text(dsn, encoding="utf-8")
    migration_dsn.write_text(dsn, encoding="utf-8")
    runtime_dsn.chmod(0o400)
    migration_dsn.chmod(0o400)

    preflight.validate_postgres_tls_inputs(
        {
            "HALLU_DEFENSE_POSTGRES_DSN_FILE": str(runtime_dsn),
            "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE": str(migration_dsn),
            "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH": str(ca_path),
        }
    )


def test_preflight_rejects_postgres_dsn_without_verify_full(tmp_path: Path) -> None:
    ca_path = (tmp_path / "postgres-ca.crt").resolve()
    ca_path.write_text("fixture-ca", encoding="utf-8")
    runtime_dsn = (tmp_path / "runtime-dsn").resolve()
    migration_dsn = (tmp_path / "migration-dsn").resolve()
    runtime_dsn.write_text(
        "postgresql://runtime@db.example.test/app?sslmode=require",
        encoding="utf-8",
    )
    migration_dsn.write_text(
        "postgresql://migration@db.example.test/app?sslmode=verify-full"
        "&sslrootcert=/run/hallu-defense/postgres/ca.crt"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable",
        encoding="utf-8",
    )
    runtime_dsn.chmod(0o400)
    migration_dsn.chmod(0o400)

    with pytest.raises(preflight.RuntimeSecretPreflightError, match="verify-full"):
        preflight.validate_postgres_tls_inputs(
            {
                "HALLU_DEFENSE_POSTGRES_DSN_FILE": str(runtime_dsn),
                "HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE": str(migration_dsn),
                "HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH": str(ca_path),
            }
        )


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (_metadata(mode=0o444), "mode 0440"),
        (_metadata(uid=1000), "root:10001"),
        (_metadata(gid=1000), "root:10001"),
    ],
)
def test_preflight_rejects_unsafe_host_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata: os.stat_result,
    message: str,
) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: metadata)

    with pytest.raises(preflight.RuntimeSecretPreflightError, match=message):
        preflight.validate_runtime_secret_paths(_environment(tmp_path))


def test_preflight_rejects_relative_paths() -> None:
    env = dict.fromkeys(preflight.SECRET_FILE_ENVIRONMENTS, "relative-secret")

    with pytest.raises(preflight.RuntimeSecretPreflightError, match="absolute"):
        preflight.validate_runtime_secret_paths(env)


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (_directory_metadata(mode=0o770), "mode 0750"),
        (_directory_metadata(uid=1000), "root-owned"),
        (_directory_metadata(gid=1000), "root:10001"),
    ],
)
def test_preflight_rejects_unsafe_direct_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata: os.stat_result,
    message: str,
) -> None:
    def fake_lstat(path: Path) -> os.stat_result:
        if path == tmp_path.resolve():
            return metadata
        if path.name.startswith("secret-"):
            return _metadata()
        return _directory_metadata(mode=0o755, gid=0)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(preflight, "read_runtime_secret_file", lambda *_a, **_k: "x")

    with pytest.raises(preflight.RuntimeSecretPreflightError, match=message):
        preflight.validate_runtime_secret_paths(_environment(tmp_path))


def test_preflight_rejects_writable_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe_ancestor = tmp_path.resolve().parent

    def fake_lstat(path: Path) -> os.stat_result:
        if path == tmp_path.resolve():
            return _directory_metadata()
        if path == unsafe_ancestor:
            return _directory_metadata(mode=0o777, gid=0)
        if path.name.startswith("secret-"):
            return _metadata()
        return _directory_metadata(mode=0o755, gid=0)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(preflight, "read_runtime_secret_file", lambda *_a, **_k: "x")

    with pytest.raises(preflight.RuntimeSecretPreflightError, match="ancestor"):
        preflight.validate_runtime_secret_paths(_environment(tmp_path))
