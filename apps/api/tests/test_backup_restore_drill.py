from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from hallu_defense.services.secrets import SecretValue
from scripts.dev import backup_restore_drill as drill


class FakeSecretManager:
    def __init__(self, value: str) -> None:
        self.value = value
        self.requests: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert field == "value"
        self.requests.append(name)
        return SecretValue(name=name, _value=self.value)


class CredentialSecretManager:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requests.append((name, field))
        values = {
            "access_key": "vault-access-sensitive",
            "secret_key": "vault-secret-sensitive",
        }
        return SecretValue(name=name, _value=values[field])


class FakeCipher:
    def encrypt(self, key: str, payload: bytes) -> bytes:
        assert key == _fernet_key()
        return b"encrypted:" + payload

    def decrypt(self, key: str, payload: bytes) -> bytes:
        assert key == _fernet_key()
        assert payload.startswith(b"encrypted:")
        return payload.removeprefix(b"encrypted:")


class FakeRunner:
    def __init__(self, *, downloaded_payload: bytes = b"encrypted:dump-data") -> None:
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        self.pg_restore_input: bytes | None = None
        self.downloaded_payload = downloaded_payload

    def run(
        self,
        command: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        timeout_seconds: int,
    ) -> drill.CommandResult:
        assert timeout_seconds == 120
        command_tuple = tuple(command)
        self.calls.append((command_tuple, input_bytes))
        if "psql" in command_tuple:
            return drill.CommandResult(stdout=b"2|checksum\n")
        if "pg_dump" in command_tuple:
            return drill.CommandResult(stdout=b"dump-data")
        if "pg_restore" in command_tuple:
            self.pg_restore_input = input_bytes
        return drill.CommandResult(stdout=b"")


class FakeS3Client:
    def __init__(self, *, downloaded_payload: bytes = b"encrypted:dump-data") -> None:
        self.downloaded_payload = downloaded_payload
        self.calls: list[tuple[object, ...]] = []

    def ensure_bucket(self, bucket: str, *, timeout_seconds: int) -> None:
        self.calls.append(("ensure_bucket", bucket, timeout_seconds))

    def upload_file(
        self,
        bucket: str,
        key: str,
        source: Path,
        *,
        timeout_seconds: int,
    ) -> None:
        self.calls.append(
            ("upload_file", bucket, key, source.read_bytes(), timeout_seconds)
        )

    def get_bytes(
        self,
        bucket: str,
        key: str,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> bytes:
        self.calls.append(("get_bytes", bucket, key, max_bytes, timeout_seconds))
        return self.downloaded_payload


def test_backup_restore_drill_skips_without_env_gate() -> None:
    result = drill.run_from_env({})

    assert result["status"] == "skipped"
    assert "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED" in str(result["reason"])


def test_production_config_reads_s3_credentials_only_from_vault_fields(
    tmp_path: Path,
) -> None:
    manager = CredentialSecretManager()
    base = {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED": "true",
        "HALLU_DEFENSE_BACKUP_DRILL_OUTPUT_DIR": str(tmp_path),
        "HALLU_DEFENSE_BACKUP_DRILL_MINIO_ENDPOINT": "https://minio.example.test",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": "https://minio.example.test",
    }

    with pytest.raises(drill.BackupRestoreDrillError, match="Vault backend"):
        drill._config_from_env(base, timestamp="20260710T010203Z", secret_manager=manager)

    config = drill._config_from_env(
        base
        | {
            "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
            "HALLU_DEFENSE_BACKUP_DRILL_MINIO_ACCESS_KEY": "must-be-ignored",
            "HALLU_DEFENSE_BACKUP_DRILL_MINIO_SECRET_KEY": "must-be-ignored",
        },
        timestamp="20260710T010203Z",
        secret_manager=manager,
    )

    assert manager.requests == [
        ("backup/minio-credentials", "access_key"),
        ("backup/minio-credentials", "secret_key"),
    ]
    assert config.minio_require_https is True
    assert config.minio_allowed_origins == ("https://minio.example.test",)
    assert config.minio_allow_private_endpoint is False
    assert "must-be-ignored" not in repr(config)
    assert "vault-access-sensitive" not in repr(config)
    assert "vault-secret-sensitive" not in repr(config)
    drill._build_s3_client(config)


def test_production_secret_manager_requires_vault_over_https() -> None:
    with pytest.raises(drill.BackupRestoreDrillError, match="Vault secret backend"):
        drill._build_secret_manager({"HALLU_DEFENSE_ENV": "production"})

    with pytest.raises(drill.BackupRestoreDrillError, match="HTTPS Vault endpoint"):
        drill._build_secret_manager(
            {
                "HALLU_DEFENSE_ENV": "staging",
                "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
                "HALLU_DEFENSE_VAULT_ADDR": "http://vault.internal:8200",
            }
        )


def test_backup_restore_drill_uses_pg_dump_fernet_s3_restore_and_writes_report(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    s3_client = FakeS3Client()
    secrets = FakeSecretManager(_fernet_key())
    env = {
        "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED": "true",
        "HALLU_DEFENSE_BACKUP_DRILL_OUTPUT_DIR": str(tmp_path),
    }

    result = drill.run_from_env(
        env,
        runner=runner,
        secret_manager=secrets,
        cipher=FakeCipher(),
        s3_client=s3_client,
        timestamp="20260709T010203Z",
    )

    assert result["status"] == "passed"
    assert result["parity_passed"] is True
    assert secrets.requests == ["backup/encryption-key"]
    assert (tmp_path / "20260709T010203Z.dump.fernet").read_bytes() == b"encrypted:dump-data"
    report_path = Path(str(result["report_path"]))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["tables"]["audit_events"]["matched"] is True
    assert report["restored_from_object_storage"] is True
    assert report["encrypted_sha256"]
    assert _fernet_key() not in report_path.read_text(encoding="utf-8")
    assert runner.pg_restore_input == b"dump-data"

    commands = [call[0] for call in runner.calls]
    assert any(command[:5] == ("docker", "compose", "exec", "-T", "postgres") and "pg_dump" in command for command in commands)
    assert s3_client.calls[0] == ("ensure_bucket", "hallu-backups", 120)
    assert s3_client.calls[1][:4] == (
        "upload_file",
        "hallu-backups",
        "postgres/20260709T010203Z.dump.fernet",
        b"encrypted:dump-data",
    )
    assert s3_client.calls[2][:3] == (
        "get_bytes",
        "hallu-backups",
        "postgres/20260709T010203Z.dump.fernet",
    )
    assert any("pg_restore" in command for command in commands)
    assert any("dropdb" in command and "--if-exists" in command for command in commands)


def test_backup_restore_drill_rejects_changed_minio_download(tmp_path: Path) -> None:
    runner = FakeRunner()

    try:
        drill.run_from_env(
            {
                "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED": "true",
                "HALLU_DEFENSE_BACKUP_DRILL_OUTPUT_DIR": str(tmp_path),
            },
            runner=runner,
            secret_manager=FakeSecretManager(_fernet_key()),
            cipher=FakeCipher(),
            s3_client=FakeS3Client(
                downloaded_payload=b"corrupted-encrypted-backup"
            ),
            timestamp="20260709T010204Z",
        )
    except drill.BackupRestoreDrillError as exc:
        assert "checksum" in str(exc)
    else:
        raise AssertionError("corrupt MinIO download must fail closed")

    assert runner.pg_restore_input is None


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(b"x" * 32).decode("ascii")
