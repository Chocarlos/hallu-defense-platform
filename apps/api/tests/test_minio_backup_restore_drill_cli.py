from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from hallu_defense.services.secrets import SecretValue
from scripts.dev import minio_backup_restore_drill as cli
from scripts.dev.s3_sigv4 import S3Object, S3SigV4Error


class FakeS3Client:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.objects = (S3Object(key="tenants/t1/a.bin", size=12),)
        self.download_payload = b"downloaded payload"

    def ensure_bucket(self, bucket: str, *, timeout_seconds: int) -> None:
        self.calls.append(("ensure_bucket", bucket, timeout_seconds))

    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str,
        max_response_bytes: int,
        timeout_seconds: int,
    ) -> tuple[S3Object, ...]:
        self.calls.append(
            ("list_objects", bucket, prefix, max_response_bytes, timeout_seconds)
        )
        return self.objects

    def download_file(
        self,
        bucket: str,
        key: str,
        destination: Path,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None:
        self.calls.append(
            ("download_file", bucket, key, destination, max_bytes, timeout_seconds)
        )
        destination.write_bytes(self.download_payload)

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

    def delete_prefix(
        self,
        bucket: str,
        *,
        prefix: str,
        timeout_seconds: int,
    ) -> None:
        self.calls.append(("delete_prefix", bucket, prefix, timeout_seconds))

    def remove_bucket(self, bucket: str, *, timeout_seconds: int) -> None:
        self.calls.append(("remove_bucket", bucket, timeout_seconds))


class FailingS3Client(FakeS3Client):
    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str,
        max_response_bytes: int,
        timeout_seconds: int,
    ) -> tuple[S3Object, ...]:
        _ = bucket, prefix, max_response_bytes, timeout_seconds
        raise S3SigV4Error("sensitive endpoint and key")


class FakeSecretManager:
    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert name == "backup/encryption-key"
        assert field == "value"
        return SecretValue(name=name, _value=_key())


def test_cli_skips_before_requiring_tenant_or_secrets() -> None:
    result = cli.run_from_env({})

    assert result["status"] == "skipped"
    assert cli.ENABLED_ENV in str(result["reason"])


def test_s3_adapter_lists_objects_without_exposing_credentials() -> None:
    client = FakeS3Client()
    config = cli.MinioClientConfig(
        endpoint="http://127.0.0.1:9000",
        access_key="access-sensitive",
        secret_key="secret-sensitive",
    )
    store = cli.S3ObjectStore(config, client)

    objects = store.list_objects(
        bucket="source-bucket",
        prefix="tenants/t1/",
        max_output_bytes=4096,
        timeout_seconds=10,
    )

    assert [(item.key, item.size) for item in objects] == [
        ("tenants/t1/a.bin", 12)
    ]
    assert client.calls == [
        ("list_objects", "source-bucket", "tenants/t1/", 4096, 10)
    ]
    rendered = repr(config)
    assert "access-sensitive" not in rendered
    assert "secret-sensitive" not in rendered


def test_s3_adapter_streams_private_files_and_cleanup_operations(tmp_path: Path) -> None:
    client = FakeS3Client()
    store = _store(client)
    destination = tmp_path / "download.bin"

    store.download(
        bucket="source-bucket",
        key="tenants/t1/object.bin",
        destination=destination,
        max_bytes=100,
        timeout_seconds=11,
    )
    store.upload(
        bucket="replica-bucket",
        key="__drill__/opaque/object.hdbk",
        source=destination,
        timeout_seconds=12,
    )
    store.delete_prefix(
        bucket="replica-bucket",
        prefix="__drill__/",
        timeout_seconds=13,
    )
    store.remove_bucket(bucket="replica-bucket", timeout_seconds=14)

    assert destination.read_bytes() == client.download_payload
    assert client.calls == [
        (
            "download_file",
            "source-bucket",
            "tenants/t1/object.bin",
            destination,
            100,
            11,
        ),
        (
            "upload_file",
            "replica-bucket",
            "__drill__/opaque/object.hdbk",
            client.download_payload,
            12,
        ),
        ("delete_prefix", "replica-bucket", "__drill__/", 13),
        ("remove_bucket", "replica-bucket", 14),
    ]


def test_s3_adapter_redacts_transport_errors() -> None:
    store = _store(FailingS3Client())

    with pytest.raises(cli.MinioDrillCommandError, match="S3 object listing failed") as caught:
        store.list_objects(
            bucket="source-bucket",
            prefix="tenants/t1/",
            max_output_bytes=4096,
            timeout_seconds=10,
        )

    assert "sensitive" not in str(caught.value)


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


def test_production_client_requires_vault_https_and_credential_fields() -> None:
    manager = CredentialSecretManager()
    base = {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_MINIO_BACKUP_ENDPOINT": "https://minio.example.test",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": "https://minio.example.test",
    }

    with pytest.raises(cli.MinioBackupDrillError, match="Vault backend"):
        cli._client_config(base, secret_manager=manager)

    config = cli._client_config(
        base
        | {
            "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
            "HALLU_DEFENSE_MINIO_BACKUP_ACCESS_KEY": "must-be-ignored",
            "HALLU_DEFENSE_MINIO_BACKUP_SECRET_KEY": "must-be-ignored",
        },
        secret_manager=manager,
    )
    cli.S3ObjectStore(config, FakeS3Client())

    assert manager.requests == [
        ("backup/minio-credentials", "access_key"),
        ("backup/minio-credentials", "secret_key"),
    ]
    assert "must-be-ignored" not in repr(config)
    assert "vault-access-sensitive" not in repr(config)
    assert "vault-secret-sensitive" not in repr(config)

    with pytest.raises(cli.MinioBackupDrillError, match="endpoint"):
        cli._client_config(
            base
            | {
                "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
                "HALLU_DEFENSE_MINIO_BACKUP_ENDPOINT": "http://minio.example.test",
            },
            secret_manager=manager,
        )


def test_production_secret_manager_requires_vault_over_https() -> None:
    with pytest.raises(cli.MinioBackupDrillError, match="Vault secret backend"):
        cli._build_secret_manager({"HALLU_DEFENSE_ENV": "production"})

    with pytest.raises(cli.MinioBackupDrillError, match="HTTPS Vault endpoint"):
        cli._build_secret_manager(
            {
                "HALLU_DEFENSE_ENV": "staging",
                "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
                "HALLU_DEFENSE_VAULT_ADDR": "http://vault.internal:8200",
            }
        )


def test_cli_failure_output_is_fixed_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive = "credential-and-object-content"

    def fail() -> dict[str, object]:
        raise RuntimeError(sensitive)

    monkeypatch.setattr(cli, "run_from_env", fail)

    assert cli.main() == 1
    output = capsys.readouterr().out
    assert sensitive not in output
    assert json.loads(output)["status"] == "failed"


def test_run_from_env_requires_tenant_before_client_or_secret_discovery() -> None:
    with pytest.raises(cli.MinioBackupDrillError, match=cli.TENANT_ENV):
        cli.run_from_env({cli.ENABLED_ENV: "true"})


def _store(client: FakeS3Client) -> cli.S3ObjectStore:
    return cli.S3ObjectStore(
        cli.MinioClientConfig(
            endpoint="http://127.0.0.1:9000",
            access_key="access",
            secret_key="secret",
        ),
        client,
    )


def _key() -> str:
    return base64.urlsafe_b64encode(b"k" * 32).decode("ascii")
