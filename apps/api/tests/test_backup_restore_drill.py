from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from pathlib import Path

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


class FakeCipher:
    def encrypt(self, key: str, payload: bytes) -> bytes:
        assert key == _fernet_key()
        return b"encrypted:" + payload

    def decrypt(self, key: str, payload: bytes) -> bytes:
        assert key == _fernet_key()
        assert payload.startswith(b"encrypted:")
        return payload.removeprefix(b"encrypted:")


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        self.pg_restore_input: bytes | None = None

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


def test_backup_restore_drill_skips_without_env_gate() -> None:
    result = drill.run_from_env({})

    assert result["status"] == "skipped"
    assert "HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED" in str(result["reason"])


def test_backup_restore_drill_uses_pg_dump_fernet_mc_restore_and_writes_report(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
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
        timestamp="20260709T010203Z",
    )

    assert result["status"] == "passed"
    assert result["parity_passed"] is True
    assert secrets.requests == ["backup/encryption-key"]
    assert (tmp_path / "20260709T010203Z.dump.fernet").read_bytes() == b"encrypted:dump-data"
    report_path = Path(str(result["report_path"]))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["tables"]["audit_events"]["matched"] is True
    assert _fernet_key() not in report_path.read_text(encoding="utf-8")
    assert runner.pg_restore_input == b"dump-data"

    commands = [call[0] for call in runner.calls]
    assert any(command[:5] == ("docker", "compose", "exec", "-T", "postgres") and "pg_dump" in command for command in commands)
    assert any("minio/mc:RELEASE.2025-09-07T16-13-09Z" in command for command in commands)
    assert any("pg_restore" in command for command in commands)
    assert any("dropdb" in command and "--if-exists" in command for command in commands)


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(b"x" * 32).decode("ascii")
