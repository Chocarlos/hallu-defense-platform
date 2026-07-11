from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, cast

from hallu_defense.config import (
    AUTH_CLAIMS_MODE_OIDC_JWT,
    PRODUCTION_LIKE_ENVIRONMENTS,
    Settings,
)
from hallu_defense.services.oidc import OidcJwksResolver, OidcJwtValidator, load_jwks
from hallu_defense.services.rate_limit import (
    RateLimitUnavailableError,
    ToolValidationRateLimitBackend,
)
from hallu_defense.services.secrets import SecretManager

LOGGER = logging.getLogger(__name__)
SCHEMA_MIGRATIONS_QUERY = (
    "SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version ASC"
)
SCHEMA_MIGRATIONS_FILENAME = "000_schema_migrations.sql"
EXPECTED_MIGRATION_VERSIONS = (
    "000_schema_migrations.sql",
    "001_rag_evidence_chunks.sql",
    "002_rag_corpus_grants.sql",
    "003_audit_ledger.sql",
    "004_approval_queue.sql",
    "005_eval_reports.sql",
    "006_ingestion_outbox.sql",
    "007_ingestion_lease_fencing.sql",
    "008_schema_migration_checksums.sql",
    "009_drop_unsafe_ivfflat.sql",
    "010_add_retrieved_at.sql",
    "011_rag_lifecycle_outbox.sql",
    "012_rag_tenant_deletion_fence.sql",
    "013_audit_history_integrity.sql",
)
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
DEFAULT_READINESS_CACHE_TTL_SECONDS = 2.0
DEFAULT_READINESS_TOTAL_TIMEOUT_SECONDS = 5.0
MAX_READINESS_WORKERS = 8


class ReadinessCheckError(RuntimeError):
    pass


class ReadinessCheck(Protocol):
    @property
    def name(self) -> str: ...

    def run(self) -> None: ...


class MigrationLedgerReader(Protocol):
    def fetch_applied_migrations(self) -> Sequence[Mapping[str, object]]: ...


class JwksResolver(Protocol):
    def resolve(self, *, force_refresh: bool = False) -> Mapping[str, object]: ...


class RagIndexHealthProbe(Protocol):
    def health_check(self) -> None: ...


@dataclass(frozen=True)
class ReadinessResult:
    ready: bool
    failed_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class MigrationFingerprint:
    version: str
    checksum_sha256: str


@dataclass(frozen=True)
class _CachedReadiness:
    result: ReadinessResult
    expires_at: float


class ReadinessService:
    def __init__(
        self,
        checks: Sequence[ReadinessCheck],
        *,
        cache_ttl_seconds: float = DEFAULT_READINESS_CACHE_TTL_SECONDS,
        total_timeout_seconds: float = DEFAULT_READINESS_TOTAL_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < cache_ttl_seconds <= 30:
            raise ReadinessCheckError("Readiness cache TTL must be in (0, 30].")
        if not 0 < total_timeout_seconds <= 30:
            raise ReadinessCheckError("Readiness timeout must be in (0, 30].")
        self._checks = tuple(checks)
        self._cache_ttl_seconds = cache_ttl_seconds
        self._total_timeout_seconds = total_timeout_seconds
        self._clock = clock
        self._condition = threading.Condition()
        self._cached: _CachedReadiness | None = None
        self._refreshing = False
        self._pending_futures: set[Future[bool]] = set()

    def check(self) -> ReadinessResult:
        now = self._clock()
        with self._condition:
            if self._cached is not None and self._cached.expires_at > now:
                return self._cached.result
            if self._refreshing:
                # A timed-out dependency may still be executing because Python
                # cannot safely kill a running thread. Reuse the fail-closed
                # timeout result until that generation really finishes so a
                # public /ready poll cannot create an unbounded series of pools.
                if self._cached is not None:
                    return self._cached.result
                self._condition.wait_for(
                    lambda: not self._refreshing,
                    timeout=self._total_timeout_seconds,
                )
                if self._cached is not None:
                    return self._cached.result
                return ReadinessResult(False, ("readiness_refresh",))
            self._refreshing = True
        result: ReadinessResult | None = None
        pending: tuple[Future[bool], ...] = ()
        try:
            result, pending = self._run_checks()
        finally:
            with self._condition:
                if result is not None:
                    self._cached = _CachedReadiness(
                        result=result,
                        expires_at=self._clock() + self._cache_ttl_seconds,
                    )
                self._pending_futures = set(pending)
                if not self._pending_futures:
                    self._refreshing = False
                self._condition.notify_all()
        for future in pending:
            future.add_done_callback(self._finish_pending_future)
        assert result is not None
        return result

    def _run_checks(self) -> tuple[ReadinessResult, tuple[Future[bool], ...]]:
        if not self._checks:
            return ReadinessResult(True), ()
        executor = ThreadPoolExecutor(
            max_workers=min(len(self._checks), MAX_READINESS_WORKERS),
            thread_name_prefix="readiness-check",
        )
        futures: dict[Future[bool], tuple[int, ReadinessCheck]] = {
            executor.submit(self._run_one, check): (index, check)
            for index, check in enumerate(self._checks)
        }
        try:
            done, pending = wait(
                futures,
                timeout=self._total_timeout_seconds,
            )
            failed: list[tuple[int, str]] = []
            for future in done:
                index, check = futures[future]
                if future.result() is False:
                    failed.append((index, check.name))
            for future in pending:
                index, check = futures[future]
                future.cancel()
                failed.append((index, check.name))
                LOGGER.warning(
                    "Readiness dependency check timed out.",
                    extra={"readiness_check": check.name},
                )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        ordered = tuple(name for _index, name in sorted(failed))
        return (
            ReadinessResult(ready=not ordered, failed_checks=ordered),
            tuple(pending),
        )

    def _finish_pending_future(self, future: Future[bool]) -> None:
        with self._condition:
            self._pending_futures.discard(future)
            if not self._pending_futures:
                self._refreshing = False
                self._condition.notify_all()

    @staticmethod
    def _run_one(check: ReadinessCheck) -> bool:
        try:
            check.run()
        except Exception as exc:
            LOGGER.warning(
                "Readiness dependency check failed.",
                extra={
                    "readiness_check": check.name,
                    "exception_type": type(exc).__name__,
                },
            )
            return False
        return True


@dataclass(frozen=True)
class UnavailableReadinessCheck:
    name: str

    def run(self) -> None:
        raise ReadinessCheckError("Required readiness dependency is not configured.")


class PostgresMigrationsReadinessCheck:
    name = "postgres"

    def __init__(
        self,
        reader: MigrationLedgerReader,
        *,
        expected_migrations: Sequence[MigrationFingerprint],
    ) -> None:
        expected = tuple(expected_migrations)
        versions = tuple(item.version for item in expected)
        if versions != EXPECTED_MIGRATION_VERSIONS or any(
            SHA256_PATTERN.fullmatch(item.checksum_sha256) is None
            for item in expected
        ):
            raise ReadinessCheckError("Expected migration inventory is incomplete.")
        self._reader = reader
        self._expected = {
            item.version: item.checksum_sha256
            for item in expected
        }

    def run(self) -> None:
        try:
            rows = self._reader.fetch_applied_migrations()
        except Exception:
            raise ReadinessCheckError("PostgreSQL readiness query failed.") from None
        applied: dict[str, str] = {}
        for row in rows:
            version = row.get("version")
            checksum = row.get("checksum_sha256")
            if (
                not isinstance(version, str)
                or not version
                or not isinstance(checksum, str)
                or SHA256_PATTERN.fullmatch(checksum) is None
                or version in applied
            ):
                raise ReadinessCheckError(
                    "PostgreSQL migration ledger is malformed or incomplete."
                )
            applied[version] = checksum
        if applied != self._expected:
            raise ReadinessCheckError(
                "PostgreSQL migration versions or checksums do not match the release."
            )


class OidcJwksReadinessCheck:
    name = "oidc_jwks"

    def __init__(self, settings: Settings, *, resolver: JwksResolver | None = None) -> None:
        self._settings = settings
        self._resolver = resolver or OidcJwksResolver(settings)

    def run(self) -> None:
        try:
            if self._settings.oidc_jwks_path is not None:
                jwks = load_jwks(self._settings.oidc_jwks_path)
            else:
                jwks = self._resolver.resolve()
            OidcJwtValidator(self._settings, jwks)
        except Exception as exc:
            raise ReadinessCheckError("OIDC signing keys are unavailable or invalid.") from exc


class ProviderSecretReadinessCheck:
    name = "provider_secret"

    def __init__(self, secret_manager: SecretManager, *, secret_name: str) -> None:
        self._secret_manager = secret_manager
        self._secret_name = secret_name

    def run(self) -> None:
        try:
            value = self._secret_manager.get_secret(self._secret_name).reveal()
        except Exception as exc:
            raise ReadinessCheckError("Provider credential is unavailable.") from exc
        if not value.strip():
            raise ReadinessCheckError("Provider credential is unavailable.")


class ToolValidationRateLimitReadinessCheck:
    name = "tool_validation_rate_limit"

    def __init__(self, limiter: ToolValidationRateLimitBackend) -> None:
        self._limiter = limiter

    def run(self) -> None:
        try:
            self._limiter.health_check()
        except RateLimitUnavailableError as exc:
            raise ReadinessCheckError("Distributed rate limit backend is unavailable.") from exc


class RagIndexReadinessCheck:
    name = "rag_opensearch"

    def __init__(self, probe: RagIndexHealthProbe) -> None:
        self._probe = probe

    def run(self) -> None:
        try:
            self._probe.health_check()
        except Exception as exc:
            raise ReadinessCheckError(
                "Persistent RAG search backend is unavailable."
            ) from exc


class ReadinessCursor(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object: ...

    def fetchall(self) -> Sequence[Mapping[str, object]]: ...


class ReadinessConnection(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def cursor(self) -> ReadinessCursor: ...


class ReadinessConnect(Protocol):
    def __call__(
        self,
        conninfo: str,
        *,
        connect_timeout: int,
        options: str,
        row_factory: object | None = None,
    ) -> ReadinessConnection: ...


class PsycopgMigrationLedgerReader:
    def __init__(
        self,
        *,
        dsn: str,
        timeout_seconds: float,
        connect: ReadinessConnect | None = None,
        row_factory: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise ReadinessCheckError("PostgreSQL DSN is required for readiness.")
        if timeout_seconds <= 0:
            raise ReadinessCheckError("PostgreSQL readiness timeout must be positive.")
        self._dsn = dsn
        self._timeout_seconds = timeout_seconds
        self._connect = connect
        self._row_factory = row_factory

    def fetch_applied_migrations(self) -> Sequence[Mapping[str, object]]:
        connect = self._connect
        row_factory = self._row_factory
        if connect is None:
            connect, row_factory = _load_psycopg_connect()
        timeout_milliseconds = max(1, int(self._timeout_seconds * 1000))
        try:
            with connect(
                self._dsn,
                connect_timeout=max(1, math.ceil(self._timeout_seconds)),
                options=f"-c statement_timeout={timeout_milliseconds}",
                row_factory=row_factory,
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(SCHEMA_MIGRATIONS_QUERY)
                    return list(cursor.fetchall())
        except Exception:
            raise ReadinessCheckError("PostgreSQL migration ledger query failed.") from None


def discover_expected_migrations(
    migrations_dir: Path,
) -> tuple[MigrationFingerprint, ...]:
    if not migrations_dir.is_dir():
        raise ReadinessCheckError("PostgreSQL migrations directory is unavailable.")
    migration_paths = tuple(sorted(migrations_dir.glob("*.sql")))
    versions = tuple(path.name for path in migration_paths)
    if versions != EXPECTED_MIGRATION_VERSIONS:
        raise ReadinessCheckError("PostgreSQL migration inventory is incomplete.")
    fingerprints: list[MigrationFingerprint] = []
    try:
        for path in migration_paths:
            statement = path.read_text(encoding="utf-8")
            fingerprints.append(
                MigrationFingerprint(
                    version=path.name,
                    checksum_sha256=_migration_checksum(statement),
                )
            )
    except (OSError, UnicodeError):
        raise ReadinessCheckError(
            "PostgreSQL migration inventory is unreadable."
        ) from None
    return tuple(fingerprints)


def _migration_checksum(statement: str) -> str:
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def locate_migrations_dir() -> Path:
    roots = (Path.cwd(), *Path(__file__).resolve().parents)
    seen: set[Path] = set()
    for root in roots:
        candidate = (root / "infra" / "rag" / "pgvector").resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.is_dir():
            return candidate
    raise ReadinessCheckError("PostgreSQL migrations directory is unavailable.")


def create_readiness_service(
    settings: Settings,
    secret_manager: SecretManager,
    *,
    tool_validation_rate_limiter: ToolValidationRateLimitBackend | None = None,
    rag_index_backend: object | None = None,
    migrations_dir: Path | None = None,
    postgres_connect: ReadinessConnect | None = None,
    postgres_row_factory: object | None = None,
    jwks_resolver: JwksResolver | None = None,
) -> ReadinessService:
    checks: list[ReadinessCheck] = []
    environment = settings.environment.strip().lower()
    dsn = settings.postgres_dsn
    postgres_required = bool(dsn and dsn.strip()) or environment in PRODUCTION_LIKE_ENVIRONMENTS
    if postgres_required:
        if dsn is None or not dsn.strip():
            checks.append(UnavailableReadinessCheck("postgres"))
        else:
            try:
                expected_migrations = discover_expected_migrations(
                    migrations_dir or locate_migrations_dir()
                )
                reader = PsycopgMigrationLedgerReader(
                    dsn=dsn,
                    timeout_seconds=settings.postgres_pool_timeout_seconds,
                    connect=postgres_connect,
                    row_factory=postgres_row_factory,
                )
                checks.append(
                    PostgresMigrationsReadinessCheck(
                        reader,
                        expected_migrations=expected_migrations,
                    )
                )
            except ReadinessCheckError:
                checks.append(UnavailableReadinessCheck("postgres"))

    if settings.auth_claims_mode.strip().lower() == AUTH_CLAIMS_MODE_OIDC_JWT:
        checks.append(OidcJwksReadinessCheck(settings, resolver=jwks_resolver))

    if settings.provider_backend.strip().lower() in {"openai", "openai-compatible"}:
        checks.append(
            ProviderSecretReadinessCheck(
                secret_manager,
                secret_name=settings.openai_compatible_api_key_secret_name,
            )
        )

    if settings.tool_validation_rate_limit_backend.strip().lower() == "redis":
        if tool_validation_rate_limiter is None:
            checks.append(UnavailableReadinessCheck("tool_validation_rate_limit"))
        else:
            checks.append(ToolValidationRateLimitReadinessCheck(tool_validation_rate_limiter))

    if settings.rag_index_backend.strip().lower() in {"opensearch", "hybrid"}:
        if not callable(getattr(rag_index_backend, "health_check", None)):
            checks.append(UnavailableReadinessCheck("rag_opensearch"))
        else:
            checks.append(
                RagIndexReadinessCheck(cast(RagIndexHealthProbe, rag_index_backend))
            )

    return ReadinessService(checks)


def _load_psycopg_connect() -> tuple[ReadinessConnect, object]:
    try:
        psycopg_module = import_module("psycopg")
        rows_module = import_module("psycopg.rows")
    except ImportError as exc:
        raise ReadinessCheckError("PostgreSQL readiness requires psycopg.") from exc
    connect = getattr(psycopg_module, "connect", None)
    row_factory = getattr(rows_module, "dict_row", None)
    if not callable(connect) or row_factory is None:
        raise ReadinessCheckError("PostgreSQL readiness adapter is unavailable.")
    return cast(ReadinessConnect, connect), row_factory
