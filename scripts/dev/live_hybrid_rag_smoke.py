"""Opt-in live smoke for the dual-store hybrid RAG backend.

The smoke never applies migrations to the configured application database. It
creates a random scratch database through an administrator DSN, applies the full
migration inventory there, and creates a random OpenSearch index. Both resources
are removed by exact name in ``finally``.
"""

from __future__ import annotations

import json
import math
import os
import re
import ssl
import sys
import uuid
from builtins import BaseExceptionGroup, ExceptionGroup
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.domain.models import Authority, Freshness, StalenessClass  # noqa: E402
from hallu_defense.services.rag_index import (  # noqa: E402
    HybridRagIndexBackend,
    HybridRevisionLockConnect,
    OpenSearchRagIndexBackend,
    OpenSearchTransport,
    PgVectorPsycopgConnect,
    PgVectorRagIndexBackend,
    PostgresHybridRevisionLockCoordinator,
    PostgresTenantDeletionFence,
    PsycopgPgVectorConnection,
    RagChunk,
    RagIndexBackend,
    RagSearchRequest,
    UrlLibOpenSearchTransport,
)
from scripts.dev.apply_postgres_migrations import (  # noqa: E402
    MIGRATIONS_DIR,
    PsycopgConnect as MigrationPsycopgConnect,
    PsycopgMigrationConnection,
    apply_migrations,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_HYBRID_RAG_SMOKE_ENABLED"
ADMIN_DSN_ENV = "HALLU_DEFENSE_LIVE_HYBRID_RAG_ADMIN_DSN"
OPENSEARCH_ENDPOINT_ENV = "HALLU_DEFENSE_OPENSEARCH_ENDPOINT"
OPENSEARCH_CA_ENV = "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH"
TIMEOUT_ENV = "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS"

DEFAULT_OPENSEARCH_ENDPOINT = "http://localhost:9200"
EXPECTED_MIGRATION_COUNT = 14
DATABASE_PREFIX = "hallu_hybrid_smoke_"
INDEX_PREFIX = "hallu_evidence_hybrid_smoke_"
SAFE_RUN_ID_PATTERN = re.compile(r"^[a-z0-9]{1,20}$")
SAFE_DATABASE_PATTERN = re.compile(r"^hallu_hybrid_smoke_[a-z0-9]{1,20}$")
SAFE_INDEX_PATTERN = re.compile(r"^hallu_evidence_hybrid_smoke_[a-z0-9]{1,20}$")
SAFE_TEMPLATE_PATTERN = re.compile(
    r"^hallu_evidence_hybrid_smoke_[a-z0-9]{1,20}_template$"
)
INDEX_TEMPLATE_PATH = (
    ROOT / "infra" / "rag" / "opensearch" / "evidence-index-template.json"
)


@dataclass(frozen=True)
class LiveHybridRagSmokeConfig:
    admin_dsn: str
    opensearch_endpoint: str
    timeout_seconds: float
    opensearch_ca_cert_path: Path | None = None


@dataclass
class ProvisionedHybridSmoke:
    backend: RagIndexBackend
    database_name: str
    index_name: str
    migrations_applied: tuple[str, ...]
    database_cleaned: bool = False
    index_cleaned: bool = False
    template_cleaned: bool = False


class HybridSmokeProvisioner(Protocol):
    def provision(
        self,
        *,
        run_id: str,
    ) -> AbstractContextManager[ProvisionedHybridSmoke]: ...


class SmokeCursor(Protocol):
    def __enter__(self) -> SmokeCursor: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object: ...


class SmokeAdminConnection(Protocol):
    def __enter__(self) -> SmokeAdminConnection: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...

    def cursor(self) -> SmokeCursor: ...


class SmokeConnect(Protocol):
    def __call__(
        self,
        conninfo: str,
        *,
        autocommit: bool = False,
        connect_timeout: int | None = None,
        options: str | None = None,
        row_factory: object | None = None,
    ) -> SmokeAdminConnection: ...


class ConninfoToDict(Protocol):
    def __call__(self, conninfo: str) -> dict[str, str]: ...


class MakeConninfo(Protocol):
    def __call__(self, **params: object) -> str: ...


class PsycopgOpenSearchSmokeProvisioner:
    def __init__(
        self,
        config: LiveHybridRagSmokeConfig,
        *,
        transport: OpenSearchTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    @contextmanager
    def provision(self, *, run_id: str) -> Iterator[ProvisionedHybridSmoke]:
        normalized_run_id = validate_run_id(run_id)
        database_name = validate_database_name(DATABASE_PREFIX + normalized_run_id)
        index_name = validate_index_name(INDEX_PREFIX + normalized_run_id)
        template_name = validate_template_name(f"{index_name}_template")
        connect, row_factory, conninfo_to_dict, make_conninfo = _load_psycopg_runtime()
        scratch_dsn = _scratch_dsn(
            self._config.admin_dsn,
            database_name=database_name,
            timeout_seconds=self._config.timeout_seconds,
            conninfo_to_dict=conninfo_to_dict,
            make_conninfo=make_conninfo,
        )
        transport = self._transport or UrlLibOpenSearchTransport(
            self._config.opensearch_endpoint,
            ssl_context=_ssl_context(self._config.opensearch_ca_cert_path),
        )
        provisioned: ProvisionedHybridSmoke | None = None
        database_created = False
        index_create_attempted = False
        template_install_attempted = False
        primary_error: BaseException | None = None
        try:
            _create_scratch_database(
                connect,
                admin_dsn=self._config.admin_dsn,
                database_name=database_name,
                timeout_seconds=self._config.timeout_seconds,
            )
            database_created = True
            migrations = tuple(
                apply_migrations(
                    PsycopgMigrationConnection(
                        dsn=scratch_dsn,
                        connect=cast(MigrationPsycopgConnect, connect),
                        row_factory=row_factory,
                    ),
                    migrations_dir=MIGRATIONS_DIR,
                )
            )
            if len(migrations) != EXPECTED_MIGRATION_COUNT:
                raise RuntimeError(
                    "Scratch PostgreSQL database did not apply the expected migration inventory."
                )

            opensearch = OpenSearchRagIndexBackend(
                endpoint=self._config.opensearch_endpoint,
                index_name=index_name,
                timeout_seconds=self._config.timeout_seconds,
                transport=transport,
            )
            opensearch.health_check()
            template = _smoke_template(index_name)
            template_install_attempted = True
            initial_schema = opensearch.provision_index_schema(
                template_name=template_name,
                template=template,
            )
            if initial_schema.index_state != "absent":
                raise RuntimeError(
                    "Hybrid RAG smoke scratch index unexpectedly existed."
                )
            index_create_attempted = True
            _create_smoke_index(
                transport,
                index_name=index_name,
                timeout_seconds=self._config.timeout_seconds,
            )
            applied_schema = opensearch.provision_index_schema(
                template_name=template_name,
                template=template,
            )
            if applied_schema.index_state != "compatible":
                raise RuntimeError("Hybrid RAG smoke index did not receive schema v3.")
            pgvector_connection = PsycopgPgVectorConnection(
                dsn=scratch_dsn,
                connect=cast(PgVectorPsycopgConnect, connect),
                row_factory=row_factory,
            )
            pgvector = PgVectorRagIndexBackend(
                table_name="rag_evidence_chunks",
                connection=pgvector_connection,
            )
            locks = PostgresHybridRevisionLockCoordinator(
                dsn=scratch_dsn,
                connect=cast(HybridRevisionLockConnect, connect),
                timeout_seconds=self._config.timeout_seconds,
                row_factory=row_factory,
            )
            provisioned = ProvisionedHybridSmoke(
                backend=HybridRagIndexBackend(
                    opensearch=opensearch,
                    pgvector=pgvector,
                    revision_locks=locks,
                    tenant_write_fence=PostgresTenantDeletionFence(
                        pgvector_connection
                    ),
                ),
                database_name=database_name,
                index_name=index_name,
                migrations_applied=migrations,
            )
            yield provisioned
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            cleanup_errors: list[Exception] = []
            if index_create_attempted:
                try:
                    _delete_smoke_index(
                        transport,
                        index_name=index_name,
                        timeout_seconds=self._config.timeout_seconds,
                    )
                    if provisioned is not None:
                        provisioned.index_cleaned = True
                except Exception as exc:
                    cleanup_errors.append(exc)
            if template_install_attempted:
                try:
                    _delete_smoke_template(
                        transport,
                        template_name=template_name,
                        timeout_seconds=self._config.timeout_seconds,
                    )
                    if provisioned is not None:
                        provisioned.template_cleaned = True
                except Exception as exc:
                    cleanup_errors.append(exc)
            if database_created:
                try:
                    _drop_scratch_database(
                        connect,
                        admin_dsn=self._config.admin_dsn,
                        database_name=database_name,
                        timeout_seconds=self._config.timeout_seconds,
                    )
                    if provisioned is not None:
                        provisioned.database_cleaned = True
                except Exception as exc:
                    cleanup_errors.append(exc)
            _raise_cleanup_failures(primary_error, cleanup_errors)


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    provisioner: HybridSmokeProvisioner | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env or os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live hybrid RAG smoke",
            "backend": "hybrid",
            "tenant_isolation": False,
            "fusion_proven": False,
            "scoped_reconciliation": False,
        }

    admin_dsn = effective_env.get(ADMIN_DSN_ENV, "").strip()
    if not admin_dsn:
        raise ValueError(
            f"{ADMIN_DSN_ENV} must be configured for an isolated scratch database"
        )
    endpoint = validate_opensearch_endpoint(
        effective_env.get(OPENSEARCH_ENDPOINT_ENV, DEFAULT_OPENSEARCH_ENDPOINT)
    )
    ca_value = effective_env.get(OPENSEARCH_CA_ENV, "").strip()
    ca_path = Path(ca_value).resolve() if ca_value else None
    if ca_path is not None and not ca_path.is_file():
        raise ValueError(f"{OPENSEARCH_CA_ENV} must reference an existing file")
    config = LiveHybridRagSmokeConfig(
        admin_dsn=admin_dsn,
        opensearch_endpoint=endpoint,
        timeout_seconds=_parse_timeout(effective_env.get(TIMEOUT_ENV, "5")),
        opensearch_ca_cert_path=ca_path,
    )
    return run_live_smoke(
        config,
        provisioner=provisioner,
        run_id=run_id,
    )


def run_live_smoke(
    config: LiveHybridRagSmokeConfig,
    *,
    provisioner: HybridSmokeProvisioner | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    smoke_run_id = validate_run_id(run_id or uuid.uuid4().hex[:16])
    active_provisioner = provisioner or PsycopgOpenSearchSmokeProvisioner(config)
    result: dict[str, object]
    with active_provisioner.provision(run_id=smoke_run_id) as provisioned:
        assertions = _exercise_hybrid_backend(provisioned.backend, smoke_run_id)
        result = {
            "status": "passed",
            "backend": "hybrid",
            "database_name": provisioned.database_name,
            "index_name": provisioned.index_name,
            "migrations_applied": len(provisioned.migrations_applied),
            **assertions,
        }
    result["database_cleaned"] = provisioned.database_cleaned
    result["index_cleaned"] = provisioned.index_cleaned
    result["template_cleaned"] = provisioned.template_cleaned
    if not all(
        (
            provisioned.database_cleaned,
            provisioned.index_cleaned,
            provisioned.template_cleaned,
        )
    ):
        raise RuntimeError("Hybrid RAG smoke resources were not cleaned up.")
    return result


def _exercise_hybrid_backend(
    backend: RagIndexBackend, run_id: str
) -> dict[str, object]:
    tenant_a = f"tenant-hybrid-smoke-{run_id}-a"
    tenant_b = f"tenant-hybrid-smoke-{run_id}-b"
    source_ref = f"hybrid-smoke-{run_id}-policy"
    corpus_id = f"hybrid-smoke-{run_id}"
    freshness = Freshness(
        retrieved_at=datetime.now(timezone.utc),
        staleness_class=StalenessClass.FRESH,
    )
    old_metadata = {
        "corpus_id": corpus_id,
        "document_revision": "revision-old",
        "smoke_run_id": run_id,
    }
    current_metadata = {
        **old_metadata,
        "document_revision": "revision-current",
    }

    writes = (
        backend.index_chunks(
            [
                RagChunk(
                    tenant_id=tenant_a,
                    evidence_id=f"ev_{run_id}_a_old_1",
                    source_ref=source_ref,
                    content=f"obsoletealpha{run_id} policy revision for tenant A",
                    authority=Authority.INTERNAL,
                    freshness=freshness,
                    metadata={**old_metadata, "owner_tenant_id": tenant_a},
                ),
                RagChunk(
                    tenant_id=tenant_a,
                    evidence_id=f"ev_{run_id}_a_old_2",
                    source_ref=source_ref,
                    content=f"obsoletebeta{run_id} policy revision for tenant A",
                    authority=Authority.INTERNAL,
                    freshness=freshness,
                    metadata={**old_metadata, "owner_tenant_id": tenant_a},
                ),
            ]
        ),
        backend.index_chunks(
            [
                RagChunk(
                    tenant_id=tenant_b,
                    evidence_id=f"ev_{run_id}_b_old",
                    source_ref=source_ref,
                    content=f"tenantbmarker{run_id} preserved old revision for tenant B",
                    authority=Authority.INTERNAL,
                    freshness=freshness,
                    metadata={**old_metadata, "owner_tenant_id": tenant_b},
                )
            ]
        ),
        backend.index_chunks(
            [
                RagChunk(
                    tenant_id=tenant_a,
                    evidence_id=f"ev_{run_id}_a_current",
                    source_ref=source_ref,
                    content=f"currentmarker{run_id} authoritative policy for tenant A",
                    authority=Authority.INTERNAL,
                    freshness=freshness,
                    metadata={**current_metadata, "owner_tenant_id": tenant_a},
                )
            ]
        ),
    )
    if any(write.backend != "hybrid" for write in writes):
        raise RuntimeError("Hybrid smoke write did not use both persistent stores.")

    tenant_a_current = backend.search(
        RagSearchRequest(
            tenant_id=tenant_a,
            claim_id="claim-hybrid-current-a",
            query_text=f"currentmarker{run_id}",
            metadata_filter={"document_revision": "revision-current"},
            context_refs=[source_ref],
            max_results=5,
        )
    )
    tenant_a_old = backend.search(
        RagSearchRequest(
            tenant_id=tenant_a,
            claim_id="claim-hybrid-old-a",
            query_text=f"obsoletealpha{run_id}",
            metadata_filter={"document_revision": "revision-old"},
            context_refs=[source_ref],
            max_results=5,
        )
    )
    tenant_b_old = backend.search(
        RagSearchRequest(
            tenant_id=tenant_b,
            claim_id="claim-hybrid-old-b",
            query_text=f"tenantbmarker{run_id}",
            metadata_filter={"document_revision": "revision-old"},
            context_refs=[source_ref],
            max_results=5,
        )
    )
    if [item.evidence_id for item in tenant_a_current] != [f"ev_{run_id}_a_current"]:
        raise RuntimeError(
            "Hybrid smoke tenant A current revision lookup was incorrect."
        )
    if tenant_a_old:
        raise RuntimeError("Hybrid smoke stale revision cleanup failed for tenant A.")
    if [item.evidence_id for item in tenant_b_old] != [f"ev_{run_id}_b_old"]:
        raise RuntimeError("Hybrid smoke reconciliation crossed a tenant boundary.")

    retrieval = tenant_a_current[0].structured_content.get("retrieval")
    if not isinstance(retrieval, Mapping) or retrieval.get("ranker") != (
        "persistent_hybrid_rrf_v1"
    ):
        raise RuntimeError("Hybrid smoke did not return the fused ranker trace.")
    rankers = retrieval.get("rankers")
    if not isinstance(rankers, Mapping):
        raise RuntimeError("Hybrid smoke fused ranker observations are missing.")
    for ranker in ("opensearch_bm25_v1", "pgvector_cosine_v1"):
        observation = rankers.get(ranker)
        if (
            not isinstance(observation, Mapping)
            or observation.get("matched") is not True
        ):
            raise RuntimeError(
                "Hybrid smoke did not prove participation by both rankers."
            )

    return {
        "indexed_count": sum(write.indexed_count for write in writes),
        "tenant_isolation": True,
        "fusion_proven": True,
        "scoped_reconciliation": True,
    }


def validate_run_id(run_id: str) -> str:
    normalized = run_id.strip().lower()
    if SAFE_RUN_ID_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            "Hybrid RAG smoke run ID must be 1-20 lowercase letters or digits."
        )
    return normalized


def validate_database_name(name: str) -> str:
    if SAFE_DATABASE_PATTERN.fullmatch(name) is None:
        raise ValueError(
            "Hybrid RAG smoke database name is outside the dedicated namespace."
        )
    return name


def validate_index_name(name: str) -> str:
    if SAFE_INDEX_PATTERN.fullmatch(name) is None:
        raise ValueError(
            "Hybrid RAG smoke index name is outside the dedicated namespace."
        )
    return name


def validate_template_name(name: str) -> str:
    if SAFE_TEMPLATE_PATTERN.fullmatch(name) is None:
        raise ValueError(
            "Hybrid RAG smoke template name is outside the dedicated namespace."
        )
    return name


def validate_opensearch_endpoint(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            f"{OPENSEARCH_ENDPOINT_ENV} must be a credential-free HTTP(S) origin"
        )
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _create_scratch_database(
    connect: SmokeConnect,
    *,
    admin_dsn: str,
    database_name: str,
    timeout_seconds: float,
) -> None:
    safe_name = validate_database_name(database_name)
    with _admin_connection(connect, admin_dsn, timeout_seconds) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE {safe_name}")


def _drop_scratch_database(
    connect: SmokeConnect,
    *,
    admin_dsn: str,
    database_name: str,
    timeout_seconds: float,
) -> None:
    safe_name = validate_database_name(database_name)
    with _admin_connection(connect, admin_dsn, timeout_seconds) as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"DROP DATABASE IF EXISTS {safe_name} WITH (FORCE)")


def _admin_connection(
    connect: SmokeConnect,
    admin_dsn: str,
    timeout_seconds: float,
) -> SmokeAdminConnection:
    timeout_milliseconds = max(1, math.ceil(timeout_seconds * 1000))
    return connect(
        admin_dsn,
        autocommit=True,
        connect_timeout=max(1, math.ceil(timeout_seconds)),
        options=f"-c statement_timeout={timeout_milliseconds}",
    )


def _scratch_dsn(
    admin_dsn: str,
    *,
    database_name: str,
    timeout_seconds: float,
    conninfo_to_dict: ConninfoToDict,
    make_conninfo: MakeConninfo,
) -> str:
    parameters: dict[str, object] = dict(conninfo_to_dict(admin_dsn))
    parameters["dbname"] = validate_database_name(database_name)
    parameters["connect_timeout"] = max(1, math.ceil(timeout_seconds))
    timeout_milliseconds = max(1, math.ceil(timeout_seconds * 1000))
    parameters["options"] = (
        f"-c lock_timeout={timeout_milliseconds} "
        f"-c statement_timeout={timeout_milliseconds}"
    )
    return make_conninfo(**parameters)


def _create_smoke_index(
    transport: OpenSearchTransport,
    *,
    index_name: str,
    timeout_seconds: float,
) -> None:
    safe_name = validate_index_name(index_name)
    response = transport.request_json(
        "PUT",
        f"/{safe_name}",
        {},
        timeout_seconds=timeout_seconds,
    )
    if response.get("acknowledged") is not True:
        raise RuntimeError("OpenSearch did not acknowledge the scratch index.")


def _delete_smoke_index(
    transport: OpenSearchTransport,
    *,
    index_name: str,
    timeout_seconds: float,
) -> None:
    safe_name = validate_index_name(index_name)
    response = transport.request_json(
        "DELETE",
        f"/{safe_name}?ignore_unavailable=true",
        {},
        timeout_seconds=timeout_seconds,
    )
    if response.get("acknowledged") is not True:
        raise RuntimeError("OpenSearch did not acknowledge scratch index cleanup.")


def _delete_smoke_template(
    transport: OpenSearchTransport,
    *,
    template_name: str,
    timeout_seconds: float,
) -> None:
    safe_name = validate_template_name(template_name)
    response = transport.request_json(
        "DELETE",
        f"/_index_template/{safe_name}",
        {},
        timeout_seconds=timeout_seconds,
    )
    if response.get("acknowledged") is not True:
        raise RuntimeError("OpenSearch did not acknowledge scratch template cleanup.")


def _smoke_template(index_name: str) -> dict[str, object]:
    safe_name = validate_index_name(index_name)
    payload = json.loads(INDEX_TEMPLATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("OpenSearch evidence index template is invalid.")
    payload["index_patterns"] = [safe_name]
    return payload


def _raise_cleanup_failures(
    primary_error: BaseException | None,
    cleanup_errors: Sequence[Exception],
) -> None:
    if not cleanup_errors:
        return
    if primary_error is None:
        raise ExceptionGroup(
            "Hybrid RAG smoke resource cleanup failed.",
            list(cleanup_errors),
        )
    raise BaseExceptionGroup(
        "Hybrid RAG smoke execution and resource cleanup failed.",
        [primary_error, *cleanup_errors],
    )


def _load_psycopg_runtime() -> tuple[
    SmokeConnect,
    object,
    ConninfoToDict,
    MakeConninfo,
]:
    try:
        psycopg = import_module("psycopg")
        rows = import_module("psycopg.rows")
        conninfo = import_module("psycopg.conninfo")
    except ImportError as exc:
        raise RuntimeError("Hybrid RAG live smoke requires psycopg.") from exc
    connect = getattr(psycopg, "connect", None)
    row_factory = getattr(rows, "dict_row", None)
    conninfo_to_dict = getattr(conninfo, "conninfo_to_dict", None)
    make_conninfo = getattr(conninfo, "make_conninfo", None)
    if not all(callable(item) for item in (connect, conninfo_to_dict, make_conninfo)):
        raise RuntimeError("Hybrid RAG live smoke psycopg runtime is incomplete.")
    return (
        cast(SmokeConnect, connect),
        row_factory,
        cast(ConninfoToDict, conninfo_to_dict),
        cast(MakeConninfo, make_conninfo),
    )


def _ssl_context(ca_path: Path | None) -> ssl.SSLContext | None:
    if ca_path is None:
        return None
    try:
        return ssl.create_default_context(cafile=str(ca_path))
    except (OSError, ssl.SSLError):
        raise RuntimeError(
            "Hybrid RAG smoke OpenSearch CA could not be loaded."
        ) from None


def _enabled(value: str) -> bool:
    return value.strip().lower() == "true"


def _parse_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise ValueError(f"{TIMEOUT_ENV} must be a positive number") from exc
    if timeout <= 0 or not math.isfinite(timeout):
        raise ValueError(f"{TIMEOUT_ENV} must be positive and finite")
    return timeout


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> int:
    del argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        result = {
            "status": "failed",
            "error": "Hybrid RAG live smoke failed.",
            "error_type": type(exc).__name__,
            "backend": "hybrid",
            "tenant_isolation": False,
            "fusion_proven": False,
            "scoped_reconciliation": False,
        }
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
