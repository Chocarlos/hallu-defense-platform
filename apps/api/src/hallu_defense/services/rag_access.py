from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from hallu_defense.domain.models import DocumentInput, Evidence
from hallu_defense.domain.rag_metadata import (
    RagMetadataValidationError,
    reject_reserved_ingestion_metadata,
    validate_metadata as validate_bounded_metadata,
    validate_metadata_filter as validate_bounded_metadata_filter,
)
from hallu_defense.services.auth import ADMIN_ROLE
from hallu_defense.services.corpus_grants import CorpusGrantRegistry

CORPUS_ID_METADATA_KEY: Final = "corpus_id"
CORPUS_READER_ROLES_METADATA_KEY: Final = "corpus_reader_roles"
CORPUS_WRITER_ROLES_METADATA_KEY: Final = "corpus_writer_roles"
OWNER_TENANT_METADATA_KEY: Final = "owner_tenant_id"
TENANT_METADATA_KEYS: Final = frozenset({"owner_tenant_id", "tenant_id"})
CORPUS_ROLE_METADATA_KEYS: Final = frozenset(
    {"corpus_reader_roles", "corpus_writer_roles"}
)


class RagAccessDeniedError(PermissionError):
    """Raised when a RAG request references metadata owned by another tenant."""


@dataclass(frozen=True)
class RagAccessPolicy:
    corpus_grant_registry: CorpusGrantRegistry | None = None
    tenant_metadata_keys: frozenset[str] = field(default=TENANT_METADATA_KEYS)
    corpus_role_metadata_keys: frozenset[str] = field(default=CORPUS_ROLE_METADATA_KEYS)
    corpus_metadata_key: str = CORPUS_ID_METADATA_KEY
    corpus_reader_roles_key: str = CORPUS_READER_ROLES_METADATA_KEY
    corpus_writer_roles_key: str = CORPUS_WRITER_ROLES_METADATA_KEY
    owner_metadata_key: str = OWNER_TENANT_METADATA_KEY

    def stamp_document_metadata(
        self,
        document: DocumentInput,
        *,
        tenant_id: str,
        corpus_id: str,
        principal_roles: frozenset[str] = frozenset(),
    ) -> DocumentInput:
        self.validate_ingestion_metadata(
            document.metadata,
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            principal_roles=principal_roles,
        )
        stamped_metadata = {
            **document.metadata,
            self.corpus_metadata_key: corpus_id,
            self.owner_metadata_key: tenant_id,
        }
        try:
            stamped_metadata = dict(validate_bounded_metadata(stamped_metadata))
        except RagMetadataValidationError as exc:
            raise RagAccessDeniedError(str(exc)) from None
        return document.model_copy(update={"metadata": stamped_metadata})

    def validate_ingestion_metadata(
        self,
        metadata: dict[str, object],
        *,
        tenant_id: str,
        corpus_id: str,
        principal_roles: frozenset[str] = frozenset(),
    ) -> None:
        try:
            reject_reserved_ingestion_metadata(metadata)
            validate_bounded_metadata(metadata)
        except RagMetadataValidationError as exc:
            raise RagAccessDeniedError(str(exc)) from None
        self.validate_metadata(metadata, tenant_id=tenant_id)
        self._validate_corpus_role_metadata(metadata)
        writer_roles = self._role_set(metadata.get(self.corpus_writer_roles_key))
        if writer_roles and not self._has_any_role(principal_roles, writer_roles):
            raise RagAccessDeniedError(
                "Principal is missing a corpus writer role required by RAG metadata."
            )
        registry_writer_roles = self._registry_writer_roles(tenant_id, corpus_id)
        if registry_writer_roles and not self._has_any_role(principal_roles, registry_writer_roles):
            raise RagAccessDeniedError(
                "Principal is missing a corpus writer role required by RAG grant registry."
            )

    def validate_metadata_filter(
        self,
        metadata_filter: dict[str, object],
        *,
        tenant_id: str,
    ) -> None:
        try:
            validate_bounded_metadata_filter(metadata_filter)
        except RagMetadataValidationError as exc:
            raise RagAccessDeniedError(str(exc)) from None
        self.validate_metadata(metadata_filter, tenant_id=tenant_id)
        self._validate_corpus_role_metadata(metadata_filter)

    def validate_retrieval_documents(
        self,
        documents: list[DocumentInput],
        *,
        tenant_id: str,
        principal_roles: frozenset[str],
    ) -> None:
        for document in documents:
            self.validate_metadata(document.metadata, tenant_id=tenant_id)
            self._validate_corpus_role_metadata(document.metadata)
            self._require_read_access(document.metadata, tenant_id, principal_roles)

    def filter_evidence_for_read(
        self,
        evidence: list[Evidence],
        claim_evidence_map: dict[str, list[str]],
        *,
        tenant_id: str,
        principal_roles: frozenset[str],
    ) -> tuple[list[Evidence], dict[str, list[str]]]:
        readable = [
            item
            for item in evidence
            if self._metadata_is_readable(self._metadata_for(item), tenant_id, principal_roles)
        ]
        readable_ids = {item.evidence_id for item in readable}
        filtered_map = {
            claim_id: [evidence_id for evidence_id in evidence_ids if evidence_id in readable_ids]
            for claim_id, evidence_ids in claim_evidence_map.items()
        }
        return readable, filtered_map

    def validate_metadata(self, metadata: dict[str, object], *, tenant_id: str) -> None:
        try:
            validate_bounded_metadata(metadata)
        except RagMetadataValidationError as exc:
            raise RagAccessDeniedError(str(exc)) from None
        for key in sorted(self.tenant_metadata_keys.intersection(metadata.keys())):
            if not self._tenant_value_allowed(metadata[key], tenant_id):
                raise RagAccessDeniedError(
                    f"RAG metadata key '{key}' must match the authenticated tenant."
                )

    def _validate_corpus_id(self, metadata: dict[str, object], corpus_id: str) -> None:
        if self.corpus_metadata_key not in metadata:
            return
        value = metadata[self.corpus_metadata_key]
        if not isinstance(value, str) or value != corpus_id:
            raise RagAccessDeniedError(
                f"RAG metadata key '{self.corpus_metadata_key}' must match the request corpus."
            )

    def _validate_corpus_role_metadata(self, metadata: dict[str, object]) -> None:
        for key in sorted(self.corpus_role_metadata_keys.intersection(metadata.keys())):
            self._role_set(metadata[key])

    def _require_read_access(
        self,
        metadata: dict[str, object],
        tenant_id: str,
        principal_roles: frozenset[str],
    ) -> None:
        if not self._metadata_is_readable(metadata, tenant_id, principal_roles):
            raise RagAccessDeniedError(
                "Principal is missing a corpus reader role required by RAG metadata."
            )

    def _metadata_is_readable(
        self,
        metadata: dict[str, object],
        tenant_id: str,
        principal_roles: frozenset[str],
    ) -> bool:
        reader_roles = self._role_set(metadata.get(self.corpus_reader_roles_key))
        if reader_roles and not self._has_any_role(principal_roles, reader_roles):
            return False
        registry_reader_roles = self._registry_reader_roles(tenant_id, metadata)
        return not registry_reader_roles or self._has_any_role(principal_roles, registry_reader_roles)

    def _metadata_for(self, evidence: Evidence) -> dict[str, object]:
        metadata = evidence.structured_content.get("metadata")
        if isinstance(metadata, dict):
            return metadata
        return {}

    def _registry_writer_roles(self, tenant_id: str, corpus_id: str) -> frozenset[str]:
        if self.corpus_grant_registry is None:
            return frozenset()
        grant = self.corpus_grant_registry.get(tenant_id=tenant_id, corpus_id=corpus_id)
        if grant is None:
            return frozenset()
        return frozenset(grant.writer_roles)

    def _registry_reader_roles(
        self,
        tenant_id: str,
        metadata: dict[str, object],
    ) -> frozenset[str]:
        if self.corpus_grant_registry is None:
            return frozenset()
        corpus_id = metadata.get(self.corpus_metadata_key)
        if not isinstance(corpus_id, str) or not corpus_id.strip():
            return frozenset()
        grant = self.corpus_grant_registry.get(tenant_id=tenant_id, corpus_id=corpus_id)
        if grant is None:
            return frozenset()
        return frozenset(grant.reader_roles)

    def _tenant_value_allowed(self, value: object, tenant_id: str) -> bool:
        if isinstance(value, str):
            return value == tenant_id
        if isinstance(value, list):
            return bool(value) and all(
                isinstance(item, str) and item == tenant_id for item in value
            )
        return False

    def _role_set(self, value: object) -> frozenset[str]:
        if value is None:
            return frozenset()
        if isinstance(value, str):
            if value.strip():
                return frozenset({value.strip()})
            raise RagAccessDeniedError("RAG corpus role metadata must not contain empty roles.")
        if isinstance(value, list):
            roles: set[str] = set()
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    raise RagAccessDeniedError(
                        "RAG corpus role metadata must contain only non-empty strings."
                    )
                roles.add(item.strip())
            return frozenset(roles)
        raise RagAccessDeniedError("RAG corpus role metadata must be a string or string list.")

    def _has_any_role(
        self,
        principal_roles: frozenset[str],
        required_roles: frozenset[str],
    ) -> bool:
        return ADMIN_ROLE in principal_roles or bool(principal_roles.intersection(required_roles))
