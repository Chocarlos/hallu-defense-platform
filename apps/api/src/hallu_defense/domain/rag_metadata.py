from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import TypeAlias

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]

RAG_METADATA_LIMITS_VERSION = "rag-metadata-limits.v1"
METADATA_FILTER_TOKEN_VERSION = "rag-metadata-filter-token.v1"

MAX_METADATA_TOP_LEVEL_KEYS = 32
MAX_METADATA_SERIALIZED_BYTES = 16 * 1024
MAX_METADATA_DEPTH = 4
MAX_METADATA_NODES = 256
MAX_METADATA_FILTERS = 8
MAX_METADATA_FILTER_KEY_LENGTH = 64
MAX_METADATA_FILTER_VALUE_BYTES = 512
MAX_METADATA_FILTER_SERIALIZED_BYTES = 2 * 1024
MIN_SIGNED_INT64 = -(2**63)
MAX_SIGNED_INT64 = 2**63 - 1

SAFE_METADATA_FILTER_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RESERVED_METADATA_KEYS = frozenset(
    {
        "corpus_id",
        "document_revision",
        "owner_tenant_id",
        "tenant_id",
    }
)
RESERVED_METADATA_PREFIXES = ("structural_",)
VALID_STALENESS_CLASSES = frozenset({"fresh", "acceptable", "stale", "unknown"})


class RagMetadataValidationError(ValueError):
    pass


def validate_metadata(metadata: Mapping[str, object]) -> dict[str, JsonValue]:
    """Validate and normalize bounded JSON metadata for deterministic storage."""

    if len(metadata) > MAX_METADATA_TOP_LEVEL_KEYS:
        raise RagMetadataValidationError(
            f"metadata exceeds {MAX_METADATA_TOP_LEVEL_KEYS} top-level keys "
            f"({RAG_METADATA_LIMITS_VERSION})"
        )
    counter = _NodeCounter()
    normalized = _normalize_json_value(dict(metadata), depth=1, counter=counter)
    if not isinstance(normalized, dict):
        raise RagMetadataValidationError("metadata must be a JSON object")
    encoded = _encode_canonical_json(normalized)
    if len(encoded) > MAX_METADATA_SERIALIZED_BYTES:
        raise RagMetadataValidationError(
            f"metadata exceeds {MAX_METADATA_SERIALIZED_BYTES} canonical UTF-8 bytes "
            f"({RAG_METADATA_LIMITS_VERSION})"
        )
    return normalized


def validate_metadata_filter(metadata_filter: Mapping[str, object]) -> dict[str, JsonValue]:
    """Validate an exact, top-level metadata filter shared by every backend."""

    if len(metadata_filter) > MAX_METADATA_FILTERS:
        raise RagMetadataValidationError(
            f"metadata_filter exceeds {MAX_METADATA_FILTERS} entries "
            f"({RAG_METADATA_LIMITS_VERSION})"
        )

    normalized: dict[str, JsonValue] = {}
    counter = _NodeCounter()
    counter.increment()
    for key, value in sorted(metadata_filter.items()):
        validate_metadata_filter_key(key)
        normalized_value = _normalize_json_value(value, depth=2, counter=counter)
        value_bytes = _encode_canonical_json(normalized_value)
        if len(value_bytes) > MAX_METADATA_FILTER_VALUE_BYTES:
            raise RagMetadataValidationError(
                "metadata_filter value for "
                f"{key!r} exceeds {MAX_METADATA_FILTER_VALUE_BYTES} canonical UTF-8 bytes "
                f"({RAG_METADATA_LIMITS_VERSION})"
            )
        normalized[key] = normalized_value

    encoded = _encode_canonical_json(normalized)
    if len(encoded) > MAX_METADATA_FILTER_SERIALIZED_BYTES:
        raise RagMetadataValidationError(
            "metadata_filter exceeds "
            f"{MAX_METADATA_FILTER_SERIALIZED_BYTES} canonical UTF-8 bytes "
            f"({RAG_METADATA_LIMITS_VERSION})"
        )
    return normalized


def validate_metadata_filter_key(key: object) -> str:
    if not isinstance(key, str):
        raise RagMetadataValidationError("metadata_filter keys must be strings")
    if len(key) > MAX_METADATA_FILTER_KEY_LENGTH:
        raise RagMetadataValidationError(
            f"metadata_filter keys must be at most {MAX_METADATA_FILTER_KEY_LENGTH} characters"
        )
    if SAFE_METADATA_FILTER_KEY_PATTERN.fullmatch(key) is None:
        raise RagMetadataValidationError(
            "metadata_filter keys must match ^[A-Za-z_][A-Za-z0-9_]*$"
        )
    return key


def reject_reserved_ingestion_metadata(metadata: Mapping[str, object]) -> None:
    for key in metadata:
        if isinstance(key, str) and (
            key in RESERVED_METADATA_KEYS or key.startswith(RESERVED_METADATA_PREFIXES)
        ):
            raise RagMetadataValidationError(
                f"RAG metadata key {key!r} is server-managed and cannot be supplied"
            )


def validate_persistable_text(value: str) -> str:
    _validate_unicode_text(value)
    return value


def validate_document_freshness_metadata(metadata: Mapping[str, object]) -> None:
    if "published_at" in metadata:
        published_at = metadata["published_at"]
        if not isinstance(published_at, str) or not published_at.strip():
            raise RagMetadataValidationError(
                "metadata published_at must be a timezone-aware RFC3339 string"
            )
        try:
            parsed = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        except ValueError:
            raise RagMetadataValidationError(
                "metadata published_at must be a timezone-aware RFC3339 string"
            ) from None
        if parsed.utcoffset() is None:
            raise RagMetadataValidationError(
                "metadata published_at must be a timezone-aware RFC3339 string"
            )
    if "staleness_class" in metadata:
        staleness = metadata["staleness_class"]
        if not isinstance(staleness, str) or staleness not in VALID_STALENESS_CLASSES:
            raise RagMetadataValidationError(
                "metadata staleness_class must be fresh, acceptable, stale, or unknown"
            )


def canonical_json(value: object) -> str:
    normalized = _normalize_json_value(value, depth=1, counter=_NodeCounter())
    return _encode_canonical_json(normalized).decode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    return canonical_json(value).encode("utf-8")


def metadata_values_equal(actual: object, expected: object) -> bool:
    try:
        return canonical_json_bytes(actual) == canonical_json_bytes(expected)
    except RagMetadataValidationError:
        return False


def metadata_filter_token(key: str, value: object) -> str:
    validate_metadata_filter_key(key)
    normalized_filter = validate_metadata_filter({key: value})
    token_input = _encode_canonical_json([key, normalized_filter[key]])
    digest = hashlib.sha256(token_input).hexdigest()
    return f"{METADATA_FILTER_TOKEN_VERSION}:{digest}"


def metadata_filter_tokens(metadata: Mapping[str, object]) -> list[str]:
    normalized = validate_metadata(metadata)
    tokens: list[str] = []
    for key, value in sorted(normalized.items()):
        if (
            len(key) <= MAX_METADATA_FILTER_KEY_LENGTH
            and SAFE_METADATA_FILTER_KEY_PATTERN.fullmatch(key) is not None
            and len(_encode_canonical_json(value)) <= MAX_METADATA_FILTER_VALUE_BYTES
        ):
            tokens.append(metadata_filter_token(key, value))
    return tokens


class _NodeCounter:
    def __init__(self) -> None:
        self.count = 0

    def increment(self) -> None:
        self.count += 1
        if self.count > MAX_METADATA_NODES:
            raise RagMetadataValidationError(
                f"metadata exceeds {MAX_METADATA_NODES} JSON nodes "
                f"({RAG_METADATA_LIMITS_VERSION})"
            )


def _normalize_json_value(
    value: object,
    *,
    depth: int,
    counter: _NodeCounter,
) -> JsonValue:
    counter.increment()
    if depth > MAX_METADATA_DEPTH:
        raise RagMetadataValidationError(
            f"metadata exceeds maximum JSON depth {MAX_METADATA_DEPTH} "
            f"({RAG_METADATA_LIMITS_VERSION})"
        )
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        _validate_unicode_text(value)
        return value
    if isinstance(value, int):
        if not MIN_SIGNED_INT64 <= value <= MAX_SIGNED_INT64:
            raise RagMetadataValidationError("metadata integers must fit signed 64-bit range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RagMetadataValidationError("metadata numbers must be finite")
        if value == 0:
            return 0
        if value.is_integer() and MIN_SIGNED_INT64 <= value <= MAX_SIGNED_INT64:
            return int(value)
        return value
    if isinstance(value, Mapping):
        normalized_mapping: dict[str, JsonValue] = {}
        for raw_key, nested_value in sorted(value.items(), key=lambda item: str(item[0])):
            if not isinstance(raw_key, str):
                raise RagMetadataValidationError("metadata object keys must be strings")
            _validate_unicode_text(raw_key)
            normalized_mapping[raw_key] = _normalize_json_value(
                nested_value,
                depth=depth + 1,
                counter=counter,
            )
        return normalized_mapping
    if isinstance(value, list):
        return [
            _normalize_json_value(item, depth=depth + 1, counter=counter)
            for item in value
        ]
    raise RagMetadataValidationError(
        f"metadata contains non-JSON value of type {type(value).__name__}"
    )


def _encode_canonical_json(value: JsonValue) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return encoded.encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError):
        raise RagMetadataValidationError("metadata is not canonical JSON") from None


def _validate_unicode_text(value: str) -> None:
    if "\x00" in value or any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise RagMetadataValidationError(
            "metadata strings and keys must not contain NUL or surrogate code points"
        )
