from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast
from urllib.parse import unquote

from hallu_defense.domain.models import Evidence

ThreatType = Literal["prompt_injection", "indirect_prompt_injection", "data_poisoning"]
ThreatSourceKind = Literal["user_message", "document", "tool_output", "evidence"]

REDACTED_SECRET = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_SSN = "[REDACTED_SSN]"
REDACTED_PHONE = "[REDACTED_PHONE]"
REDACTED_CARD = "[REDACTED_CARD]"
REDACTED_PASSPORT = "[REDACTED_PASSPORT]"
REDACTED_DOB = "[REDACTED_DOB]"
REDACTED_ADDRESS = "[REDACTED_ADDRESS]"
REDACTED_KEY = "[REDACTED_KEY]"
REDACTED_UNSAFE_STRUCTURE = "[REDACTED_UNSAFE_STRUCTURE]"

_REDACTED_PLACEHOLDERS = {
    REDACTED_SECRET.casefold(),
    REDACTED_EMAIL.casefold(),
    REDACTED_SSN.casefold(),
    REDACTED_PHONE.casefold(),
    REDACTED_CARD.casefold(),
    REDACTED_PASSPORT.casefold(),
    REDACTED_DOB.casefold(),
    REDACTED_ADDRESS.casefold(),
    REDACTED_KEY.casefold(),
    REDACTED_UNSAFE_STRUCTURE.casefold(),
    "<redacted>",
    "<set-at-runtime>",
}
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_LABELED_COMPACT_SSN_RE = re.compile(
    r"(?i)(?P<label>\b(?:ssn|social\s+security\s+number)\s*[:=]\s*)"
    r"(?P<quote>['\"]?)(?!(?:000|666|9\d{2}))\d{3}(?!00)\d{2}"
    r"(?!0000)\d{4}(?P=quote)(?!\d)"
)
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})"
    r"[\s.-][2-9]\d{2}[\s.-]\d{4}(?!\w)"
)
_LABELED_COMPACT_PHONE_RE = re.compile(
    r"(?i)(?P<label>\b(?:phone|telephone|mobile)\s*[:=]\s*)"
    r"(?P<quote>['\"]?)(?:(?:\+?1)[\s.-]?)?"
    r"[2-9]\d{2}[2-9]\d{2}\d{4}(?P=quote)(?!\d)"
)
_PAYMENT_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_PASSPORT_ASSIGNMENT_RE = re.compile(
    r"(?i)\bpassport(?:\s+(?:number|no\.?))?\s*[:=]\s*[A-Z0-9-]{5,20}\b"
)
_DOB_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:dob|date\s+of\s+birth|birth\s+date)\s*[:=]\s*"
    r"(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b"
)
_ADDRESS_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:home\s+|mailing\s+|street\s+)?address\s*[:=]\s*[^\r\n;]{5,128}"
)
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN[ \t]+[A-Z0-9 ]+-----.*?(?:-----END[ \t]+[A-Z0-9 ]+-----|\Z)",
    re.I | re.S,
)
_CREDENTIAL_HEADER_RE = re.compile(
    r"(?im)(?:\A|(?<=[\r\n\u2028\u2029]))"
    r"(?P<indent>[ \t]*)(?P<name>Proxy[-_.]?Authorization|Authorization|"
    r"Set[-_.]?Cookie|Cookie|X[-_.]?Forwarded[-_.]?Authorization|"
    r"X[-_.]?Goog[-_.]?Signature|X[-_.]?Amz[-_.]?Security[-_.]?Token|"
    r"X[-_.]?Goog[-_.]?Credential|X[-_.]?API[-_.]?Key|"
    r"X[-_.]?Access[-_.]?Token|X[-_.]?Auth[-_.]?Token)"
    r"[ \t]*:[^\r\n\u2028\u2029]*"
    r"(?:(?:\r\n|[\r\n\u2028\u2029])[ \t]+[^\r\n\u2028\u2029]*)*"
)
_URL_CREDENTIAL_VALUE_PATTERN = (
    r'"(?:\\.|[^"\\\r\n])*"|'
    r"'(?:\\.|[^'\\\r\n])*'|"
    r'"(?:\\.|[^"\\\r\n&#;])*?(?=[&#;\s]|\Z)|'
    r"'(?:\\.|[^'\\\r\n&#;])*?(?=[&#;\s]|\Z)|"
    r'''[^&#;\s"'\\]+'''
)
_SIGNED_URL_QUERY_RE = re.compile(
    r"(?i)(?P<prefix>(?:[?;]|&amp;|&)(?:x-amz-signature|access_token|"
    r"signature|sig|token)=)"
    rf"(?P<credential>{_URL_CREDENTIAL_VALUE_PATTERN})"
)
_URL_QUERY_PARAMETER_RE = re.compile(
    r"(?i)(?P<prefix>(?:[?;]|&amp;|&))"
    r"(?P<name>(?:%[0-9a-f]{2}|[a-z0-9_.~-])+?)="
    rf"(?P<credential>{_URL_CREDENTIAL_VALUE_PATTERN})"
)
_SIGNED_URL_CREDENTIAL_NAMES = frozenset(
    {
        "access_token",
        "sig",
        "signature",
        "token",
        "x_access_token",
        "x_amz_security_token",
        "x_amz_signature",
        "x_api_key",
        "x_auth_token",
        "x_goog_credential",
        "x_goog_signature",
    }
)
_SIGNED_URL_CREDENTIAL_COMPACT_NAMES = frozenset(
    name.replace("_", "") for name in _SIGNED_URL_CREDENTIAL_NAMES
)
_JSON_SCALAR_FIELD_RE = re.compile(
    r'(?P<prefix>"(?P<key>(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|'
    r'[^"\\\r\n])*)"[ \t\r\n\u2028\u2029]*:[ \t\r\n\u2028\u2029]*)'
    r'(?P<value>"(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|'
    r'[^"\\\r\n])*"|(?:true|false|null|-?(?:0|[1-9]\d*)'
    r'(?:\.\d+)?(?:[eE][+-]?\d+)?))'
)
_JSON_FIELD_PREFIX_RE = re.compile(
    r'(?<!\\)"(?P<key>(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|'
    r'[^"\\\r\n])*)"\s*:\s*'
)
_JSON_COMPACT_SSN_FIELD_RE = re.compile(
    r'(?i)(?P<prefix>"(?:ssn|social[\s_-]?security[\s_-]?number)"'
    r'[ \t]*:[ \t]*)"?(?!(?:000|666|9\d{2}))\d{3}(?!00)\d{2}'
    r'(?!0000)\d{4}"?'
)
_JSON_COMPACT_PHONE_FIELD_RE = re.compile(
    r'(?i)(?P<prefix>"(?:phone|telephone|mobile)"[ \t]*:[ \t]*)'
    r'"?(?:(?:\+?1)[\s.-]?)?[2-9]\d{2}[2-9]\d{2}\d{4}"?'
)
_SHARED_ACCESS_SIGNATURE_RE = re.compile(
    r"(?i)\bShared[\s_-]?Access[\s_-]?Signature\b"
    r"(?:[ \t]*[:=][ \t]*|[ \t]+)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:api[\s_-]?key|access[\s_-]?key|account[\s_-]?key|"
    r"shared[\s_-]?access[\s_-]?key|authorization|bearer|credential|"
    r"proxy[\s_-]?authorization|client[\s_-]?secret|password|"
    r"private[\s_-]?key|secret|token)\b"
    r"[ \t]*[:=](?![ \t]*\[REDACTED\])[ \t]*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n,;&]+)"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@"),
    _SECRET_ASSIGNMENT_RE,
)


@dataclass(frozen=True)
class RedactionLimits:
    """Resource limits for defensive traversal of attacker-controlled values."""

    max_depth: int = 32
    max_nodes: int = 4_096
    max_items_per_container: int = 1_024
    max_string_chars: int = 65_536
    max_total_string_chars: int = 262_144
    max_number_chars: int = 128

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if value < 1:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True)
class RedactionResult:
    value: object
    secret_found: bool
    pii_found: bool
    complete: bool
    violations: tuple[str, ...]


@dataclass
class _RedactionState:
    nodes: int = 0
    string_chars: int = 0
    secret_found: bool = False
    pii_found: bool = False
    violations: list[str] = field(default_factory=list)
    active_container_ids: set[int] = field(default_factory=set)

    def violate(self, reason: str) -> None:
        if reason not in self.violations:
            self.violations.append(reason)


class SensitiveDataRedactor:
    """Bounded, cycle-safe redaction for JSON-like untrusted values.

    Any traversal violation replaces the complete containing structure with a
    fixed marker. Callers can therefore reject incomplete results without ever
    serializing the unsafe subtree.
    """

    def __init__(self, limits: RedactionLimits | None = None) -> None:
        self._limits = limits or RedactionLimits()

    def redact(self, value: object) -> RedactionResult:
        state = _RedactionState()
        sanitized = self._visit(value, depth=0, state=state, keyed_marker=None)
        if state.violations:
            sanitized = REDACTED_UNSAFE_STRUCTURE
        return RedactionResult(
            value=sanitized,
            secret_found=state.secret_found,
            pii_found=state.pii_found,
            complete=not state.violations,
            violations=tuple(state.violations),
        )

    def redact_text(self, value: str) -> RedactionResult:
        return self.redact(value)

    def _visit(
        self,
        value: object,
        *,
        depth: int,
        state: _RedactionState,
        keyed_marker: str | None,
    ) -> object:
        if state.violations:
            return REDACTED_UNSAFE_STRUCTURE
        if depth > self._limits.max_depth:
            state.violate("max_depth_exceeded")
            return REDACTED_UNSAFE_STRUCTURE
        state.nodes += 1
        if state.nodes > self._limits.max_nodes:
            state.violate("max_nodes_exceeded")
            return REDACTED_UNSAFE_STRUCTURE

        if keyed_marker is not None and not self._is_redacted_placeholder(value):
            if keyed_marker == REDACTED_SECRET:
                state.secret_found = True
            else:
                state.pii_found = True
            if isinstance(value, str):
                self._account_string_chars(len(value), state)
            elif isinstance(value, bytes | bytearray):
                self._account_string_chars(len(value), state)
            elif isinstance(value, int) and not isinstance(value, bool):
                self._account_integer(value, state)
            elif isinstance(value, float):
                self._account_float(value, state)
            elif value is None or isinstance(value, bool):
                pass
            elif isinstance(value, Mapping):
                self._visit_mapping(value, depth=depth, state=state)
            elif isinstance(value, list | tuple | set | frozenset):
                self._visit_sequence(value, depth=depth, state=state)
            else:
                state.violate("unsupported_type")
            if state.violations:
                return REDACTED_UNSAFE_STRUCTURE
            return keyed_marker

        if isinstance(value, str):
            return self._redact_string(value, state, depth=depth)
        if isinstance(value, bytes | bytearray):
            if not self._account_string_chars(len(value), state):
                return REDACTED_UNSAFE_STRUCTURE
            return self._redact_string(
                bytes(value).decode("utf-8", errors="replace"),
                state,
                depth=depth,
                already_accounted=True,
            )
        if isinstance(value, int) and not isinstance(value, bool):
            if not self._account_integer(value, state):
                return REDACTED_UNSAFE_STRUCTURE
            return value
        if isinstance(value, float):
            if not self._account_float(value, state):
                return REDACTED_UNSAFE_STRUCTURE
            return value
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, Mapping):
            return self._visit_mapping(value, depth=depth, state=state)
        if isinstance(value, list | tuple | set | frozenset):
            return self._visit_sequence(value, depth=depth, state=state)

        state.violate("unsupported_type")
        return REDACTED_UNSAFE_STRUCTURE

    def _visit_mapping(
        self,
        value: Mapping[object, object],
        *,
        depth: int,
        state: _RedactionState,
    ) -> object:
        container_id = id(value)
        if container_id in state.active_container_ids:
            state.violate("cycle_detected")
            return REDACTED_UNSAFE_STRUCTURE
        try:
            if len(value) > self._limits.max_items_per_container:
                state.violate("max_items_per_container_exceeded")
                return REDACTED_UNSAFE_STRUCTURE
            items: list[tuple[object, object]] = []
            for index, raw_item_pair in enumerate(value.items()):
                if index >= self._limits.max_items_per_container:
                    state.violate("max_items_per_container_exceeded")
                    return REDACTED_UNSAFE_STRUCTURE
                raw_key, raw_value = raw_item_pair
                items.append((raw_key, raw_value))
        except Exception:
            state.violate("mapping_traversal_failed")
            return REDACTED_UNSAFE_STRUCTURE

        prepared: list[tuple[str, object, str | None]] = []
        prepared_keys: set[str] = set()
        for raw_key, raw_item in items:
            try:
                key = str(raw_key)
            except Exception:
                state.violate("mapping_key_conversion_failed")
                return REDACTED_UNSAFE_STRUCTURE
            if len(key) > self._limits.max_string_chars:
                state.violate("max_string_chars_exceeded")
                return REDACTED_UNSAFE_STRUCTURE
            state.string_chars += len(key)
            if state.string_chars > self._limits.max_total_string_chars:
                state.violate("max_total_string_chars_exceeded")
                return REDACTED_UNSAFE_STRUCTURE
            redacted_key = self._redact_string(
                key,
                state,
                depth=depth,
                already_accounted=True,
                parse_serialized_json=False,
            )
            safe_key = REDACTED_KEY if redacted_key != key else key
            if safe_key in prepared_keys:
                state.violate("mapping_key_collision")
                return REDACTED_UNSAFE_STRUCTURE
            prepared_keys.add(safe_key)
            prepared.append((safe_key, raw_item, self.marker_for_key(key)))

        state.active_container_ids.add(container_id)
        try:
            sanitized: dict[str, object] = {}
            for key, prepared_value, marker in prepared:
                sanitized[key] = self._visit(
                    prepared_value,
                    depth=depth + 1,
                    state=state,
                    keyed_marker=marker,
                )
                if state.violations:
                    return REDACTED_UNSAFE_STRUCTURE
            return sanitized
        finally:
            state.active_container_ids.remove(container_id)

    def _visit_sequence(
        self,
        value: list[object] | tuple[object, ...] | set[object] | frozenset[object],
        *,
        depth: int,
        state: _RedactionState,
    ) -> object:
        container_id = id(value)
        if container_id in state.active_container_ids:
            state.violate("cycle_detected")
            return REDACTED_UNSAFE_STRUCTURE
        if len(value) > self._limits.max_items_per_container:
            state.violate("max_items_per_container_exceeded")
            return REDACTED_UNSAFE_STRUCTURE

        state.active_container_ids.add(container_id)
        try:
            sanitized: list[object] = []
            try:
                iterator = iter(value)
                for index, item in enumerate(iterator):
                    if index >= self._limits.max_items_per_container:
                        state.violate("max_items_per_container_exceeded")
                        return REDACTED_UNSAFE_STRUCTURE
                    sanitized.append(
                        self._visit(
                            item,
                            depth=depth + 1,
                            state=state,
                            keyed_marker=None,
                        )
                    )
                    if state.violations:
                        return REDACTED_UNSAFE_STRUCTURE
            except Exception:
                state.violate("sequence_traversal_failed")
                return REDACTED_UNSAFE_STRUCTURE
            return sanitized
        finally:
            state.active_container_ids.remove(container_id)

    def _redact_string(
        self,
        value: str,
        state: _RedactionState,
        *,
        depth: int,
        already_accounted: bool = False,
        parse_serialized_json: bool = True,
    ) -> str:
        if not already_accounted and not self._account_string_chars(len(value), state):
            return REDACTED_UNSAFE_STRUCTURE
        if _contains_unicode_surrogate(value):
            state.violate("invalid_unicode_surrogate")
            return REDACTED_UNSAFE_STRUCTURE
        if self._is_redacted_placeholder(value):
            return value

        matching_value = unicodedata.normalize("NFKC", value)
        matching_value = "".join(
            character for character in matching_value if unicodedata.category(character) != "Cf"
        )
        composed = (
            self._redact_embedded_json(matching_value, state=state, depth=depth)
            if parse_serialized_json
            else matching_value
        )
        if state.violations:
            return REDACTED_UNSAFE_STRUCTURE
        redacted = _PEM_BLOCK_RE.sub(REDACTED_SECRET, composed)
        redacted = _JSON_SCALAR_FIELD_RE.sub(
            self._redact_json_scalar_secret_field,
            redacted,
        )
        redacted = _CREDENTIAL_HEADER_RE.sub(_redact_credential_header, redacted)
        redacted = _URL_QUERY_PARAMETER_RE.sub(
            _redact_encoded_url_credential,
            redacted,
        )
        redacted = _SIGNED_URL_QUERY_RE.sub(_redact_signed_url_credential, redacted)
        redacted = _SHARED_ACCESS_SIGNATURE_RE.sub(REDACTED_SECRET, redacted)
        for pattern in _SECRET_VALUE_PATTERNS:
            redacted = pattern.sub(REDACTED_SECRET, redacted)
        if self._has_unredacted_sensitive_json_field(redacted):
            state.violate("sensitive_json_field_unparseable")
            return REDACTED_UNSAFE_STRUCTURE
        if redacted != composed:
            state.secret_found = True

        pii_redacted = _EMAIL_RE.sub(REDACTED_EMAIL, redacted)
        pii_redacted = _SSN_RE.sub(REDACTED_SSN, pii_redacted)
        pii_redacted = _JSON_COMPACT_SSN_FIELD_RE.sub(
            lambda match: f'{match.group("prefix")}"{REDACTED_SSN}"',
            pii_redacted,
        )
        pii_redacted = _LABELED_COMPACT_SSN_RE.sub(
            lambda match: (
                f"{match.group('label')}{match.group('quote')}"
                f"{REDACTED_SSN}{match.group('quote')}"
            ),
            pii_redacted,
        )
        pii_redacted = _PHONE_RE.sub(REDACTED_PHONE, pii_redacted)
        pii_redacted = _JSON_COMPACT_PHONE_FIELD_RE.sub(
            lambda match: f'{match.group("prefix")}"{REDACTED_PHONE}"',
            pii_redacted,
        )
        pii_redacted = _LABELED_COMPACT_PHONE_RE.sub(
            lambda match: (
                f"{match.group('label')}{match.group('quote')}"
                f"{REDACTED_PHONE}{match.group('quote')}"
            ),
            pii_redacted,
        )
        pii_redacted = _PASSPORT_ASSIGNMENT_RE.sub(REDACTED_PASSPORT, pii_redacted)
        pii_redacted = _DOB_ASSIGNMENT_RE.sub(REDACTED_DOB, pii_redacted)
        pii_redacted = _ADDRESS_ASSIGNMENT_RE.sub(REDACTED_ADDRESS, pii_redacted)
        pii_redacted = _PAYMENT_CARD_CANDIDATE_RE.sub(_redact_valid_payment_card, pii_redacted)
        if pii_redacted != redacted:
            state.pii_found = True
        if pii_redacted == matching_value:
            return value
        return pii_redacted

    def _redact_embedded_json(
        self,
        value: str,
        *,
        state: _RedactionState,
        depth: int,
    ) -> str:
        decoder = json.JSONDecoder(parse_constant=_reject_nonfinite_json_constant)
        scan_cursor = 0
        emit_cursor = 0
        attempts = 0
        fragments: list[str] = []
        changed = False
        while scan_cursor < len(value):
            object_index = value.find("{", scan_cursor)
            array_index = value.find("[", scan_cursor)
            candidates = [index for index in (object_index, array_index) if index >= 0]
            if not candidates:
                break
            candidate = min(candidates)
            attempts += 1
            if attempts > self._limits.max_nodes:
                state.violate("max_json_candidates_exceeded")
                return REDACTED_UNSAFE_STRUCTURE
            try:
                parsed, end = decoder.raw_decode(value, candidate)
            except RecursionError:
                state.violate("json_decoding_failed")
                return REDACTED_UNSAFE_STRUCTURE
            except (TypeError, ValueError):
                scan_cursor = candidate + 1
                continue
            if not isinstance(parsed, dict | list):
                scan_cursor = candidate + 1
                continue
            sanitized = self._visit(
                parsed,
                depth=depth + 1,
                state=state,
                keyed_marker=None,
            )
            if state.violations:
                return REDACTED_UNSAFE_STRUCTURE
            if sanitized != parsed:
                try:
                    replacement = json.dumps(
                        sanitized,
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                    )
                except (TypeError, ValueError):
                    state.violate("json_redaction_serialization_failed")
                    return REDACTED_UNSAFE_STRUCTURE
                fragments.append(value[emit_cursor:candidate])
                fragments.append(replacement)
                emit_cursor = end
                changed = True
            scan_cursor = end
        if not changed:
            return value
        fragments.append(value[emit_cursor:])
        rendered = "".join(fragments)
        if len(rendered) > self._limits.max_string_chars:
            state.violate("max_string_chars_exceeded")
            return REDACTED_UNSAFE_STRUCTURE
        return rendered

    def _redact_json_scalar_secret_field(self, match: re.Match[str]) -> str:
        try:
            decoded_key = json.loads(f'"{match.group("key")}"')
        except (TypeError, ValueError, json.JSONDecodeError):
            return match.group(0)
        if not isinstance(decoded_key, str):
            return match.group(0)
        if self.marker_for_key(decoded_key) != REDACTED_SECRET:
            return match.group(0)
        return f'{match.group("prefix")}"{REDACTED_SECRET}"'

    def _has_unredacted_sensitive_json_field(self, value: str) -> bool:
        for match in _JSON_FIELD_PREFIX_RE.finditer(value):
            try:
                decoded_key = json.loads(f'"{match.group("key")}"')
            except (TypeError, ValueError):
                continue
            if (
                isinstance(decoded_key, str)
                and self.marker_for_key(decoded_key) == REDACTED_SECRET
            ):
                remainder = value[match.end() :]
                marker = f'"{REDACTED_SECRET}"'
                if not remainder.startswith(marker):
                    return True
                tail = remainder[len(marker) :].lstrip()
                if tail and tail[0] not in {",", "}", "]"}:
                    return True
        return False

    def _account_string_chars(self, length: int, state: _RedactionState) -> bool:
        if length > self._limits.max_string_chars:
            state.violate("max_string_chars_exceeded")
            return False
        state.string_chars += length
        if state.string_chars > self._limits.max_total_string_chars:
            state.violate("max_total_string_chars_exceeded")
            return False
        return True

    def _account_integer(self, value: int, state: _RedactionState) -> bool:
        max_bits = int(self._limits.max_number_chars * 3.322) + 1
        if value.bit_length() > max_bits:
            state.violate("max_number_chars_exceeded")
            return False
        length = len(str(value))
        if length > self._limits.max_number_chars:
            state.violate("max_number_chars_exceeded")
            return False
        state.string_chars += length
        if state.string_chars > self._limits.max_total_string_chars:
            state.violate("max_total_string_chars_exceeded")
            return False
        return True

    def _account_float(self, value: float, state: _RedactionState) -> bool:
        if not math.isfinite(value):
            state.violate("non_finite_number")
            return False
        rendered = repr(value)
        if len(rendered) > self._limits.max_number_chars:
            state.violate("max_number_chars_exceeded")
            return False
        state.string_chars += len(rendered)
        if state.string_chars > self._limits.max_total_string_chars:
            state.violate("max_total_string_chars_exceeded")
            return False
        return True

    def marker_for_key(self, key: str) -> str | None:
        normalized = _normalize_sensitive_key(key)
        compact = normalized.replace("_", "")
        tokens = tuple(token for token in normalized.split("_") if token)
        token_set = set(tokens)

        if normalized in {
            "authorization_policy",
            "authorization_required",
            "cookie_policy",
            "cookie_preferences",
            "password_policy",
            "passwordpolicy",
            "signature_verification",
            "token_count",
            "tokencount",
        } or tokens[-2:] in {
            ("authorization", "policy"),
            ("cookie", "preferences"),
        }:
            return None
        if (
            normalized
            in {
                "accesskey",
                "accesstoken",
                "access_token",
                "accountkey",
                "account_key",
                "apikey",
                "authorization",
                "authtoken",
                "bearertoken",
                "clientsecret",
                "cookie",
                "pem",
                "privatekey",
                "proxy_authorization",
                "set_cookie",
                "sharedaccesskey",
                "sharedaccesssignature",
                "shared_access_key",
                "shared_access_signature",
                "sig",
                "signature",
                "x_amz_signature",
                "x_amz_security_token",
                "x_api_key",
                "x_access_token",
                "x_auth_token",
                "x_goog_credential",
                "x_goog_signature",
            }
            or _is_sensitive_header_path(tokens)
            or _is_sensitive_compact_key(compact)
            or "credential" in token_set
            or "secret" in token_set
            or "password" in token_set
            or "token" in token_set
            or "pem" in token_set
            or _has_adjacent_tokens(tokens, "api", "key")
            or _has_adjacent_tokens(tokens, "access", "key")
            or _has_adjacent_tokens(tokens, "private", "key")
        ):
            return REDACTED_SECRET
        if normalized in {
            "email",
            "email_address",
            "email_addresses",
            "emailaddress",
            "emailaddresses",
            "emails",
        } or normalized.endswith(("_email", "_emails")):
            return REDACTED_EMAIL
        if normalized in {
            "socialsecuritynumber",
            "socialsecuritynumbers",
            "ssn",
            "ssns",
            "social_security_number",
            "social_security_numbers",
        } or normalized.endswith(("_ssn", "_ssns")):
            return REDACTED_SSN
        if normalized in {
            "cell_phone",
            "cell_phones",
            "cellphone",
            "cellphones",
            "mobile",
            "mobiles",
            "phone",
            "phone_number",
            "phone_numbers",
            "phonenumber",
            "phonenumbers",
            "phones",
            "telephone",
            "telephone_number",
            "telephone_numbers",
            "telephonenumber",
            "telephonenumbers",
            "telephones",
        } or normalized.endswith(
            (
                "_mobile",
                "_mobiles",
                "_phone",
                "_phone_number",
                "_phone_numbers",
                "_phones",
                "_telephone",
                "_telephones",
            )
        ):
            return REDACTED_PHONE
        if normalized in {
            "card",
            "card_number",
            "card_numbers",
            "cardnumber",
            "cardnumbers",
            "cards",
            "credit_card",
            "credit_card_number",
            "credit_card_numbers",
            "credit_cards",
            "creditcard",
            "creditcardnumber",
            "creditcardnumbers",
            "creditcards",
            "pan",
        }:
            return REDACTED_CARD
        if "passport" in token_set or normalized in {
            "passportno",
            "passportnumber",
            "passportnumbers",
            "passports",
        }:
            return REDACTED_PASSPORT
        if normalized in {
            "birthdate",
            "birthdates",
            "birthday",
            "birthdays",
            "dateofbirth",
            "dob",
            "dobs",
            "date_of_birth",
            "birth_date",
            "birth_dates",
        }:
            return REDACTED_DOB
        if "address" in token_set or normalized in {
            "address",
            "addresses",
            "homeaddress",
            "homeaddresses",
            "mailingaddress",
            "mailingaddresses",
            "street",
            "streetaddress",
            "streetaddresses",
            "street_address",
            "street_addresses",
        }:
            return REDACTED_ADDRESS
        return None

    @staticmethod
    def _is_redacted_placeholder(value: object) -> bool:
        return isinstance(value, str) and value.strip().casefold() in _REDACTED_PLACEHOLDERS


def _normalize_sensitive_key(value: str) -> str:
    compatible = unicodedata.normalize("NFKC", value)
    compatible = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", compatible)
    compatible = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", compatible)
    normalized = unicodedata.normalize("NFKD", compatible.casefold())
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) not in {"Mn", "Me", "Cf"}
    )
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")


def _contains_unicode_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _has_adjacent_tokens(tokens: tuple[str, ...], first: str, second: str) -> bool:
    return any(left == first and right == second for left, right in zip(tokens, tokens[1:]))


def _is_sensitive_header_path(tokens: tuple[str, ...]) -> bool:
    if not tokens:
        return False
    sensitive_sequences = {
        ("x", "amz", "signature"),
        ("x", "forwarded", "authorization"),
        ("x", "goog", "signature"),
        ("header", "authorization"),
        ("header", "cookie"),
        ("headers", "authorization"),
        ("headers", "cookie"),
    }
    return any(
        tokens[index : index + len(sequence)] == sequence
        for sequence in sensitive_sequences
        for index in range(len(tokens) - len(sequence) + 1)
    )


def _is_sensitive_compact_key(compact: str) -> bool:
    sensitive_fragments = (
        "headerauthorization",
        "headercookie",
        "headersauthorization",
        "headerscookie",
        "xforwardedauthorization",
        "xaccesstoken",
        "xamzsecuritytoken",
        "xamzsignature",
        "xapikey",
        "xauthtoken",
        "xgoogcredential",
        "xgoogsignature",
    )
    return any(fragment in compact for fragment in sensitive_fragments)


def _redact_valid_payment_card(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return match.group(0)
    checksum = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return REDACTED_CARD if checksum % 10 == 0 else match.group(0)


def _redact_credential_header(match: re.Match[str]) -> str:
    return f"{match.group('indent')}{match.group('name')}: {REDACTED_SECRET}"


def _redact_signed_url_credential(match: re.Match[str]) -> str:
    if match.group("credential").startswith(REDACTED_SECRET):
        return match.group(0)
    return f"{match.group('prefix')}{REDACTED_SECRET}"


def _redact_encoded_url_credential(match: re.Match[str]) -> str:
    decoded_name = _normalize_sensitive_key(unquote(match.group("name")))
    if (
        decoded_name not in _SIGNED_URL_CREDENTIAL_NAMES
        and decoded_name.replace("_", "")
        not in _SIGNED_URL_CREDENTIAL_COMPACT_NAMES
    ):
        return match.group(0)
    if match.group("credential").startswith(REDACTED_SECRET):
        return match.group(0)
    return (
        f"{match.group('prefix')}{match.group('name')}="
        f"{REDACTED_SECRET}"
    )


def _reject_nonfinite_json_constant(value: str) -> object:
    raise ValueError(f"Non-finite JSON constant is not allowed: {value}")


@dataclass(frozen=True)
class ContentThreat:
    threat_type: ThreatType
    source_kind: ThreatSourceKind
    source_ref: str
    rule_id: str

    def to_metadata(self) -> dict[str, str]:
        return {
            "threat_type": self.threat_type,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "rule_id": self.rule_id,
        }


class ContentSecurityScanner:
    """Deterministic scanner for untrusted instructions and poisoned evidence markers."""

    _DIRECT_PROMPT_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("ignore_previous_instructions", re.compile(r"\bignore (?:all )?(?:previous|prior|above) instructions\b", re.I)),
        ("disregard_system_instructions", re.compile(r"\bdisregard (?:the )?(?:system|developer) instructions\b", re.I)),
        ("reveal_system_prompt", re.compile(r"\b(?:reveal|print|show|dump) (?:the )?(?:system|developer) prompt\b", re.I)),
        ("jailbreak_roleplay", re.compile(r"\b(?:jailbreak|developer mode|do anything now|dan mode)\b", re.I)),
        ("bypass_policy", re.compile(r"\b(?:bypass|disable|override) (?:the )?(?:safety|policy|guardrail|instructions)\b", re.I)),
    )
    _INDIRECT_PROMPT_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("untrusted_instruction_override", re.compile(r"\b(?:assistant|model|agent) (?:must|should|shall) ignore\b", re.I)),
        ("document_says_ignore_instructions", re.compile(r"\bignore (?:all )?(?:previous|prior|system|developer) instructions\b", re.I)),
        ("exfiltrate_secret_instruction", re.compile(r"\b(?:exfiltrate|leak|send|reveal) (?:secrets?|tokens?|credentials?|system prompt)\b", re.I)),
        ("tool_result_instruction", re.compile(r"\btool result instruction\s*:\s*", re.I)),
    )
    _DATA_POISONING_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("declared_data_poisoning", re.compile(r"\bdata poisoning\s*:", re.I)),
        ("poisoned_evidence_marker", re.compile(r"\bpoisoned[_ -]?evidence\s*[:=]\s*(?:true|1|yes)\b", re.I)),
        ("retrieval_override", re.compile(r"\bretrieval override\s*:\s*", re.I)),
        ("tamper_verification", re.compile(r"\b(?:tamper|override) (?:verification|evidence ranking|retrieval)\b", re.I)),
    )

    def __init__(self, *, redactor: SensitiveDataRedactor | None = None) -> None:
        self._redactor = redactor or SensitiveDataRedactor()

    def scan_user_message(self, text: str, *, source_ref: str = "message") -> list[ContentThreat]:
        return self._scan(
            text,
            source_kind="user_message",
            source_ref=source_ref,
            rules=(("prompt_injection", self._DIRECT_PROMPT_INJECTION_RULES),),
        )

    def scan_document(self, text: str, *, source_ref: str) -> list[ContentThreat]:
        return self._scan(
            text,
            source_kind="document",
            source_ref=source_ref,
            rules=(
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ),
        )

    def scan_tool_output(self, evidence: Evidence) -> list[ContentThreat]:
        return self._scan(
            evidence.content,
            source_kind="tool_output",
            source_ref=evidence.source_ref or evidence.evidence_id,
            rules=(
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ),
        )

    def scan_tool_payload(
        self,
        payload: Mapping[str, object],
        *,
        source_ref: str,
        pre_tool: bool,
    ) -> list[ContentThreat]:
        """Scan an untrusted tool payload without persisting or logging it."""
        redaction = self._redactor.redact(payload)
        if not redaction.complete:
            return [
                ContentThreat(
                    threat_type="data_poisoning",
                    source_kind="user_message" if pre_tool else "tool_output",
                    source_ref=source_ref,
                    rule_id="payload_scan_limit_exceeded",
                )
            ]
        try:
            text = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return [
                ContentThreat(
                    threat_type="data_poisoning",
                    source_kind="user_message" if pre_tool else "tool_output",
                    source_ref=source_ref,
                    rule_id="payload_scan_serialization_failed",
                )
            ]
        rule_list: list[
            tuple[ThreatType, tuple[tuple[str, re.Pattern[str]], ...]]
        ] = []
        if pre_tool:
            rule_list.append(("prompt_injection", self._DIRECT_PROMPT_INJECTION_RULES))
        rule_list.extend(
            [
                ("indirect_prompt_injection", self._INDIRECT_PROMPT_INJECTION_RULES),
                ("data_poisoning", self._DATA_POISONING_RULES),
            ]
        )
        rules = tuple(rule_list)
        return self._scan(
            text,
            source_kind="user_message" if pre_tool else "tool_output",
            source_ref=source_ref,
            rules=rules,
        )

    def mark_evidence(self, evidence: Evidence) -> Evidence:
        threats = self.scan_document(evidence.content, source_ref=evidence.source_ref)
        if not threats:
            return evidence
        raw_security = evidence.structured_content.get("security")
        security: dict[str, object] = dict(raw_security) if isinstance(raw_security, dict) else {}
        security["threats"] = [threat.to_metadata() for threat in threats]
        return evidence.model_copy(
            update={"structured_content": {**evidence.structured_content, "security": security}}
        )

    def threat_attributes(self, threats: list[ContentThreat]) -> dict[str, object]:
        threat_types = {threat.threat_type for threat in threats}
        return {
            "prompt_injection_detected": "prompt_injection" in threat_types,
            "indirect_prompt_injection_detected": "indirect_prompt_injection" in threat_types,
            "data_poisoning_detected": "data_poisoning" in threat_types,
        }

    def threats_from_evidence(self, evidence: list[Evidence]) -> list[ContentThreat]:
        threats: list[ContentThreat] = []
        for item in evidence:
            threats.extend(self.scan_tool_output(item) if item.kind.value == "tool_output" else [])
            security = item.structured_content.get("security")
            if not isinstance(security, dict):
                continue
            raw_threats = security.get("threats")
            if not isinstance(raw_threats, list):
                continue
            for raw in raw_threats:
                if not isinstance(raw, dict):
                    continue
                threat = self._threat_from_metadata(raw, fallback_source_ref=item.source_ref)
                if threat is not None:
                    threats.append(threat)
        return threats

    def _scan(
        self,
        text: str,
        *,
        source_kind: ThreatSourceKind,
        source_ref: str,
        rules: tuple[tuple[ThreatType, tuple[tuple[str, re.Pattern[str]], ...]], ...],
    ) -> list[ContentThreat]:
        findings: list[ContentThreat] = []
        for threat_type, threat_rules in rules:
            for rule_id, pattern in threat_rules:
                if pattern.search(text):
                    findings.append(
                        ContentThreat(
                            threat_type=threat_type,
                            source_kind=source_kind,
                            source_ref=source_ref,
                            rule_id=rule_id,
                        )
                    )
        return findings

    def _threat_from_metadata(
        self,
        raw: dict[object, object],
        *,
        fallback_source_ref: str,
    ) -> ContentThreat | None:
        threat_type = raw.get("threat_type")
        source_kind = raw.get("source_kind")
        rule_id = raw.get("rule_id")
        source_ref = raw.get("source_ref") or fallback_source_ref
        if not isinstance(threat_type, str) or threat_type not in {
            "prompt_injection",
            "indirect_prompt_injection",
            "data_poisoning",
        }:
            return None
        if not isinstance(source_kind, str) or source_kind not in {
            "user_message",
            "document",
            "tool_output",
            "evidence",
        }:
            return None
        if not isinstance(rule_id, str) or not isinstance(source_ref, str):
            return None
        return ContentThreat(
            threat_type=cast(ThreatType, threat_type),
            source_kind=cast(ThreatSourceKind, source_kind),
            source_ref=source_ref,
            rule_id=rule_id,
        )
