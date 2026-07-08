from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import socket
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from hallu_defense.config import Settings
from hallu_defense.services.auth import Principal

_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_MAX_OIDC_JSON_BYTES = 1_048_576


class OidcJwtValidationError(RuntimeError):
    pass


class OidcJwksKeyNotFoundError(OidcJwtValidationError):
    pass


@dataclass(frozen=True)
class _RsaPublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class OidcPrincipalClaims:
    principal: Principal
    tenant_id: str


@dataclass(frozen=True)
class _CachedJwks:
    payload: Mapping[str, object]
    expires_at: float


JsonFetcher = Callable[[str, int], Mapping[str, object]]
Clock = Callable[[], float]


class OidcJwksResolver:
    def __init__(
        self,
        settings: Settings,
        *,
        fetch_json: JsonFetcher | None = None,
        clock: Clock = time.time,
    ) -> None:
        self._settings = settings
        self._fetch_json = fetch_json or fetch_json_url
        self._clock = clock
        self._lock = threading.Lock()
        self._cached_jwks: _CachedJwks | None = None
        self._cached_discovered_jwks_url: str | None = None

    def resolve(self, *, force_refresh: bool = False) -> Mapping[str, object]:
        if self._settings.oidc_jwks_path is not None:
            return load_jwks(self._settings.oidc_jwks_path)

        now = self._clock()
        with self._lock:
            if (
                not force_refresh
                and self._cached_jwks is not None
                and self._cached_jwks.expires_at > now
            ):
                return self._cached_jwks.payload
            jwks_url = self._settings.oidc_jwks_url or self._discovered_jwks_url(force_refresh)
            payload = self._fetch_json(jwks_url, self._settings.oidc_http_timeout_seconds)
            _validate_jwks_shape(payload)
            self._cached_jwks = _CachedJwks(
                payload=payload,
                expires_at=now + self._settings.oidc_jwks_cache_ttl_seconds,
            )
            return payload

    def _discovered_jwks_url(self, force_refresh: bool) -> str:
        if not force_refresh and self._cached_discovered_jwks_url is not None:
            return self._cached_discovered_jwks_url
        discovery_url = self._settings.oidc_discovery_url
        if not discovery_url:
            raise OidcJwtValidationError(
                "OIDC JWKS URL or discovery URL is required when no JWKS path is configured."
            )
        discovery = self._fetch_json(discovery_url, self._settings.oidc_http_timeout_seconds)
        issuer = discovery.get("issuer")
        if issuer != self._settings.oidc_issuer:
            raise OidcJwtValidationError("OIDC discovery issuer does not match configured issuer.")
        jwks_uri = discovery.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.strip():
            raise OidcJwtValidationError("OIDC discovery document must contain jwks_uri.")
        _validate_remote_jwks_url(jwks_uri)
        self._cached_discovered_jwks_url = jwks_uri.strip()
        return self._cached_discovered_jwks_url


class OidcJwtValidator:
    def __init__(self, settings: Settings, jwks: Mapping[str, object]) -> None:
        if not settings.oidc_issuer:
            raise OidcJwtValidationError("OIDC issuer is not configured.")
        if not settings.oidc_audience:
            raise OidcJwtValidationError("OIDC audience is not configured.")
        self._issuer = settings.oidc_issuer
        self._audience = settings.oidc_audience
        self._subject_claim = settings.oidc_subject_claim
        self._roles_claim = settings.oidc_roles_claim
        self._tenant_claim = settings.oidc_tenant_claim
        self._clock_skew_seconds = settings.oidc_clock_skew_seconds
        self._keys = _jwk_keys_by_id(jwks)

    def validate(self, authorization: str | None, *, current_time_seconds: int | None = None) -> OidcPrincipalClaims:
        token = _bearer_token(authorization)
        header, payload, signed_part, signature = _decode_jwt(token)
        if header.get("alg") != "RS256":
            raise OidcJwtValidationError("OIDC JWT alg must be RS256.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OidcJwtValidationError("OIDC JWT kid header is required.")
        key = self._keys.get(kid)
        if key is None:
            raise OidcJwksKeyNotFoundError("OIDC JWT kid was not found in JWKS.")
        _verify_rs256_signature(key, signed_part, signature)
        self._validate_registered_claims(payload, current_time_seconds=current_time_seconds)
        subject = _string_claim(payload, self._subject_claim, required=True)
        tenant_id = _string_claim(payload, self._tenant_claim, required=True)
        roles = frozenset(_roles_claim(payload.get(self._roles_claim)))
        return OidcPrincipalClaims(
            principal=Principal(subject_id=subject, roles=roles),
            tenant_id=tenant_id,
        )

    def _validate_registered_claims(
        self,
        payload: Mapping[str, object],
        *,
        current_time_seconds: int | None,
    ) -> None:
        if payload.get("iss") != self._issuer:
            raise OidcJwtValidationError("OIDC JWT issuer is invalid.")
        aud = payload.get("aud")
        if isinstance(aud, str):
            audience_matches = aud == self._audience
        elif isinstance(aud, Sequence) and not isinstance(aud, (bytes, bytearray, str)):
            audience_matches = self._audience in aud
        else:
            audience_matches = False
        if not audience_matches:
            raise OidcJwtValidationError("OIDC JWT audience is invalid.")

        now = int(time.time()) if current_time_seconds is None else current_time_seconds
        exp = _integer_claim(payload, "exp", required=True)
        if exp is None:
            raise OidcJwtValidationError("OIDC JWT exp claim is required.")
        if now > exp + self._clock_skew_seconds:
            raise OidcJwtValidationError("OIDC JWT is expired.")
        nbf = _integer_claim(payload, "nbf", required=False)
        if nbf is not None and now + self._clock_skew_seconds < nbf:
            raise OidcJwtValidationError("OIDC JWT is not valid yet.")
        iat = _integer_claim(payload, "iat", required=False)
        if iat is not None and now + self._clock_skew_seconds < iat:
            raise OidcJwtValidationError("OIDC JWT issued-at time is in the future.")


def load_jwks(path: Path) -> Mapping[str, object]:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise OidcJwtValidationError("OIDC JWKS file could not be read.") from exc
    except json.JSONDecodeError as exc:
        raise OidcJwtValidationError("OIDC JWKS file is not valid JSON.") from exc
    if not isinstance(payload, Mapping):
        raise OidcJwtValidationError("OIDC JWKS must be a JSON object.")
    jwks = cast(Mapping[str, object], payload)
    _validate_jwks_shape(jwks)
    return jwks


def fetch_json_url(url: str, timeout_seconds: int) -> Mapping[str, object]:
    _validate_remote_jwks_url(url)
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(_MAX_OIDC_JSON_BYTES + 1)
    except HTTPError as exc:
        raise OidcJwtValidationError("OIDC remote JSON request failed.") from exc
    except (OSError, TimeoutError, URLError, socket.timeout) as exc:
        raise OidcJwtValidationError("OIDC remote JSON request could not be completed.") from exc
    if len(raw) > _MAX_OIDC_JSON_BYTES:
        raise OidcJwtValidationError("OIDC remote JSON response is too large.")
    try:
        payload: object = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OidcJwtValidationError("OIDC remote JSON response is not valid JSON.") from exc
    if not isinstance(payload, Mapping):
        raise OidcJwtValidationError("OIDC remote JSON response must be a JSON object.")
    return cast(Mapping[str, object], payload)


def _validate_jwks_shape(jwks: Mapping[str, object]) -> None:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise OidcJwtValidationError("OIDC JWKS must contain a keys array.")


def _validate_remote_jwks_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise OidcJwtValidationError("OIDC remote URL must be an absolute HTTP(S) URL.")


def _jwk_keys_by_id(jwks: Mapping[str, object]) -> dict[str, _RsaPublicKey]:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise OidcJwtValidationError("OIDC JWKS must contain a keys array.")
    by_id: dict[str, _RsaPublicKey] = {}
    for raw_key in keys:
        if not isinstance(raw_key, Mapping):
            continue
        kid = raw_key.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        if raw_key.get("kty") != "RSA":
            continue
        if raw_key.get("use") not in {None, "sig"}:
            continue
        if raw_key.get("alg") not in {None, "RS256"}:
            continue
        by_id[kid] = _rsa_public_key_from_jwk(raw_key)
    if not by_id:
        raise OidcJwtValidationError("OIDC JWKS contains no usable RSA signing keys.")
    return by_id


def _rsa_public_key_from_jwk(jwk: Mapping[str, object]) -> _RsaPublicKey:
    raw_n = jwk.get("n")
    raw_e = jwk.get("e")
    if not isinstance(raw_n, str) or not isinstance(raw_e, str):
        raise OidcJwtValidationError("OIDC RSA JWK must contain n and e.")
    n = int.from_bytes(_base64url_decode(raw_n), "big")
    e = int.from_bytes(_base64url_decode(raw_e), "big")
    if n.bit_length() < 2048:
        raise OidcJwtValidationError("OIDC RSA JWK modulus must be at least 2048 bits.")
    if e <= 1 or e % 2 == 0:
        raise OidcJwtValidationError("OIDC RSA JWK exponent is invalid.")
    return _RsaPublicKey(n=n, e=e)


def _decode_jwt(token: str) -> tuple[Mapping[str, object], Mapping[str, object], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcJwtValidationError("OIDC JWT must have three segments.")
    header = _json_segment(parts[0], "header")
    payload = _json_segment(parts[1], "payload")
    signature = _base64url_decode(parts[2])
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def _json_segment(segment: str, label: str) -> Mapping[str, object]:
    try:
        payload: object = json.loads(_base64url_decode(segment).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OidcJwtValidationError(f"OIDC JWT {label} is not valid JSON.") from exc
    if not isinstance(payload, Mapping):
        raise OidcJwtValidationError(f"OIDC JWT {label} must be a JSON object.")
    if not all(isinstance(key, str) for key in payload):
        raise OidcJwtValidationError(f"OIDC JWT {label} must use string keys.")
    return cast(Mapping[str, object], payload)


def _verify_rs256_signature(
    key: _RsaPublicKey,
    signed_part: bytes,
    signature: bytes,
) -> None:
    expected = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signed_part).digest()
    if len(signature) != key.size_bytes:
        raise OidcJwtValidationError("OIDC JWT signature is invalid.")
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= key.n:
        raise OidcJwtValidationError("OIDC JWT signature is invalid.")
    encoded_message = pow(signature_int, key.e, key.n).to_bytes(key.size_bytes, "big")
    separator_index = encoded_message.find(b"\x00", 2)
    if (
        len(encoded_message) < len(expected) + 11
        or not encoded_message.startswith(b"\x00\x01")
        or separator_index < 10
        or encoded_message[2:separator_index] != b"\xff" * (separator_index - 2)
        or not hmac.compare_digest(encoded_message[separator_index + 1 :], expected)
    ):
        raise OidcJwtValidationError("OIDC JWT signature is invalid.")


def _bearer_token(authorization: str | None) -> str:
    if authorization is None or not authorization.strip():
        raise OidcJwtValidationError("Authorization bearer token is required for oidc_jwt mode.")
    scheme, _, bearer_value = authorization.strip().partition(" ")
    if scheme.lower() != "bearer" or not bearer_value.strip():
        raise OidcJwtValidationError("Authorization header must use Bearer token format.")
    return bearer_value.strip()


def _base64url_decode(value: str) -> bytes:
    padding_length = (-len(value)) % 4
    try:
        return base64.b64decode(
            (value + ("=" * padding_length)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise OidcJwtValidationError("OIDC JWT contains invalid base64url data.") from exc


def _integer_claim(
    payload: Mapping[str, object],
    claim_name: str,
    *,
    required: bool,
) -> int | None:
    value = payload.get(claim_name)
    if value is None:
        if required:
            raise OidcJwtValidationError(f"OIDC JWT {claim_name} claim is required.")
        return None
    if not isinstance(value, int):
        raise OidcJwtValidationError(f"OIDC JWT {claim_name} claim must be an integer.")
    return value


def _string_claim(payload: Mapping[str, object], claim_name: str, *, required: bool) -> str:
    value = payload.get(claim_name)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip():
        raise OidcJwtValidationError(f"OIDC JWT {claim_name} claim must be a non-empty string.")
    return value.strip()


def _roles_claim(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {role for role in value.replace(",", " ").split() if role}
    if isinstance(value, list):
        roles: set[str] = set()
        for role in value:
            if not isinstance(role, str) or not role.strip():
                raise OidcJwtValidationError("OIDC JWT roles claim must contain only strings.")
            roles.add(role.strip())
        return roles
    raise OidcJwtValidationError("OIDC JWT roles claim must be a string or string array.")
