from __future__ import annotations

import ipaddress
import re
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from email.message import Message
from http.client import HTTPResponse
from typing import IO, Protocol, cast
from urllib import error, request
from urllib.parse import urlsplit

PRODUCTION_LIKE_ENVIRONMENTS = frozenset({"production", "staging"})
DEFAULT_HTTPS_PORT = 443
_AMBIGUOUS_IP_TOKEN_RE = re.compile(r"(?:[0-9]+|0x[0-9a-f]+)", re.IGNORECASE)


class OutboundHttpPolicyError(ValueError):
    """Raised when an outbound endpoint violates the configured origin policy."""


class OutboundHttpRedirectError(RuntimeError):
    """Raised for every HTTP redirect before urllib can follow it."""


class OutboundPolicySettings(Protocol):
    @property
    def environment(self) -> str: ...

    @property
    def outbound_https_allowed_origins(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, order=True)
class CanonicalHttpsOrigin:
    scheme: str
    host: str
    port: int

    @property
    def value(self) -> str:
        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        port_suffix = "" if self.port == DEFAULT_HTTPS_PORT else f":{self.port}"
        return f"{self.scheme}://{rendered_host}{port_suffix}"


@dataclass(frozen=True)
class OutboundHttpPolicy:
    environment: str
    allowed_origins: frozenset[CanonicalHttpsOrigin]

    @classmethod
    def from_values(
        cls,
        *,
        environment: str,
        allowed_origins: Sequence[str],
    ) -> OutboundHttpPolicy:
        normalized_environment = environment.strip().lower()
        production_like = normalized_environment in PRODUCTION_LIKE_ENVIRONMENTS
        if production_like and not allowed_origins:
            raise OutboundHttpPolicyError(
                "Production and staging require a non-empty outbound HTTPS origin allowlist."
            )

        normalized_origins: list[CanonicalHttpsOrigin] = []
        for index, candidate in enumerate(allowed_origins, start=1):
            try:
                origin = canonicalize_https_origin(
                    candidate,
                    reject_unsafe_ip_literals=production_like,
                )
            except (OutboundHttpPolicyError, UnicodeError, ValueError):
                raise OutboundHttpPolicyError(
                    f"Outbound HTTPS allowlist item {index} is invalid."
                ) from None
            if origin in normalized_origins:
                raise OutboundHttpPolicyError(
                    f"Outbound HTTPS allowlist item {index} duplicates another origin."
                )
            normalized_origins.append(origin)

        return cls(
            environment=normalized_environment,
            allowed_origins=frozenset(normalized_origins),
        )

    @classmethod
    def local_unrestricted(cls) -> OutboundHttpPolicy:
        return cls(environment="local", allowed_origins=frozenset())

    @property
    def enforced(self) -> bool:
        return bool(self.allowed_origins) or self.environment in PRODUCTION_LIKE_ENVIRONMENTS

    def validate_url(self, url: str) -> CanonicalHttpsOrigin | None:
        origin = _origin_from_endpoint(
            url,
            require_https=self.enforced,
            reject_unsafe_ip_literals=self.environment in PRODUCTION_LIKE_ENVIRONMENTS,
        )
        if not self.enforced:
            return origin
        if origin is None:
            raise OutboundHttpPolicyError("Outbound endpoint must use HTTPS.")
        if origin not in self.allowed_origins:
            raise OutboundHttpPolicyError(
                "Outbound HTTPS endpoint is not allowed by policy."
            )
        return origin


def outbound_http_policy_from_settings(settings: OutboundPolicySettings) -> OutboundHttpPolicy:
    return OutboundHttpPolicy.from_values(
        environment=settings.environment,
        allowed_origins=settings.outbound_https_allowed_origins,
    )


def canonicalize_https_origin(
    value: str,
    *,
    reject_unsafe_ip_literals: bool = False,
) -> CanonicalHttpsOrigin:
    if not value or value != value.strip() or _has_forbidden_url_characters(value):
        raise OutboundHttpPolicyError("Outbound HTTPS origin is invalid.")
    if "*" in value:
        raise OutboundHttpPolicyError("Outbound HTTPS origins must not contain wildcards.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise OutboundHttpPolicyError("Outbound HTTPS origin is invalid.") from None
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        raise OutboundHttpPolicyError(
            "Outbound HTTPS allowlist entries must be origins without credentials or paths."
        )
    host = _canonical_host(
        parsed.hostname,
        reject_unsafe_ip_literals=reject_unsafe_ip_literals,
    )
    if port is not None and port < 1:
        raise OutboundHttpPolicyError("Outbound HTTPS origin port is invalid.")
    return CanonicalHttpsOrigin(
        scheme="https",
        host=host,
        port=DEFAULT_HTTPS_PORT if port is None else port,
    )


def _origin_from_endpoint(
    value: str,
    *,
    require_https: bool,
    reject_unsafe_ip_literals: bool,
) -> CanonicalHttpsOrigin | None:
    if not value or value != value.strip() or _has_forbidden_url_characters(value):
        raise OutboundHttpPolicyError("Outbound endpoint URL is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise OutboundHttpPolicyError("Outbound endpoint URL is invalid.") from None
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        raise OutboundHttpPolicyError("Outbound endpoint must be an absolute HTTP(S) URL.")
    if require_https and scheme != "https":
        raise OutboundHttpPolicyError("Outbound endpoint must use HTTPS.")
    host = _canonical_host(
        parsed.hostname,
        reject_unsafe_ip_literals=reject_unsafe_ip_literals,
    )
    if port is None:
        port = DEFAULT_HTTPS_PORT if scheme == "https" else 80
    if port < 1:
        raise OutboundHttpPolicyError("Outbound endpoint port is invalid.")
    if scheme == "http":
        return None
    return CanonicalHttpsOrigin(scheme=scheme, host=host, port=port)


def _canonical_host(value: str, *, reject_unsafe_ip_literals: bool) -> str:
    if not value or value.endswith(".") or "%" in value:
        raise OutboundHttpPolicyError("Outbound endpoint host is invalid.")
    try:
        ip_literal = ipaddress.ip_address(value)
    except ValueError:
        try:
            host = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise OutboundHttpPolicyError("Outbound endpoint host is invalid.") from None
        if len(host) > 253:
            raise OutboundHttpPolicyError("Outbound endpoint host is invalid.")
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        ):
            raise OutboundHttpPolicyError("Outbound endpoint host is invalid.")
        if reject_unsafe_ip_literals and (
            host == "localhost"
            or host.endswith(".localhost")
            or _looks_like_ambiguous_ip_literal(host)
        ):
            raise OutboundHttpPolicyError(
                "Loopback aliases and ambiguous IP literals are not permitted in production."
            )
        return host

    if reject_unsafe_ip_literals and (
        ip_literal.is_loopback
        or ip_literal.is_link_local
        or ip_literal.is_unspecified
        or ip_literal.is_multicast
    ):
        raise OutboundHttpPolicyError(
            "Unsafe IP literal is not permitted in production or staging."
        )
    return ip_literal.compressed.lower()


def _looks_like_ambiguous_ip_literal(host: str) -> bool:
    labels = host.split(".")
    return all(_AMBIGUOUS_IP_TOKEN_RE.fullmatch(label) is not None for label in labels)


def _has_forbidden_url_characters(value: str) -> bool:
    return "\\" in value or any(
        ord(character) < 0x20
        or ord(character) == 0x7F
        or character.isspace()
        for character in value
    )


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> request.Request | None:
        try:
            fp.close()
        finally:
            del req, fp, code, msg, headers, newurl
            raise OutboundHttpRedirectError("Outbound HTTP redirects are not allowed.")


def open_url_no_redirect(
    url_request: request.Request,
    *,
    timeout: float,
    context: ssl.SSLContext | None = None,
) -> HTTPResponse:
    handlers: list[request.BaseHandler] = [_NoRedirectHandler()]
    if context is not None:
        handlers.append(request.HTTPSHandler(context=context))
    opener = request.build_opener(*handlers)
    try:
        return cast(HTTPResponse, opener.open(url_request, timeout=timeout))
    except OutboundHttpRedirectError:
        raise
    except error.HTTPError as exc:
        if 300 <= exc.code < 400:
            try:
                exc.close()
            finally:
                raise OutboundHttpRedirectError(
                    "Outbound HTTP redirects are not allowed."
                ) from None
        raise
