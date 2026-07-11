"""Small, dependency-free AWS Signature Version 4 client for S3-compatible drills.

This module intentionally implements only the path-style S3 operations used by
the repository's backup/restore verification. It does not retry writes, follow
redirects, expose response payloads in exceptions, or persist credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import socket
import ssl
import stat
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"
DEFAULT_REGION = "us-east-1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date"
MAX_ERROR_BYTES = 64 * 1024
MAX_LIST_PAGES = 100
MAX_LIST_OBJECTS = 10_000
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class S3SigV4Error(RuntimeError):
    """A redacted S3 transport, protocol, or validation failure."""


@dataclass(frozen=True)
class S3SigV4Config:
    endpoint: str
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    region: str = DEFAULT_REGION
    require_https: bool = False
    allowed_origins: tuple[str, ...] = ()
    allow_private_endpoint: bool = False
    ca_file: Path | None = None


@dataclass(frozen=True)
class S3Object:
    key: str
    size: int


@dataclass(frozen=True)
class _Response:
    status: int
    body: bytes


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated address while preserving TLS SNI/hostname checks."""

    def __init__(
        self,
        hostname: str,
        connect_host: str,
        *,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._connect_host = connect_host

    def connect(self) -> None:
        plain_socket = socket.create_connection(
            (self._connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(
                plain_socket,
                server_hostname=self.host,
            )
        except Exception:
            plain_socket.close()
            raise


class S3SigV4Client:
    def __init__(
        self,
        config: S3SigV4Config,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._endpoint = _validate_config(config)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def ensure_bucket(self, bucket: str, *, timeout_seconds: int) -> None:
        _validate_bucket(bucket)
        deadline = _deadline(timeout_seconds)
        head = self._request(
            "HEAD",
            bucket=bucket,
            timeout_seconds=timeout_seconds,
            deadline=deadline,
            allowed_statuses={200, 204, 404},
        )
        if head.status in {200, 204}:
            return
        created = self._request(
            "PUT",
            bucket=bucket,
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
            allowed_statuses={200, 204, 409},
        )
        if created.status == 409 and _s3_error_code(created.body) != "BucketAlreadyOwnedByYou":
            raise S3SigV4Error("S3 bucket creation failed with HTTP 409.")

    def put_bytes(
        self,
        bucket: str,
        key: str,
        payload: bytes,
        *,
        timeout_seconds: int,
    ) -> None:
        _validate_bucket(bucket)
        _validate_key(key)
        self._request(
            "PUT",
            bucket=bucket,
            key=key,
            payload=payload,
            timeout_seconds=timeout_seconds,
            deadline=_deadline(timeout_seconds),
            allowed_statuses={200, 201, 204},
        )

    def upload_file(
        self,
        bucket: str,
        key: str,
        source: Path,
        *,
        timeout_seconds: int,
    ) -> None:
        _validate_bucket(bucket)
        _validate_key(key)
        deadline = _deadline(timeout_seconds)
        try:
            with source.open("rb", buffering=0) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise S3SigV4Error("S3 upload source must be a regular file.")
                payload_hash = _hash_stream(stream)
                after_hash = os.fstat(stream.fileno())
                if not _same_file_snapshot(before, after_hash):
                    raise S3SigV4Error("S3 upload source changed while it was hashed.")
                stream.seek(0)
                response = self._request_stream(
                    "PUT",
                    bucket=bucket,
                    key=key,
                    stream=stream,
                    content_length=before.st_size,
                    payload_hash=payload_hash,
                    deadline=deadline,
                    allowed_statuses={200, 201, 204},
                )
                _ = response
                after_send = os.fstat(stream.fileno())
                if not _same_file_snapshot(before, after_send):
                    raise S3SigV4Error("S3 upload source changed while it was sent.")
        except S3SigV4Error:
            raise
        except OSError:
            raise S3SigV4Error("S3 upload source could not be read.") from None

    def get_bytes(
        self,
        bucket: str,
        key: str,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> bytes:
        _positive_limit(max_bytes, "S3 download byte limit")
        return self._request(
            "GET",
            bucket=bucket,
            key=key,
            timeout_seconds=timeout_seconds,
            deadline=_deadline(timeout_seconds),
            max_response_bytes=max_bytes,
            allowed_statuses={200},
        ).body

    def download_file(
        self,
        bucket: str,
        key: str,
        destination: Path,
        *,
        max_bytes: int,
        timeout_seconds: int,
    ) -> None:
        _validate_bucket(bucket)
        _validate_key(key)
        _positive_limit(max_bytes, "S3 download byte limit")
        if destination.exists():
            raise S3SigV4Error("S3 download destination already exists.")
        deadline = _deadline(timeout_seconds)
        connection: http.client.HTTPConnection | None = None
        descriptor: int | None = None
        try:
            canonical_uri = _canonical_uri(bucket, key)
            headers = self._signed_headers("GET", canonical_uri, "", EMPTY_SHA256)
            connection = self._connection(deadline)
            connection.request("GET", canonical_uri, headers=headers)
            _set_socket_timeout(connection, _remaining(deadline))
            response = connection.getresponse()
            if response.status != 200:
                body = _read_bounded(
                    response,
                    MAX_ERROR_BYTES,
                    connection=connection,
                    deadline=deadline,
                )
                raise _http_error(response.status, body)
            descriptor = _open_private_destination(destination)
            total = 0
            with os.fdopen(descriptor, "wb", buffering=0) as output:
                descriptor = None
                while True:
                    _set_socket_timeout(connection, _remaining(deadline))
                    chunk = _read_response_chunk(
                        response,
                        min(64 * 1024, max_bytes - total + 1),
                    )
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise S3SigV4Error("S3 response exceeded its configured byte limit.")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        except S3SigV4Error:
            destination.unlink(missing_ok=True)
            raise
        except (OSError, TimeoutError, http.client.HTTPException):
            destination.unlink(missing_ok=True)
            raise S3SigV4Error("S3 download failed.") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if connection is not None:
                connection.close()

    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str,
        max_response_bytes: int,
        timeout_seconds: int,
        _deadline_at: float | None = None,
    ) -> tuple[S3Object, ...]:
        _validate_bucket(bucket)
        _validate_prefix(prefix)
        _positive_limit(max_response_bytes, "S3 listing byte limit")
        deadline = _deadline_at if _deadline_at is not None else _deadline(timeout_seconds)
        objects: list[S3Object] = []
        continuation: str | None = None
        remaining_bytes = max_response_bytes
        for _page in range(MAX_LIST_PAGES):
            query: list[tuple[str, str]] = [("list-type", "2"), ("prefix", prefix)]
            if continuation is not None:
                query.append(("continuation-token", continuation))
            response = self._request(
                "GET",
                bucket=bucket,
                query=query,
                timeout_seconds=_remaining_seconds(deadline),
                deadline=deadline,
                max_response_bytes=remaining_bytes,
                allowed_statuses={200},
            )
            remaining_bytes -= len(response.body)
            page, truncated, continuation = _parse_listing(response.body)
            objects.extend(page)
            if len(objects) > MAX_LIST_OBJECTS:
                raise S3SigV4Error("S3 listing exceeded its configured object limit.")
            if not truncated:
                return tuple(objects)
            if not continuation or remaining_bytes <= 0:
                raise S3SigV4Error("S3 listing pagination was incomplete.")
        raise S3SigV4Error("S3 listing exceeded its configured page limit.")

    def delete_object(
        self,
        bucket: str,
        key: str,
        *,
        timeout_seconds: int,
        _deadline_at: float | None = None,
    ) -> None:
        deadline = _deadline_at if _deadline_at is not None else _deadline(timeout_seconds)
        self._request(
            "DELETE",
            bucket=bucket,
            key=key,
            timeout_seconds=timeout_seconds,
            deadline=deadline,
            allowed_statuses={200, 204},
        )

    def delete_prefix(
        self,
        bucket: str,
        *,
        prefix: str,
        timeout_seconds: int,
        _deadline_at: float | None = None,
    ) -> None:
        deadline = _deadline_at if _deadline_at is not None else _deadline(timeout_seconds)
        objects = self.list_objects(
            bucket,
            prefix=prefix,
            max_response_bytes=8 * 1024 * 1024,
            timeout_seconds=_remaining_seconds(deadline),
            _deadline_at=deadline,
        )
        if any(not item.key.startswith(prefix) for item in objects):
            raise S3SigV4Error("S3 listing crossed the requested prefix boundary.")
        for item in objects:
            self.delete_object(
                bucket,
                item.key,
                timeout_seconds=_remaining_seconds(deadline),
                _deadline_at=deadline,
            )

    def remove_bucket(self, bucket: str, *, timeout_seconds: int) -> None:
        deadline = _deadline(timeout_seconds)
        self.delete_prefix(
            bucket,
            prefix="",
            timeout_seconds=_remaining_seconds(deadline),
            _deadline_at=deadline,
        )
        self._request(
            "DELETE",
            bucket=bucket,
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
            allowed_statuses={200, 204, 404},
        )

    def _request(
        self,
        method: str,
        *,
        bucket: str,
        key: str | None = None,
        query: Sequence[tuple[str, str]] = (),
        payload: bytes = b"",
        timeout_seconds: int,
        max_response_bytes: int = MAX_ERROR_BYTES,
        allowed_statuses: set[int],
        deadline: float | None = None,
    ) -> _Response:
        _validate_bucket(bucket)
        if key is not None:
            _validate_key(key)
        _positive_limit(max_response_bytes, "S3 response byte limit")
        deadline = deadline if deadline is not None else _deadline(timeout_seconds)
        canonical_uri = _canonical_uri(bucket, key)
        canonical_query = _canonical_query(query)
        payload_hash = hashlib.sha256(payload).hexdigest()
        headers = self._signed_headers(
            method,
            canonical_uri,
            canonical_query,
            payload_hash,
        )
        headers["Content-Length"] = str(len(payload))
        target = canonical_uri + (f"?{canonical_query}" if canonical_query else "")
        connection: http.client.HTTPConnection | None = None
        try:
            connection = self._connection(deadline)
            connection.request(method, target, body=payload, headers=headers)
            _set_socket_timeout(connection, _remaining(deadline))
            response = connection.getresponse()
            body = _read_bounded(
                response,
                max_response_bytes,
                connection=connection,
                deadline=deadline,
            )
            if response.status not in allowed_statuses:
                raise _http_error(response.status, body)
            return _Response(status=response.status, body=body)
        except S3SigV4Error:
            raise
        except (OSError, TimeoutError, http.client.HTTPException):
            raise S3SigV4Error("S3 request failed.") from None
        finally:
            if connection is not None:
                connection.close()

    def _request_stream(
        self,
        method: str,
        *,
        bucket: str,
        key: str,
        stream: BinaryIO,
        content_length: int,
        payload_hash: str,
        deadline: float,
        allowed_statuses: set[int],
    ) -> _Response:
        canonical_uri = _canonical_uri(bucket, key)
        headers = self._signed_headers(method, canonical_uri, "", payload_hash)
        headers["Content-Length"] = str(content_length)
        connection: http.client.HTTPConnection | None = None
        try:
            connection = self._connection(deadline)
            connection.request(method, canonical_uri, body=stream, headers=headers)
            _set_socket_timeout(connection, _remaining(deadline))
            response = connection.getresponse()
            body = _read_bounded(
                response,
                MAX_ERROR_BYTES,
                connection=connection,
                deadline=deadline,
            )
            if response.status not in allowed_statuses:
                raise _http_error(response.status, body)
            return _Response(status=response.status, body=body)
        except S3SigV4Error:
            raise
        except (OSError, TimeoutError, http.client.HTTPException):
            raise S3SigV4Error("S3 upload failed.") from None
        finally:
            if connection is not None:
                connection.close()

    def _signed_headers(
        self,
        method: str,
        canonical_uri: str,
        canonical_query: str,
        payload_hash: str,
    ) -> dict[str, str]:
        now = self._clock()
        if now.tzinfo is None:
            raise S3SigV4Error("S3 signing clock must return a timezone-aware value.")
        now = now.astimezone(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        host = self._endpoint[3]
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        canonical_request = "\n".join(
            (
                method,
                canonical_uri,
                canonical_query,
                canonical_headers,
                SIGNED_HEADERS,
                payload_hash,
            )
        )
        scope = f"{date_stamp}/{self._config.region}/{SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            (
                ALGORITHM,
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            )
        )
        signing_key = _signing_key(
            self._config.secret_key,
            date_stamp,
            self._config.region,
        )
        signature = hmac.new(
            signing_key,
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        authorization = (
            f"{ALGORITHM} Credential={self._config.access_key}/{scope}, "
            f"SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
        )
        return {
            "Authorization": authorization,
            "Host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }

    def _connection(self, deadline: float) -> http.client.HTTPConnection:
        scheme, hostname, configured_port, _host, _origin = self._endpoint
        port = configured_port or (443 if scheme == "https" else 80)
        connect_host = _resolve_connect_host(
            hostname,
            port,
            allow_private=self._config.allow_private_endpoint,
        )
        timeout_seconds = _remaining(deadline)
        if scheme == "https":
            context = ssl.create_default_context(
                cafile=str(self._config.ca_file) if self._config.ca_file else None
            )
            return _PinnedHTTPSConnection(
                hostname,
                connect_host,
                port=port,
                timeout=timeout_seconds,
                context=context,
            )
        return http.client.HTTPConnection(connect_host, port=port, timeout=timeout_seconds)


def _validate_config(
    config: S3SigV4Config,
) -> tuple[str, str, int | None, str, str]:
    scheme, hostname, port, rendered_host, origin = _parse_endpoint(config.endpoint)
    if config.require_https and scheme != "https":
        raise S3SigV4Error("S3 endpoint is invalid.")
    if config.require_https and config.allow_private_endpoint:
        raise S3SigV4Error("Private S3 endpoints are forbidden in production mode.")
    allowed_origins = {_parse_allowed_origin(value) for value in config.allowed_origins}
    if config.require_https and not allowed_origins:
        raise S3SigV4Error("Production S3 requires at least one approved origin.")
    if allowed_origins and origin not in allowed_origins:
        raise S3SigV4Error("S3 endpoint origin is not approved.")
    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None and not config.allow_private_endpoint:
        raise S3SigV4Error("S3 IP literals require explicit local mode.")
    if not config.access_key or not config.secret_key:
        raise S3SigV4Error("S3 credentials are invalid.")
    if any(
        ord(character) < 32
        for credential in (config.access_key, config.secret_key)
        for character in credential
    ):
        raise S3SigV4Error("S3 credentials are invalid.")
    if REGION_RE.fullmatch(config.region) is None:
        raise S3SigV4Error("S3 region is invalid.")
    if config.ca_file is not None and not config.ca_file.is_file():
        raise S3SigV4Error("S3 CA file does not exist.")
    return scheme, hostname, port, rendered_host, origin


def _parse_endpoint(value: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise S3SigV4Error("S3 endpoint is invalid.") from None
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise S3SigV4Error("S3 endpoint is invalid.")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        raise S3SigV4Error("S3 endpoint hostname must be ASCII.") from None
    if any(character.isspace() or ord(character) < 32 for character in hostname):
        raise S3SigV4Error("S3 endpoint is invalid.")
    default_port = 443 if parsed.scheme == "https" else 80
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    if port is not None and port != default_port:
        rendered_host = f"{rendered_host}:{port}"
    return parsed.scheme, hostname, port, rendered_host, f"{parsed.scheme}://{rendered_host}"


def _parse_allowed_origin(value: str) -> str:
    scheme, _hostname, _port, _host, origin = _parse_endpoint(value)
    if scheme != "https":
        raise S3SigV4Error("Approved S3 origins must use HTTPS.")
    return origin


def _resolve_connect_host(hostname: str, port: int, *, allow_private: bool) -> str:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not allow_private:
            raise S3SigV4Error("S3 IP literals require explicit local mode.")
        return literal.compressed
    try:
        resolved = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError:
        raise S3SigV4Error("S3 endpoint resolution failed.") from None
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for item in resolved:
        raw_address = item[4][0]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            raise S3SigV4Error("S3 endpoint resolution returned an invalid address.") from None
        if address.compressed not in seen:
            seen.add(address.compressed)
            addresses.append(address)
    if not addresses:
        raise S3SigV4Error("S3 endpoint resolution returned no addresses.")
    if not allow_private and any(not address.is_global for address in addresses):
        raise S3SigV4Error("S3 endpoint resolved to a non-public address.")
    return addresses[0].compressed


def _validate_bucket(bucket: str) -> None:
    if BUCKET_RE.fullmatch(bucket) is None or ".." in bucket:
        raise S3SigV4Error("S3 bucket name is invalid.")


def _validate_key(key: str) -> None:
    if not key or len(key.encode("utf-8")) > 1024:
        raise S3SigV4Error("S3 object key is invalid.")
    if any(ord(character) < 32 or ord(character) == 127 for character in key):
        raise S3SigV4Error("S3 object key is invalid.")


def _validate_prefix(prefix: str) -> None:
    if len(prefix.encode("utf-8")) > 1024:
        raise S3SigV4Error("S3 object prefix is invalid.")
    if any(ord(character) < 32 or ord(character) == 127 for character in prefix):
        raise S3SigV4Error("S3 object prefix is invalid.")


def _canonical_uri(bucket: str, key: str | None) -> str:
    root = f"/{quote(bucket, safe='-_.~')}"
    return root if key is None else f"{root}/{quote(key, safe='/-_.~')}"


def _canonical_query(items: Iterable[tuple[str, str]]) -> str:
    encoded = [
        (quote(name, safe="-_.~"), quote(value, safe="-_.~"))
        for name, value in items
    ]
    return "&".join(f"{name}={value}" for name, value in sorted(encoded))


def _signing_key(secret: str, date_stamp: str, region: str) -> bytes:
    date_key = hmac.new(f"AWS4{secret}".encode(), date_stamp.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, SERVICE.encode(), hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _hash_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
    )


def _open_private_destination(destination: Path) -> int:
    if os.name != "nt":
        return os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    return _open_private_windows_destination(destination)


def _open_private_windows_destination(destination: Path) -> int:
    """Create a Windows file atomically with a protected, least-privilege DACL."""

    import ctypes
    import msvcrt
    from ctypes import wintypes

    token_query = 0x0008
    token_user_class = 1
    generic_write = 0x40000000
    create_new = 1
    file_attribute_normal = 0x00000080
    sddl_revision_1 = 1

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("user", SidAndAttributes)]

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("security_descriptor", wintypes.LPVOID),
            ("inherit_handle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_uint,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.LPVOID,)
    kernel32.LocalFree.restype = wintypes.LPVOID

    token = wintypes.HANDLE()
    sid_string = wintypes.LPWSTR()
    security_descriptor = wintypes.LPVOID()
    native_handle: int | None = None
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            token_query,
            ctypes.byref(token),
        ):
            raise S3SigV4Error("S3 download destination permissions could not be secured.")
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            token_user_class,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value == 0:
            raise S3SigV4Error("S3 download destination permissions could not be secured.")
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            token_user_class,
            token_buffer,
            required,
            ctypes.byref(required),
        ):
            raise S3SigV4Error("S3 download destination permissions could not be secured.")
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(
            token_user.user.sid,
            ctypes.byref(sid_string),
        ):
            raise S3SigV4Error("S3 download destination permissions could not be secured.")
        sddl = f"D:P(A;;FA;;;{sid_string.value})(A;;FA;;;SY)(A;;FA;;;BA)"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            sddl_revision_1,
            ctypes.byref(security_descriptor),
            None,
        ):
            raise S3SigV4Error("S3 download destination permissions could not be secured.")
        attributes = SecurityAttributes(
            ctypes.sizeof(SecurityAttributes),
            security_descriptor,
            False,
        )
        handle = kernel32.CreateFileW(
            str(destination),
            generic_write,
            0,
            ctypes.byref(attributes),
            create_new,
            file_attribute_normal,
            None,
        )
        invalid_handle = wintypes.HANDLE(-1).value
        if handle == invalid_handle:
            raise S3SigV4Error("S3 download destination could not be created.")
        native_handle = int(handle)
        descriptor = msvcrt.open_osfhandle(
            native_handle,
            os.O_WRONLY | getattr(os, "O_BINARY", 0),
        )
        native_handle = None
        return descriptor
    finally:
        if native_handle is not None:
            kernel32.CloseHandle(native_handle)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)
        if sid_string:
            kernel32.LocalFree(sid_string)
        if token:
            kernel32.CloseHandle(token)


def _read_bounded(
    response: http.client.HTTPResponse,
    max_bytes: int,
    *,
    connection: http.client.HTTPConnection,
    deadline: float,
) -> bytes:
    payload = bytearray()
    while True:
        _set_socket_timeout(connection, _remaining(deadline))
        chunk = _read_response_chunk(
            response,
            min(64 * 1024, max_bytes - len(payload) + 1),
        )
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > max_bytes:
            raise S3SigV4Error("S3 response exceeded its configured byte limit.")


def _read_response_chunk(response: http.client.HTTPResponse, size: int) -> bytes:
    read1 = getattr(response, "read1", None)
    return read1(size) if callable(read1) else response.read(size)


def _parse_listing(payload: bytes) -> tuple[list[S3Object], bool, str | None]:
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise S3SigV4Error("S3 listing XML is unsafe.")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        raise S3SigV4Error("S3 listing XML is invalid.") from None
    objects: list[S3Object] = []
    for content in root.findall("{*}Contents"):
        key = content.findtext("{*}Key")
        raw_size = content.findtext("{*}Size")
        try:
            size = int(raw_size) if raw_size is not None else -1
        except ValueError:
            size = -1
        if key is None or size < 0:
            raise S3SigV4Error("S3 listing fields are invalid.")
        _validate_key(key)
        objects.append(S3Object(key=key, size=size))
    truncated = (root.findtext("{*}IsTruncated") or "false").strip().lower() == "true"
    continuation = root.findtext("{*}NextContinuationToken")
    if continuation is not None and (
        not continuation or len(continuation.encode("utf-8")) > 4096
    ):
        raise S3SigV4Error("S3 listing continuation token is invalid.")
    return objects, truncated, continuation


def _s3_error_code(payload: bytes) -> str | None:
    if len(payload) > MAX_ERROR_BYTES or b"<!DOCTYPE" in payload.upper():
        return None
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return None
    code = root.findtext("{*}Code")
    if code is None or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", code):
        return None
    return code


def _http_error(status: int, payload: bytes) -> S3SigV4Error:
    code = _s3_error_code(payload)
    suffix = f" ({code})" if code else ""
    return S3SigV4Error(f"S3 request failed with HTTP {status}{suffix}.")


def _positive_limit(value: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise S3SigV4Error(f"{label} must be positive.")


def _deadline(timeout_seconds: int) -> float:
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise S3SigV4Error("S3 timeout must be a positive integer.")
    if timeout_seconds <= 0 or timeout_seconds > 600:
        raise S3SigV4Error("S3 timeout is outside the allowed bounds.")
    return time.monotonic() + timeout_seconds


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise S3SigV4Error("S3 request timed out.")
    return remaining


def _remaining_seconds(deadline: float) -> int:
    return max(1, min(600, int(_remaining(deadline) + 0.999)))


def _set_socket_timeout(connection: http.client.HTTPConnection, timeout: float) -> None:
    if connection.sock is not None:
        connection.sock.settimeout(timeout)
