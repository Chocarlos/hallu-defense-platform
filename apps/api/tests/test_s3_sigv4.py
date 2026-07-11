from __future__ import annotations

import hashlib
import http.server
import os
import socketserver
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

import pytest

from scripts.dev import s3_sigv4 as s3


class FakeResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self._body = body
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, bytes, dict[str, str]]] = []
        self.closed = False
        self.sock = None

    def request(
        self,
        method: str,
        target: str,
        body: bytes | BinaryIO | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if body is None:
            payload = b""
        elif isinstance(body, bytes):
            payload = body
        else:
            payload = body.read()
        self.requests.append((method, target, payload, dict(headers or {})))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _client() -> s3.S3SigV4Client:
    return s3.S3SigV4Client(
        s3.S3SigV4Config(
            endpoint="http://127.0.0.1:9000",
            access_key="access-sensitive",
            secret_key="secret-sensitive",
            allow_private_endpoint=True,
        ),
        clock=lambda: datetime(2026, 7, 10, 1, 2, 3, tzinfo=timezone.utc),
    )


def test_signature_matches_aws_published_get_bucket_lifecycle_vector() -> None:
    client = s3.S3SigV4Client(
        s3.S3SigV4Config(
            endpoint="https://examplebucket.s3.amazonaws.com",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        clock=lambda: datetime(2013, 5, 24, tzinfo=timezone.utc),
    )

    headers = client._signed_headers("GET", "/", "lifecycle=", s3.EMPTY_SHA256)

    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    )


def test_put_bytes_signs_payload_and_preserves_s3_path_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    connection = FakeConnection(FakeResponse(200))
    monkeypatch.setattr(client, "_connection", lambda _timeout: connection)

    client.put_bytes(
        "safe-bucket",
        "tenant/a b//c.txt",
        b"payload",
        timeout_seconds=5,
    )

    method, target, payload, headers = connection.requests[0]
    assert (method, target, payload) == (
        "PUT",
        "/safe-bucket/tenant/a%20b//c.txt",
        b"payload",
    )
    assert headers["x-amz-content-sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert headers["x-amz-date"] == "20260710T010203Z"
    assert "secret-sensitive" not in repr(headers)
    assert connection.closed is True


def test_listing_is_bounded_paginated_and_namespace_aware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>true</IsTruncated><NextContinuationToken>next-token</NextContinuationToken>
  <Contents><Key>tenants/t1/a.bin</Key><Size>12</Size></Contents>
</ListBucketResult>"""
    second = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <IsTruncated>false</IsTruncated>
  <Contents><Key>tenants/t1/b.bin</Key><Size>7</Size></Contents>
</ListBucketResult>"""
    connections = [
        FakeConnection(FakeResponse(200, first)),
        FakeConnection(FakeResponse(200, second)),
    ]
    client = _client()
    monkeypatch.setattr(client, "_connection", lambda _timeout: connections.pop(0))

    objects = client.list_objects(
        "safe-bucket",
        prefix="tenants/t1/",
        max_response_bytes=len(first) + len(second),
        timeout_seconds=5,
    )

    assert objects == (
        s3.S3Object(key="tenants/t1/a.bin", size=12),
        s3.S3Object(key="tenants/t1/b.bin", size=7),
    )


def test_delete_prefix_validates_every_listed_key_before_any_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    deleted: list[str] = []
    monkeypatch.setattr(
        client,
        "list_objects",
        lambda *_args, **_kwargs: (
            s3.S3Object(key="tenants/t1/safe.bin", size=1),
            s3.S3Object(key="tenants/t2/victim.bin", size=1),
        ),
    )
    monkeypatch.setattr(
        client,
        "delete_object",
        lambda _bucket, key, **_kwargs: deleted.append(key),
    )

    with pytest.raises(s3.S3SigV4Error, match="prefix boundary"):
        client.delete_prefix(
            "safe-bucket",
            prefix="tenants/t1/",
            timeout_seconds=5,
        )

    assert deleted == []


def test_bounded_reader_enforces_one_monotonic_deadline_across_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100.0]

    class SlowDripResponse:
        def read1(self, _size: int) -> bytes:
            now[0] += 0.6
            return b"x"

    monkeypatch.setattr(s3.time, "monotonic", lambda: now[0])

    with pytest.raises(s3.S3SigV4Error, match="timed out"):
        s3._read_bounded(
            SlowDripResponse(),  # type: ignore[arg-type]
            100,
            connection=FakeConnection(FakeResponse(200)),  # type: ignore[arg-type]
            deadline=101.0,
        )

    assert now[0] == pytest.approx(101.2)


def test_real_slow_drip_response_cannot_extend_wall_clock_deadline() -> None:
    class SlowDripHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", "10")
            self.end_headers()
            try:
                for _ in range(10):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.3)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    class QuietServer(socketserver.TCPServer):
        def handle_error(self, _request: object, _client_address: object) -> None:
            pass

    with QuietServer(("127.0.0.1", 0), SlowDripHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = s3.S3SigV4Client(
            s3.S3SigV4Config(
                endpoint=f"http://127.0.0.1:{server.server_address[1]}",
                access_key="access",
                secret_key="secret",
                allow_private_endpoint=True,
            )
        )
        started = time.monotonic()
        with pytest.raises(s3.S3SigV4Error):
            client.get_bytes(
                "safe-bucket",
                "slow",
                max_bytes=32,
                timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        server.shutdown()
        thread.join(timeout=2)

    assert 0.8 <= elapsed <= 1.8


def test_download_overflow_removes_partial_private_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _client()
    connection = FakeConnection(FakeResponse(200, b"too-large"))
    monkeypatch.setattr(client, "_connection", lambda _timeout: connection)
    destination = tmp_path / "download.bin"

    with pytest.raises(s3.S3SigV4Error, match="byte limit"):
        client.download_file(
            "safe-bucket",
            "key",
            destination,
            max_bytes=4,
            timeout_seconds=5,
        )

    assert not destination.exists()


def test_successful_download_is_private(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    client = _client()
    connection = FakeConnection(FakeResponse(200, b"verified"))
    monkeypatch.setattr(client, "_connection", lambda _timeout: connection)
    destination = tmp_path / "download.bin"
    opened: list[Path] = []
    original_open = s3._open_private_destination

    def tracked_open(path: Path) -> int:
        opened.append(path)
        return original_open(path)

    monkeypatch.setattr(s3, "_open_private_destination", tracked_open)

    client.download_file(
        "safe-bucket",
        "key",
        destination,
        max_bytes=32,
        timeout_seconds=5,
    )

    assert destination.read_bytes() == b"verified"
    assert opened == [destination]
    if os.name != "nt":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_unsafe_xml_and_https_downgrade_fail_closed() -> None:
    with pytest.raises(s3.S3SigV4Error, match="unsafe"):
        s3._parse_listing(b"<!DOCTYPE x [<!ENTITY y 'z'>]><ListBucketResult />")

    with pytest.raises(s3.S3SigV4Error, match="endpoint"):
        s3.S3SigV4Client(
            s3.S3SigV4Config(
                endpoint="http://storage.example.test",
                access_key="access",
                secret_key="secret",
                require_https=True,
            )
        )


def test_production_requires_exact_https_origin_allowlist() -> None:
    base = {
        "endpoint": "https://storage.example.test:9443",
        "access_key": "access",
        "secret_key": "secret",
        "require_https": True,
    }

    with pytest.raises(s3.S3SigV4Error, match="approved origin"):
        s3.S3SigV4Client(s3.S3SigV4Config(**base))

    with pytest.raises(s3.S3SigV4Error, match="not approved"):
        s3.S3SigV4Client(
            s3.S3SigV4Config(
                **base,
                allowed_origins=("https://other.example.test:9443",),
            )
        )

    client = s3.S3SigV4Client(
        s3.S3SigV4Config(
            **base,
            allowed_origins=("https://storage.example.test:9443",),
        )
    )
    assert client._endpoint[4] == "https://storage.example.test:9443"


def test_private_literal_and_private_dns_resolution_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(s3.S3SigV4Error, match="explicit local mode"):
        s3.S3SigV4Client(
            s3.S3SigV4Config(
                endpoint="http://169.254.169.254",
                access_key="access",
                secret_key="secret",
            )
        )

    client = s3.S3SigV4Client(
        s3.S3SigV4Config(
            endpoint="https://storage.example.test",
            access_key="access",
            secret_key="secret",
            require_https=True,
            allowed_origins=("https://storage.example.test",),
        )
    )
    monkeypatch.setattr(
        s3.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (s3.socket.AF_INET, s3.socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))
        ],
    )

    with pytest.raises(s3.S3SigV4Error, match="non-public"):
        client._connection(s3.time.monotonic() + 5)


def test_http_redirect_is_rejected_without_a_second_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    connection = FakeConnection(FakeResponse(307))
    monkeypatch.setattr(client, "_connection", lambda _deadline: connection)

    with pytest.raises(s3.S3SigV4Error, match="HTTP 307"):
        client.get_bytes(
            "safe-bucket",
            "key",
            max_bytes=32,
            timeout_seconds=5,
        )

    assert len(connection.requests) == 1


def test_credentials_are_redacted_from_config_repr() -> None:
    config = s3.S3SigV4Config(
        endpoint="https://storage.example.test",
        access_key="access-sensitive",
        secret_key="secret-sensitive",
    )

    assert "access-sensitive" not in repr(config)
    assert "secret-sensitive" not in repr(config)
