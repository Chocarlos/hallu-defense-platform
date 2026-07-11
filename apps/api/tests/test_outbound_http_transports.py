from __future__ import annotations

import ipaddress
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import Message
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import hallu_defense.outbound_http as outbound_http_module
import hallu_defense.services.oidc as oidc_module
import hallu_defense.services.providers as providers_module
import hallu_defense.services.rag_index as rag_index_module
import hallu_defense.services.secrets as secrets_module
from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpRedirectError,
    _NoRedirectHandler,
    open_url_no_redirect,
)
from hallu_defense.services.oidc import OidcJwtValidationError, fetch_json_url
from hallu_defense.services.providers import (
    ProviderRequestError,
    UrllibJsonTransport,
)
from hallu_defense.services.rag_index import (
    MAX_OPENSEARCH_HTTP_RESPONSE_BYTES,
    RagIndexTransportError,
    UrlLibOpenSearchTransport,
)
from hallu_defense.services.sandbox_kubernetes import (
    InClusterKubernetesTransport,
    KubernetesApiError,
)
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretNotFoundError,
    _urllib_get_json,
)
from hallu_defense.services.telemetry import _otlp_no_redirect_session


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    authorization: str | None
    vault_token: str | None


@dataclass
class RunningTlsServer:
    server: ThreadingHTTPServer
    thread: threading.Thread
    origin: str
    requests: list[RecordedRequest]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


@dataclass(frozen=True)
class TlsServerPair:
    allowed: RunningTlsServer
    rejected: RunningTlsServer
    certificate_path: Path
    client_context: ssl.SSLContext


class FakeHttpResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_amount: int | None = None

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self.payload if amount < 0 else self.payload[:amount]


class CloseTrackingBody:
    def __init__(self) -> None:
        self.closed = False
        self.read_called = False

    def close(self) -> None:
        self.closed = True

    def read(self, _amount: int = -1) -> bytes:
        self.read_called = True
        return b"remote-body-marker"


@pytest.fixture
def tls_server_pair(tmp_path: Path) -> TlsServerPair:
    certificate_path, key_path = _write_loopback_certificate(tmp_path)
    rejected = _start_tls_server(certificate_path, key_path)
    allowed = _start_tls_server(
        certificate_path,
        key_path,
        cross_origin_target=rejected.origin,
    )
    client_context = ssl.create_default_context(cafile=str(certificate_path))
    pair = TlsServerPair(
        allowed=allowed,
        rejected=rejected,
        certificate_path=certificate_path,
        client_context=client_context,
    )
    try:
        yield pair
    finally:
        allowed.close()
        rejected.close()


def test_all_http_transports_reject_redirects_without_forwarding_credentials(
    tls_server_pair: TlsServerPair,
) -> None:
    allowed = tls_server_pair.allowed
    rejected = tls_server_pair.rejected
    policy = OutboundHttpPolicy.from_values(
        environment="test",
        allowed_origins=(allowed.origin,),
    )
    provider = UrllibJsonTransport(
        policy=policy,
        ssl_context=tls_server_pair.client_context,
    )

    assert provider.post_json(
        f"{allowed.origin}/direct",
        headers={"Authorization": "Bearer provider-marker"},
        payload={"model": "test"},
        timeout_seconds=3,
    ) == {"ok": True}

    with pytest.raises(ProviderRequestError, match="blocked") as unlisted_error:
        provider.post_json(
            f"{rejected.origin}/direct",
            headers={"Authorization": "Bearer blocked-marker"},
            payload={"model": "test"},
            timeout_seconds=3,
        )
    assert unlisted_error.value.__cause__ is None
    assert rejected.requests == []

    direct_count = sum(item.path == "/direct" for item in allowed.requests)
    with pytest.raises(ProviderRequestError, match="redirect") as same_origin_error:
        provider.post_json(
            f"{allowed.origin}/redirect-same",
            headers={"Authorization": "Bearer provider-marker"},
            payload={"model": "test"},
            timeout_seconds=3,
        )
    assert same_origin_error.value.__cause__ is None
    assert sum(item.path == "/direct" for item in allowed.requests) == direct_count

    with pytest.raises(ProviderRequestError, match="redirect") as generic_3xx_error:
        provider.post_json(
            f"{allowed.origin}/redirect-304",
            headers={"Authorization": "Bearer provider-marker"},
            payload={"model": "test"},
            timeout_seconds=3,
        )
    assert generic_3xx_error.value.__cause__ is None

    with pytest.raises(ProviderRequestError, match="redirect") as provider_error:
        provider.post_json(
            f"{allowed.origin}/redirect-cross-provider",
            headers={"Authorization": "Bearer provider-marker"},
            payload={"model": "test"},
            timeout_seconds=3,
        )
    assert provider_error.value.__cause__ is None

    with pytest.raises(SecretAccessError, match="redirect") as vault_error:
        _urllib_get_json(
            f"{allowed.origin}/redirect-cross-vault",
            {"X-Vault-Token": "vault-marker"},
            3,
            ca_cert_path=tls_server_pair.certificate_path,
            policy=policy,
        )
    assert vault_error.value.__cause__ is None

    kubernetes = InClusterKubernetesTransport(
        api_server=allowed.origin,
        token="k8s-marker",
        ssl_context=tls_server_pair.client_context,
    )
    with pytest.raises(KubernetesApiError, match="redirect") as kubernetes_error:
        kubernetes.request("GET", "/redirect-cross-kubernetes", timeout=3)
    assert kubernetes_error.value.__cause__ is None

    with pytest.raises(OidcJwtValidationError, match="redirect") as oidc_error:
        fetch_json_url(
            f"{allowed.origin}/redirect-cross-oidc",
            3,
            policy=policy,
            ssl_context=tls_server_pair.client_context,
        )
    assert oidc_error.value.__cause__ is None

    opensearch = UrlLibOpenSearchTransport(
        allowed.origin,
        outbound_policy=policy,
        ssl_context=tls_server_pair.client_context,
    )
    with pytest.raises(RagIndexTransportError, match="redirect") as search_error:
        opensearch.request_json(
            "POST",
            "/redirect-cross-opensearch",
            {"query": {"match_all": {}}},
            headers={"Authorization": "Bearer search-marker"},
            timeout_seconds=3,
        )
    assert search_error.value.__cause__ is None

    otlp_session = _otlp_no_redirect_session()
    otlp_session.trust_env = False
    try:
        with pytest.raises(requests.exceptions.TooManyRedirects, match="not allowed") as otlp_error:
            otlp_session.post(
                f"{allowed.origin}/redirect-cross-otlp",
                data=b"trace",
                headers={"Authorization": "Bearer otlp-marker"},
                timeout=3,
                verify=str(tls_server_pair.certificate_path),
            )
        assert otlp_error.value.__cause__ is None
    finally:
        otlp_session.close()

    assert rejected.requests == []
    allowed_by_path = {item.path: item for item in allowed.requests}
    assert allowed_by_path["/redirect-cross-provider"].authorization == (
        "Bearer provider-marker"
    )
    assert allowed_by_path["/redirect-cross-vault"].vault_token == "vault-marker"
    assert allowed_by_path["/redirect-cross-kubernetes"].authorization == (
        "Bearer k8s-marker"
    )
    assert allowed_by_path["/redirect-cross-opensearch"].authorization == (
        "Bearer search-marker"
    )
    assert allowed_by_path["/redirect-cross-otlp"].authorization == "Bearer otlp-marker"

    sanitizing_session = _otlp_no_redirect_session()
    sanitizing_session.trust_env = False
    try:
        response = sanitizing_session.post(
            f"{allowed.origin}/otlp-large-error",
            data=b"trace",
            timeout=3,
            verify=str(tls_server_pair.certificate_path),
        )
        assert response.status_code == 503
        assert response.reason == "upstream response"
        assert response.content == b""
        assert "remote-body-marker" not in response.text
        assert "remote-reason-marker" not in str(response.reason)
    finally:
        sanitizing_session.close()


def test_redirect_handler_closes_302_body_without_reading_or_leaking_reason() -> None:
    body = CloseTrackingBody()

    with pytest.raises(OutboundHttpRedirectError, match="not allowed") as exc_info:
        _NoRedirectHandler().redirect_request(
            request.Request("https://allowed.example.test/start"),
            body,  # type: ignore[arg-type]
            302,
            "remote-reason-marker",
            Message(),
            "https://other.example.test/sink",
        )

    assert body.closed is True
    assert body.read_called is False
    assert exc_info.value.__cause__ is None
    assert "remote-reason-marker" not in str(exc_info.value)


@pytest.mark.parametrize("status_code", [304, 399])
def test_open_url_closes_redirect_http_error_without_reading(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    body = CloseTrackingBody()
    remote_error = error.HTTPError(
        "https://allowed.example.test/start",
        status_code,
        "remote-reason-marker",
        Message(),
        body,  # type: ignore[arg-type]
    )

    class RaisingOpener:
        def open(self, *_args: object, **_kwargs: object) -> object:
            raise remote_error

    monkeypatch.setattr(
        outbound_http_module.request,
        "build_opener",
        lambda *_handlers: RaisingOpener(),
    )

    with pytest.raises(OutboundHttpRedirectError, match="not allowed") as exc_info:
        open_url_no_redirect(
            request.Request("https://allowed.example.test/start"),
            timeout=3,
        )

    assert body.closed is True
    assert body.read_called is False
    assert exc_info.value.__cause__ is None
    assert "remote-reason-marker" not in str(exc_info.value)


@pytest.mark.parametrize(
    "adapter",
    ["oidc", "provider", "opensearch", "vault", "vault-not-found", "kubernetes"],
)
def test_productive_adapters_close_http_error_without_reading_or_leaking(
    monkeypatch: pytest.MonkeyPatch,
    adapter: str,
) -> None:
    body = CloseTrackingBody()
    status_code = 404 if adapter == "vault-not-found" else 503
    remote_error = error.HTTPError(
        "https://service.example.test/resource",
        status_code,
        "remote-reason-marker",
        Message(),
        body,  # type: ignore[arg-type]
    )

    def raise_http_error(*_args: object, **_kwargs: object) -> object:
        raise remote_error

    operation: Callable[[], object]
    expected_error: type[Exception]
    if adapter == "oidc":
        monkeypatch.setattr(oidc_module, "open_url_no_redirect", raise_http_error)
        operation = partial(fetch_json_url, "https://service.example.test/jwks", 3)
        expected_error = OidcJwtValidationError
    elif adapter == "provider":
        monkeypatch.setattr(
            providers_module,
            "open_url_no_redirect",
            raise_http_error,
        )
        operation = partial(
            UrllibJsonTransport().post_json,
            "https://service.example.test/v1/chat",
            headers={"Authorization": "Bearer provider-marker"},
            payload={"model": "test"},
            timeout_seconds=3,
        )
        expected_error = ProviderRequestError
    elif adapter == "opensearch":
        monkeypatch.setattr(
            rag_index_module,
            "open_url_no_redirect",
            raise_http_error,
        )
        search = UrlLibOpenSearchTransport("https://service.example.test")
        operation = partial(
            search.request_json,
            "POST",
            "/index/_search",
            {"query": {"match_all": {}}},
            timeout_seconds=3,
        )
        expected_error = RagIndexTransportError
    elif adapter in {"vault", "vault-not-found"}:
        monkeypatch.setattr(
            secrets_module,
            "open_url_no_redirect",
            raise_http_error,
        )
        operation = partial(
            _urllib_get_json,
            "https://service.example.test/v1/secret",
            {"X-Vault-Token": "vault-marker"},
            3,
        )
        expected_error = SecretNotFoundError if status_code == 404 else SecretAccessError
    else:
        kubernetes = InClusterKubernetesTransport(
            api_server="https://service.example.test",
            token="k8s-marker",
            ssl_context=ssl.create_default_context(),
            urlopen=raise_http_error,  # type: ignore[arg-type]
        )
        operation = partial(
            kubernetes.request,
            "GET",
            "/api/v1/namespaces",
            timeout=3,
        )
        expected_error = KubernetesApiError

    with pytest.raises(expected_error) as exc_info:
        operation()

    assert body.closed is True
    assert body.read_called is False
    assert exc_info.value.__cause__ is None
    assert "remote-reason-marker" not in str(exc_info.value)
    assert "remote-body-marker" not in str(exc_info.value)


def test_opensearch_transport_caps_response_before_json_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeHttpResponse(b"x" * (MAX_OPENSEARCH_HTTP_RESPONSE_BYTES + 1))
    monkeypatch.setattr(
        rag_index_module,
        "open_url_no_redirect",
        lambda *_args, **_kwargs: response,
    )

    transport = UrlLibOpenSearchTransport("https://search.example.test")
    with pytest.raises(RagIndexTransportError, match="1 MiB"):
        transport.request_json(
            "POST",
            "/index/_search",
            {"query": {"match_all": {}}},
            timeout_seconds=3,
        )

    assert response.read_amount == MAX_OPENSEARCH_HTTP_RESPONSE_BYTES + 1


def _write_loopback_certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "server-cert.pem"
    key_path = tmp_path / "server-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def _start_tls_server(
    certificate_path: Path,
    key_path: Path,
    *,
    cross_origin_target: str | None = None,
) -> RunningTlsServer:
    recorded: list[RecordedRequest] = []
    state: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def _handle(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length:
                self.rfile.read(content_length)
            recorded.append(
                RecordedRequest(
                    method=self.command,
                    path=self.path,
                    authorization=self.headers.get("Authorization"),
                    vault_token=self.headers.get("X-Vault-Token"),
                )
            )
            if self.path == "/redirect-same":
                self.send_response(302)
                self.send_header("Location", f"{state['origin']}/direct")
                self.end_headers()
                return
            if self.path == "/redirect-304":
                self.send_response(304)
                self.end_headers()
                return
            if self.path.startswith("/redirect-cross-") and cross_origin_target:
                self.send_response(302)
                self.send_header("Location", f"{cross_origin_target}/sink")
                self.end_headers()
                return
            if self.path == "/otlp-large-error":
                chunk = b"remote-body-marker" * 4096
                self.send_response(503, "remote-reason-marker")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(chunk) * 256))
                self.end_headers()
                try:
                    for _ in range(256):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except OSError:
                    pass
                return
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=certificate_path, keyfile=key_path)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    host, port = server.server_address
    origin = f"https://{host}:{port}"
    state["origin"] = origin
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return RunningTlsServer(
        server=server,
        thread=thread,
        origin=origin,
        requests=recorded,
    )
