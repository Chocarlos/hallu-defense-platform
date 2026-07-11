from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Protocol, cast

from hallu_defense.services.metrics import PROMETHEUS_CONTENT_TYPE

MAX_AUTHORIZATION_HEADER_BYTES = 4096
MAX_METRICS_RESPONSE_BYTES = 8 * 1024 * 1024
METRICS_CLIENT_TIMEOUT_SECONDS = 2.0


class MetricsTokenVerifier(Protocol):
    def matches(self, candidate: str) -> bool: ...


class WorkerMetricsServerError(RuntimeError):
    pass


class _MetricsHttpServer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 32

    def get_request(self) -> tuple[socket.socket, object]:
        request, client_address = super().get_request()
        request.settimeout(METRICS_CLIENT_TIMEOUT_SECONDS)
        return request, client_address

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        render_metrics: Callable[[], str],
        token_verifier: MetricsTokenVerifier,
    ) -> None:
        self.render_metrics = render_metrics
        self.token_verifier = token_verifier
        super().__init__(server_address, _MetricsRequestHandler)


class _MetricsRequestHandler(BaseHTTPRequestHandler):
    server_version = "hallu-worker-metrics"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path != "/metrics":
            self._empty_response(404)
            return
        token = _bearer_token(self.headers.get("Authorization"))
        server = cast(_MetricsHttpServer, self.server)
        if token is None or not server.token_verifier.matches(token):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            payload = server.render_metrics().encode("utf-8")
        except Exception:
            self._empty_response(503)
            return
        if len(payload) > MAX_METRICS_RESPONSE_BYTES:
            self._empty_response(503)
            return
        self.send_response(200)
        self.send_header("Content-Type", PROMETHEUS_CONTENT_TYPE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _empty_response(self, status_code: int) -> None:
        self.send_response(status_code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class WorkerMetricsServer:
    """Authenticated Prometheus endpoint owned by the worker process."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        render_metrics: Callable[[], str],
        token_verifier: MetricsTokenVerifier,
    ) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            raise WorkerMetricsServerError(
                "Worker metrics host must be an IPv4 literal."
            ) from None
        if not isinstance(address, ipaddress.IPv4Address):
            raise WorkerMetricsServerError(
                "Worker metrics host must be an IPv4 literal."
            )
        if not 0 <= port <= 65535:
            raise WorkerMetricsServerError(
                "Worker metrics port must be between 0 and 65535."
            )
        self._host = host
        self._port = port
        self._render_metrics = render_metrics
        self._token_verifier = token_verifier
        self._server: _MetricsHttpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        server = self._server
        if server is None:
            raise WorkerMetricsServerError("Worker metrics server is not running.")
        return int(server.server_address[1])

    def start(self) -> None:
        if self._server is not None:
            raise WorkerMetricsServerError("Worker metrics server is already running.")
        try:
            server = _MetricsHttpServer(
                (self._host, self._port),
                render_metrics=self._render_metrics,
                token_verifier=self._token_verifier,
            )
        except OSError:
            raise WorkerMetricsServerError(
                "Worker metrics server could not bind its configured address."
            ) from None
        thread = threading.Thread(
            target=server.serve_forever,
            name="hallu-worker-metrics",
            daemon=True,
        )
        self._server = server
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        if server is None:
            return
        self._server = None
        self._thread = None
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                raise WorkerMetricsServerError(
                    "Worker metrics server did not stop within five seconds."
                )


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    if len(authorization.encode("utf-8")) > MAX_AUTHORIZATION_HEADER_BYTES:
        return None
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer":
        return None
    if not token or token != token.strip():
        return None
    if any(character.isspace() for character in token):
        return None
    return token
