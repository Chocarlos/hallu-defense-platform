from __future__ import annotations

from pathlib import Path
from typing import cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from hallu_defense import worker as worker_module
from hallu_defense.config import Settings
from hallu_defense.services.metrics_server import (
    WorkerMetricsServer,
    WorkerMetricsServerError,
)
from hallu_defense.services.secrets import SecretValue
from hallu_defense.services.secret_token import MAX_BEARER_TOKEN_BYTES
from hallu_defense.worker import (
    IngestionWorker,
    IngestionWorkerError,
    build_worker_metrics_server,
)


class StaticVerifier:
    def __init__(self, expected: str) -> None:
        self.expected = expected
        self.candidates: list[str] = []

    def matches(self, candidate: str) -> bool:
        self.candidates.append(candidate)
        return candidate == self.expected


def test_worker_metrics_server_requires_bearer_and_renders_metrics() -> None:
    verifier = StaticVerifier("metrics-token")
    server = WorkerMetricsServer(
        host="127.0.0.1",
        port=0,
        render_metrics=lambda: "# TYPE worker_jobs_total counter\nworker_jobs_total 2\n",
        token_verifier=verifier,
    )
    server.start()
    try:
        endpoint = f"http://127.0.0.1:{server.bound_port}/metrics"
        with pytest.raises(HTTPError) as unauthorized:
            urlopen(endpoint, timeout=2)
        assert unauthorized.value.code == 401

        request = Request(endpoint, headers={"Authorization": "Bearer metrics-token"})
        with urlopen(request, timeout=2) as response:
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store"
            assert response.read().decode("utf-8") == (
                "# TYPE worker_jobs_total counter\nworker_jobs_total 2\n"
            )
        assert verifier.candidates == ["metrics-token"]
    finally:
        server.stop()


def test_worker_metrics_server_rejects_wrong_path_and_oversized_output() -> None:
    server = WorkerMetricsServer(
        host="127.0.0.1",
        port=0,
        render_metrics=lambda: "x" * (8 * 1024 * 1024 + 1),
        token_verifier=StaticVerifier("token"),
    )
    server.start()
    try:
        origin = f"http://127.0.0.1:{server.bound_port}"
        with pytest.raises(HTTPError) as missing:
            urlopen(f"{origin}/health", timeout=2)
        assert missing.value.code == 404
        request = Request(
            f"{origin}/metrics",
            headers={"Authorization": "Bearer token"},
        )
        with pytest.raises(HTTPError) as oversized:
            urlopen(request, timeout=2)
        assert oversized.value.code == 503
    finally:
        server.stop()


@pytest.mark.parametrize("host", ["localhost", "worker.internal", "", "::1"])
def test_worker_metrics_server_rejects_non_ip_bind_host(host: str) -> None:
    with pytest.raises(WorkerMetricsServerError, match="IPv4 literal"):
        WorkerMetricsServer(
            host=host,
            port=9090,
            render_metrics=lambda: "",
            token_verifier=StaticVerifier("token"),
        )


def test_worker_metrics_server_lifecycle_is_fail_closed() -> None:
    server = WorkerMetricsServer(
        host="127.0.0.1",
        port=0,
        render_metrics=lambda: "",
        token_verifier=StaticVerifier("token"),
    )
    with pytest.raises(WorkerMetricsServerError, match="not running"):
        _ = server.bound_port
    server.start()
    try:
        with pytest.raises(WorkerMetricsServerError, match="already running"):
            server.start()
    finally:
        server.stop()
    server.stop()


def test_worker_metrics_configuration_fails_closed_in_production_without_token() -> None:
    class RenderOnlyWorker:
        def render_metrics(self) -> str:
            return ""

    worker = cast(IngestionWorker, RenderOnlyWorker())
    base_settings: dict[str, object] = {
        "policy_version": "worker-metrics-test",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 1,
        "max_output_chars": 100,
    }
    with pytest.raises(IngestionWorkerError, match="bearer-token secret"):
        build_worker_metrics_server(
            Settings(environment="production", **base_settings),  # type: ignore[arg-type]
            worker,
            host="0.0.0.0",
            port=9090,
        )

    assert (
        build_worker_metrics_server(
            Settings(environment="local", **base_settings),  # type: ignore[arg-type]
            worker,
            host="127.0.0.1",
            port=9090,
        )
        is None
    )


def test_worker_metrics_configuration_validates_secret_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RenderOnlyWorker:
        def render_metrics(self) -> str:
            return ""

    class StaticSecretManager:
        def __init__(self, value: str) -> None:
            self.value = value
            self.requested: list[str] = []

        def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
            assert field == "value"
            self.requested.append(name)
            return SecretValue(name=name, _value=self.value)

    worker = cast(IngestionWorker, RenderOnlyWorker())
    settings = Settings(
        environment="local",
        policy_version="worker-metrics-test",
        auth_required=False,
        allowed_workspace=Path.cwd(),
        max_command_seconds=1,
        max_output_chars=100,
        metrics_bearer_token_secret_name="observability/worker-metrics",
    )
    for invalid_value in (
        "short-token",
        " " * 32,
        "á" * 32,
        "x" * (MAX_BEARER_TOKEN_BYTES + 1),
    ):
        invalid = StaticSecretManager(invalid_value)
        monkeypatch.setattr(
            worker_module,
            "create_secret_manager",
            lambda _settings, manager=invalid: manager,
        )
        with pytest.raises(IngestionWorkerError, match="invalid format"):
            build_worker_metrics_server(
                settings,
                worker,
                host="127.0.0.1",
                port=9090,
            )
        assert invalid.requested == ["observability/worker-metrics"]

    strong = StaticSecretManager("x" * 32)
    monkeypatch.setattr(worker_module, "create_secret_manager", lambda _settings: strong)
    server = build_worker_metrics_server(
        settings,
        worker,
        host="127.0.0.1",
        port=9090,
    )
    assert isinstance(server, WorkerMetricsServer)
    assert strong.requested == ["observability/worker-metrics"]
