from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from scripts.dev import live_observability_smoke as smoke

_API_URL = "http://api.example"
_PROMETHEUS_URL = "http://prometheus.example"
_GRAFANA_URL = "http://grafana.example"
_GRAFANA_PASSWORD = "smoke-only-not-a-secret"


def _enabled_env(**overrides: str) -> dict[str, str]:
    env = {
        smoke.ENABLED_ENV: "true",
        smoke.API_URL_ENV: _API_URL,
        smoke.PROMETHEUS_URL_ENV: _PROMETHEUS_URL,
        smoke.GRAFANA_URL_ENV: _GRAFANA_URL,
        smoke.GRAFANA_PASSWORD_ENV: _GRAFANA_PASSWORD,
        smoke.POLL_ATTEMPTS_ENV: "3",
    }
    env.update(overrides)
    return env


def _targets_payload(*, job: str = smoke.DEFAULT_PROMETHEUS_JOB, health: str = "up") -> dict[str, object]:
    return {
        "status": "success",
        "data": {"activeTargets": [{"labels": {"job": job}, "health": health}]},
    }


def _query_payload(value: float) -> dict[str, object]:
    if value <= 0:
        return {"status": "success", "data": {"resultType": "vector", "result": []}}
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {}, "value": [1720000000, str(value)]}],
        },
    }


def _fake_fetch_json(
    *,
    targets: dict[str, object] | None = None,
    query_value: float = 5.0,
    grafana_health: dict[str, object] | None = None,
    grafana_datasource: dict[str, object] | None = None,
):
    calls: list[tuple[str, Mapping[str, str] | None]] = []

    def fetch(url: str, headers: Mapping[str, str] | None) -> object:
        calls.append((url, headers))
        if url == f"{_PROMETHEUS_URL}/api/v1/targets":
            return targets if targets is not None else _targets_payload()
        if url.startswith(f"{_PROMETHEUS_URL}/api/v1/query?"):
            return _query_payload(query_value)
        if url == f"{_GRAFANA_URL}/api/health":
            return grafana_health if grafana_health is not None else {"database": "ok"}
        if url.startswith(f"{_GRAFANA_URL}/api/datasources/name/"):
            return grafana_datasource if grafana_datasource is not None else {
                "type": "prometheus",
                "access": "proxy",
                "url": "http://prometheus:9090",
            }
        raise AssertionError(f"unexpected fetch_json url: {url}")

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def _fake_post_json(*, status_code: int = 200):
    calls: list[tuple[str, Mapping[str, object], Mapping[str, str] | None]] = []

    def post(url: str, payload: Mapping[str, object], headers: Mapping[str, str] | None):
        calls.append((url, payload, headers))
        return status_code, {"trace_id": (headers or {}).get("x-trace-id")}

    post.calls = calls  # type: ignore[attr-defined]
    return post


def _no_op_sleep():
    calls: list[float] = []

    def sleep(seconds: float) -> None:
        calls.append(seconds)

    sleep.calls = calls  # type: ignore[attr-defined]
    return sleep


def test_skips_by_default_without_exposing_password() -> None:
    result = smoke.run_from_env({smoke.GRAFANA_PASSWORD_ENV: _GRAFANA_PASSWORD})

    assert result["status"] == "skipped"
    assert result["prometheus_targets_up"] is False
    assert result["http_requests_metric_present"] is False
    assert result["verification_runs_metric_present"] is False
    assert result["grafana_health_ok"] is False
    assert result["grafana_datasource_ok"] is False
    assert _GRAFANA_PASSWORD not in json.dumps(result)


def test_enabled_path_passes_with_injected_fakes() -> None:
    fetch = _fake_fetch_json()
    post = _fake_post_json()
    sleep = _no_op_sleep()

    result = smoke.run_from_env(
        _enabled_env(),
        fetch_json=fetch,
        post_json=post,
        sleep=sleep,
        run_id="unit-test",
    )

    assert result == {
        "status": "passed",
        "prometheus_targets_up": True,
        "prometheus_target_job": smoke.DEFAULT_PROMETHEUS_JOB,
        "load_requests_sent": smoke.DEFAULT_LOAD_REQUEST_COUNT,
        "http_requests_metric_present": True,
        "http_requests_metric_value": 5.0,
        "verification_runs_metric_present": True,
        "verification_runs_metric_value": 5.0,
        "grafana_health_ok": True,
        "grafana_datasource_ok": True,
        "grafana_datasource_type": "prometheus",
    }
    assert len(post.calls) == smoke.DEFAULT_LOAD_REQUEST_COUNT
    for url, payload, headers in post.calls:
        assert url == f"{_API_URL}/verification/run"
        assert payload["message_text"] == "OK."
        assert headers is not None
        assert headers["x-trace-id"].startswith(f"{smoke.SMOKE_TRACE_PREFIX}_unit-test_")
    datasource_calls = [call for call in fetch.calls if "datasources" in call[0]]
    assert datasource_calls and datasource_calls[0][1] is not None
    assert datasource_calls[0][1]["Authorization"].startswith("Basic ")


def test_enabled_path_raises_when_prometheus_target_not_up() -> None:
    fetch = _fake_fetch_json(targets=_targets_payload(health="down"))
    sleep = _no_op_sleep()

    with pytest.raises(smoke.LiveObservabilitySmokeError, match="not up"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=fetch,
            post_json=_fake_post_json(),
            sleep=sleep,
        )

    assert len(sleep.calls) == 2


def test_enabled_path_waits_for_prometheus_target_to_become_up() -> None:
    target_payloads = iter(
        [
            _targets_payload(health="unknown"),
            _targets_payload(health="down"),
            _targets_payload(health="up"),
        ]
    )
    base_fetch = _fake_fetch_json()

    def fetch(url: str, headers: Mapping[str, str] | None) -> object:
        if url == f"{_PROMETHEUS_URL}/api/v1/targets":
            return next(target_payloads)
        return base_fetch(url, headers)

    sleep = _no_op_sleep()
    result = smoke.run_from_env(
        _enabled_env(),
        fetch_json=fetch,
        post_json=_fake_post_json(),
        sleep=sleep,
    )

    assert result["prometheus_targets_up"] is True
    assert sleep.calls == [smoke.DEFAULT_POLL_INTERVAL_SECONDS] * 2


def test_enabled_path_raises_when_prometheus_target_missing() -> None:
    fetch = _fake_fetch_json(targets=_targets_payload(job="some-other-job"))

    with pytest.raises(smoke.LiveObservabilitySmokeError, match="no active target"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=fetch,
            post_json=_fake_post_json(),
            sleep=_no_op_sleep(),
        )


def test_enabled_path_raises_when_load_request_fails() -> None:
    with pytest.raises(smoke.LiveObservabilitySmokeError, match="returned status 500"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=_fake_fetch_json(),
            post_json=_fake_post_json(status_code=500),
            sleep=_no_op_sleep(),
        )


def test_enabled_path_raises_when_metric_never_becomes_positive() -> None:
    sleep = _no_op_sleep()

    with pytest.raises(smoke.LiveObservabilitySmokeError, match="did not report a positive value"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=_fake_fetch_json(query_value=0.0),
            post_json=_fake_post_json(),
            sleep=sleep,
        )

    assert len(sleep.calls) == 2


def test_enabled_path_raises_when_grafana_health_not_ok() -> None:
    fetch = _fake_fetch_json(grafana_health={"database": "locked"})

    with pytest.raises(smoke.LiveObservabilitySmokeError, match="database=.*locked"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=fetch,
            post_json=_fake_post_json(),
            sleep=_no_op_sleep(),
        )


def test_enabled_path_raises_when_datasource_type_is_wrong() -> None:
    fetch = _fake_fetch_json(grafana_datasource={"type": "loki", "access": "proxy"})

    with pytest.raises(smoke.LiveObservabilitySmokeError, match="expected 'prometheus'"):
        smoke.run_from_env(
            _enabled_env(),
            fetch_json=fetch,
            post_json=_fake_post_json(),
            sleep=_no_op_sleep(),
        )


def test_redacts_grafana_password_from_text() -> None:
    redacted = smoke._redact_grafana_password(
        f"boom {_GRAFANA_PASSWORD} tail",
        {smoke.GRAFANA_PASSWORD_ENV: _GRAFANA_PASSWORD},
    )

    assert _GRAFANA_PASSWORD not in redacted
    assert "***" in redacted


def test_main_prints_skip_json_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"


def test_main_reports_failure_without_leaking_password(capsys: pytest.CaptureFixture[str]) -> None:
    unreachable = "http://127.0.0.1:1"
    exit_code = smoke.main(
        env={
            smoke.ENABLED_ENV: "true",
            smoke.API_URL_ENV: unreachable,
            smoke.PROMETHEUS_URL_ENV: unreachable,
            smoke.GRAFANA_URL_ENV: unreachable,
            smoke.GRAFANA_PASSWORD_ENV: _GRAFANA_PASSWORD,
            smoke.HTTP_TIMEOUT_ENV: "2",
        }
    )

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert isinstance(payload["error"], str) and payload["error"]
    assert _GRAFANA_PASSWORD not in payload["error"]
