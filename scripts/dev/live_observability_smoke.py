from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENABLED_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_SMOKE_ENABLED"
API_URL_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_API_URL"
PROMETHEUS_URL_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_PROMETHEUS_URL"
GRAFANA_URL_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_GRAFANA_URL"
PROMETHEUS_JOB_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_PROMETHEUS_JOB"
GRAFANA_DATASOURCE_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_GRAFANA_DATASOURCE"
GRAFANA_USER_ENV = "GRAFANA_ADMIN_USER"
GRAFANA_PASSWORD_ENV = "GRAFANA_ADMIN_PASSWORD"
LOAD_REQUEST_COUNT_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_LOAD_REQUESTS"
HTTP_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_HTTP_TIMEOUT_SECONDS"
POLL_ATTEMPTS_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_METRIC_POLL_ATTEMPTS"
POLL_INTERVAL_ENV = "HALLU_DEFENSE_LIVE_OBSERVABILITY_METRIC_POLL_INTERVAL_SECONDS"

DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_PROMETHEUS_URL = "http://localhost:9090"
DEFAULT_GRAFANA_URL = "http://localhost:3001"
DEFAULT_PROMETHEUS_JOB = "hallu-defense-api"
DEFAULT_GRAFANA_DATASOURCE = "Prometheus"
DEFAULT_GRAFANA_USER = "admin"
DEFAULT_GRAFANA_PASSWORD = "change-me"
DEFAULT_LOAD_REQUEST_COUNT = 3
DEFAULT_HTTP_TIMEOUT_SECONDS = 5
DEFAULT_POLL_ATTEMPTS = 10
DEFAULT_POLL_INTERVAL_SECONDS = 5.0

LOAD_PATH = "/verification/run"
HTTP_REQUESTS_METRIC = "hallu_http_requests_total"
# Keep this in the hallu_verification_* family; the smoke intentionally checks
# a domain metric in addition to generic HTTP traffic.
VERIFICATION_RUNS_METRIC = "hallu_verification_runs_total"
SMOKE_TRACE_PREFIX = "tr_live_observability_smoke"
_MAX_RESPONSE_BYTES = 2_097_152

JsonGetter = Callable[[str, Mapping[str, str] | None], object]
JsonPoster = Callable[[str, Mapping[str, object], Mapping[str, str] | None], tuple[int, object]]
Sleeper = Callable[[float], None]


class LiveObservabilitySmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveObservabilitySmokeConfig:
    api_url: str
    prometheus_url: str
    grafana_url: str
    prometheus_job: str
    grafana_datasource_name: str
    grafana_user: str
    grafana_password: str
    load_request_count: int
    http_timeout_seconds: int
    poll_attempts: int
    poll_interval_seconds: float


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    fetch_json: JsonGetter | None = None,
    post_json: JsonPoster | None = None,
    sleep: Sleeper | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return _skip_result()

    config = _config_from_env(effective_env)
    getter = fetch_json or _default_fetch_json(config.http_timeout_seconds)
    poster = post_json or _default_post_json(config.http_timeout_seconds)
    sleeper = sleep or time.sleep
    return run_live_smoke(
        config,
        fetch_json=getter,
        post_json=poster,
        sleep=sleeper,
        run_id=run_id,
    )


def run_live_smoke(
    config: LiveObservabilitySmokeConfig,
    *,
    fetch_json: JsonGetter,
    post_json: JsonPoster,
    sleep: Sleeper,
    run_id: str | None = None,
) -> dict[str, object]:
    smoke_run_id = run_id or uuid.uuid4().hex[:12]
    prometheus_targets_up = _poll_prometheus_target_up(fetch_json, config, sleep=sleep)
    _generate_load(post_json, config, smoke_run_id)

    http_requests_value = _poll_metric_value(
        fetch_json,
        config,
        query=f'sum({HTTP_REQUESTS_METRIC}{{path="{LOAD_PATH}"}})',
        sleep=sleep,
    )
    verification_runs_value = _poll_metric_value(
        fetch_json,
        config,
        query=f"sum({VERIFICATION_RUNS_METRIC})",
        sleep=sleep,
    )
    grafana_health_ok = _check_grafana_health(fetch_json, config)
    grafana_datasource_type = _check_grafana_datasource(fetch_json, config)

    return {
        "status": "passed",
        "prometheus_targets_up": prometheus_targets_up,
        "prometheus_target_job": config.prometheus_job,
        "load_requests_sent": config.load_request_count,
        "http_requests_metric_present": http_requests_value > 0,
        "http_requests_metric_value": http_requests_value,
        "verification_runs_metric_present": verification_runs_value > 0,
        "verification_runs_metric_value": verification_runs_value,
        "grafana_health_ok": grafana_health_ok,
        "grafana_datasource_ok": grafana_datasource_type == "prometheus",
        "grafana_datasource_type": grafana_datasource_type,
    }


def _poll_prometheus_target_up(
    fetch_json: JsonGetter,
    config: LiveObservabilitySmokeConfig,
    *,
    sleep: Sleeper,
) -> bool:
    target_url = f"{config.prometheus_url.rstrip('/')}/api/v1/targets"
    last_health: object = None
    target_found = False
    for attempt in range(config.poll_attempts):
        active_targets = _active_targets(fetch_json(target_url, None))
        for target in active_targets:
            labels = target.get("labels") if isinstance(target, Mapping) else None
            if isinstance(labels, Mapping) and labels.get("job") == config.prometheus_job:
                target_found = True
                last_health = target.get("health")
                if last_health == "up":
                    return True
                break
        if attempt < config.poll_attempts - 1:
            sleep(config.poll_interval_seconds)

    if target_found:
        raise LiveObservabilitySmokeError(
            f"prometheus target job={config.prometheus_job!r} is not up after "
            f"{config.poll_attempts} attempts (health={last_health!r})"
        )
    raise LiveObservabilitySmokeError(
        f"prometheus has no active target for job={config.prometheus_job!r} after "
        f"{config.poll_attempts} attempts"
    )


def _active_targets(payload: object) -> Sequence[Mapping[str, object]]:
    if not isinstance(payload, Mapping) or payload.get("status") != "success":
        raise LiveObservabilitySmokeError("prometheus /api/v1/targets did not return status=success")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise LiveObservabilitySmokeError("prometheus /api/v1/targets response missing data")
    targets = data.get("activeTargets")
    if not isinstance(targets, list):
        raise LiveObservabilitySmokeError("prometheus /api/v1/targets response missing activeTargets")
    return targets


def _generate_load(post_json: JsonPoster, config: LiveObservabilitySmokeConfig, run_id: str) -> None:
    url = f"{config.api_url.rstrip('/')}{LOAD_PATH}"
    for index in range(config.load_request_count):
        trace_id = f"{SMOKE_TRACE_PREFIX}_{run_id}_{index}"
        status_code, _body = post_json(
            url,
            {
                "message_text": "OK.",
                "task_type": "chat",
                "message_id": f"live-observability-smoke-{run_id}-{index}",
            },
            {"x-trace-id": trace_id},
        )
        if status_code >= 400:
            raise LiveObservabilitySmokeError(
                f"POST {LOAD_PATH} returned status {status_code} while generating smoke load"
            )


def _poll_metric_value(
    fetch_json: JsonGetter,
    config: LiveObservabilitySmokeConfig,
    *,
    query: str,
    sleep: Sleeper,
) -> float:
    url = f"{config.prometheus_url.rstrip('/')}/api/v1/query?{urlencode({'query': query})}"
    last_value = 0.0
    for attempt in range(config.poll_attempts):
        payload = fetch_json(url, None)
        last_value = _scalar_query_value(payload)
        if last_value > 0:
            return last_value
        if attempt < config.poll_attempts - 1:
            sleep(config.poll_interval_seconds)
    raise LiveObservabilitySmokeError(
        f"prometheus query {query!r} did not report a positive value after "
        f"{config.poll_attempts} attempts (last value={last_value})"
    )


def _scalar_query_value(payload: object) -> float:
    if not isinstance(payload, Mapping) or payload.get("status") != "success":
        raise LiveObservabilitySmokeError("prometheus /api/v1/query did not return status=success")
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise LiveObservabilitySmokeError("prometheus /api/v1/query response missing data")
    result = data.get("result")
    if not isinstance(result, list) or not result:
        return 0.0
    first = result[0]
    if not isinstance(first, Mapping):
        return 0.0
    value = first.get("value")
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return 0.0
    try:
        return float(value[1])
    except (TypeError, ValueError):
        return 0.0


def _check_grafana_health(fetch_json: JsonGetter, config: LiveObservabilitySmokeConfig) -> bool:
    payload = fetch_json(f"{config.grafana_url.rstrip('/')}/api/health", None)
    if not isinstance(payload, Mapping):
        raise LiveObservabilitySmokeError("grafana /api/health did not return a JSON object")
    if payload.get("database") != "ok":
        raise LiveObservabilitySmokeError(
            f"grafana /api/health reported database={payload.get('database')!r}, expected 'ok'"
        )
    return True


def _check_grafana_datasource(fetch_json: JsonGetter, config: LiveObservabilitySmokeConfig) -> str:
    encoded_name = quote(config.grafana_datasource_name, safe="")
    url = f"{config.grafana_url.rstrip('/')}/api/datasources/name/{encoded_name}"
    headers = {"Authorization": _basic_auth_header(config.grafana_user, config.grafana_password)}
    payload = fetch_json(url, headers)
    if not isinstance(payload, Mapping):
        raise LiveObservabilitySmokeError("grafana datasource lookup did not return a JSON object")
    datasource_type = payload.get("type")
    if datasource_type != "prometheus":
        raise LiveObservabilitySmokeError(
            f"grafana datasource {config.grafana_datasource_name!r} has type "
            f"{datasource_type!r}, expected 'prometheus'"
        )
    if payload.get("access") != "proxy":
        raise LiveObservabilitySmokeError(
            f"grafana datasource {config.grafana_datasource_name!r} access is "
            f"{payload.get('access')!r}, expected 'proxy'"
        )
    return str(datasource_type)


def _default_fetch_json(timeout_seconds: int) -> JsonGetter:
    def fetch(url: str, headers: Mapping[str, str] | None) -> object:
        request = Request(url, headers=dict(headers or {}))
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise LiveObservabilitySmokeError(f"GET {url} failed") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise LiveObservabilitySmokeError(f"GET {url} response is too large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LiveObservabilitySmokeError(f"GET {url} did not return valid JSON") from exc

    return fetch


def _default_post_json(timeout_seconds: int) -> JsonPoster:
    def post(
        url: str,
        payload: Mapping[str, object],
        headers: Mapping[str, str] | None,
    ) -> tuple[int, object]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **dict(headers or {})},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                status_code = response.status
        except HTTPError as exc:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1)
            status_code = exc.code
        except (URLError, TimeoutError, OSError) as exc:
            raise LiveObservabilitySmokeError(f"POST {url} failed") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise LiveObservabilitySmokeError(f"POST {url} response is too large")
        parsed: object = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
        return status_code, parsed

    return post


def _config_from_env(env: Mapping[str, str]) -> LiveObservabilitySmokeConfig:
    return LiveObservabilitySmokeConfig(
        api_url=_optional(env, API_URL_ENV) or DEFAULT_API_URL,
        prometheus_url=_optional(env, PROMETHEUS_URL_ENV) or DEFAULT_PROMETHEUS_URL,
        grafana_url=_optional(env, GRAFANA_URL_ENV) or DEFAULT_GRAFANA_URL,
        prometheus_job=_optional(env, PROMETHEUS_JOB_ENV) or DEFAULT_PROMETHEUS_JOB,
        grafana_datasource_name=_optional(env, GRAFANA_DATASOURCE_ENV) or DEFAULT_GRAFANA_DATASOURCE,
        grafana_user=_optional(env, GRAFANA_USER_ENV) or DEFAULT_GRAFANA_USER,
        grafana_password=_optional(env, GRAFANA_PASSWORD_ENV) or DEFAULT_GRAFANA_PASSWORD,
        load_request_count=_positive_int(env, LOAD_REQUEST_COUNT_ENV, DEFAULT_LOAD_REQUEST_COUNT),
        http_timeout_seconds=_positive_int(env, HTTP_TIMEOUT_ENV, DEFAULT_HTTP_TIMEOUT_SECONDS),
        poll_attempts=_positive_int(env, POLL_ATTEMPTS_ENV, DEFAULT_POLL_ATTEMPTS),
        poll_interval_seconds=_non_negative_float(
            env,
            POLL_INTERVAL_ENV,
            DEFAULT_POLL_INTERVAL_SECONDS,
        ),
    )


def _skip_result() -> dict[str, object]:
    return {
        "status": "skipped",
        "reason": f"set {ENABLED_ENV}=true to run the live observability smoke",
        "prometheus_targets_up": False,
        "http_requests_metric_present": False,
        "verification_runs_metric_present": False,
        "grafana_health_ok": False,
        "grafana_datasource_ok": False,
    }


def _basic_auth_header(user: str, password: str) -> str:
    encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LiveObservabilitySmokeError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise LiveObservabilitySmokeError(f"{name} must be positive.")
    return parsed


def _non_negative_float(env: Mapping[str, str], name: str, default: float) -> float:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise LiveObservabilitySmokeError(f"{name} must be a number.") from exc
    if parsed < 0:
        raise LiveObservabilitySmokeError(f"{name} must not be negative.")
    return parsed


def _redact_grafana_password(text: str, env: Mapping[str, str] | None) -> str:
    source = env if env is not None else os.environ
    password = source.get(GRAFANA_PASSWORD_ENV, "").strip() or DEFAULT_GRAFANA_PASSWORD
    if password and password in text:
        return text.replace(password, "***")
    return text


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    del argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        source_env = env if env is not None else os.environ
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": _redact_grafana_password(str(exc), source_env),
                    "prometheus_targets_up": False,
                    "http_requests_metric_present": False,
                    "verification_runs_metric_present": False,
                    "grafana_health_ok": False,
                    "grafana_datasource_ok": False,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
