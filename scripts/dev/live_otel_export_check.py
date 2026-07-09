from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ENABLED_ENV = "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_ENABLED"
API_BASE_URL_ENV = "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_API_BASE_URL"
SPANS_PATH_ENV = "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_SPANS_PATH"
POLL_TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_POLL_TIMEOUT_SECONDS"
POLL_INTERVAL_ENV = "HALLU_DEFENSE_LIVE_OTEL_EXPORT_CHECK_POLL_INTERVAL_SECONDS"

DEFAULT_API_BASE_URL = "http://localhost:8000"
DEFAULT_SPANS_PATH = "var/otel/spans.jsonl"
DEFAULT_POLL_TIMEOUT_SECONDS = 60.0
DEFAULT_POLL_INTERVAL_SECONDS = 2.0

REQUIRED_EXACT_SPAN_NAMES = ("policy.evaluate", "sandbox.run")
SENSITIVE_ATTRIBUTE_KEY_FRAGMENTS = (
    "authorization",
    "cookie",
    "message_text",
    "payload",
    "repo_ref",
    "secret",
    "source_ref",
    "tenant_id",
    "tool_input",
    "tool_output",
)


class LiveOtelExportCheckError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveOtelExportCheckConfig:
    api_base_url: str
    spans_path: Path
    poll_timeout_seconds: float
    poll_interval_seconds: float


@dataclass(frozen=True)
class RunMarkers:
    run_id: str
    trace_id: str
    tenant_id: str
    secret_value: str
    message_marker: str

    def leak_markers(self) -> tuple[str, ...]:
        return (self.secret_value, self.tenant_id, self.message_marker)


HttpPost = Callable[
    [LiveOtelExportCheckConfig, str, Mapping[str, object], Mapping[str, str], Sequence[int]],
    None,
]
WaitReady = Callable[[LiveOtelExportCheckConfig], None]


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    http_post: HttpPost | None = None,
    wait_ready: WaitReady | None = None,
    sleep: Callable[[float], None] | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live OTel export check",
        }

    config = _config_from_env(effective_env)
    markers = _run_markers(run_id or uuid.uuid4().hex[:12])
    post_fn = http_post or _http_post_json
    wait_fn = wait_ready or _wait_for_api_ready
    sleep_fn = sleep or time.sleep

    wait_fn(config)
    start_offset = config.spans_path.stat().st_size if config.spans_path.exists() else 0
    _generate_traffic(config, markers, post_fn)
    found_names = _poll_for_required_spans(config, start_offset, sleep_fn)
    _assert_no_sensitive_leak(config.spans_path, start_offset, markers)

    return {
        "status": "passed",
        "run_id": markers.run_id,
        "spans_path": str(config.spans_path),
        "span_names_seen": sorted(found_names),
    }


def _config_from_env(env: Mapping[str, str]) -> LiveOtelExportCheckConfig:
    return LiveOtelExportCheckConfig(
        api_base_url=_optional(env, API_BASE_URL_ENV) or DEFAULT_API_BASE_URL,
        spans_path=_resolve_path(_optional(env, SPANS_PATH_ENV) or DEFAULT_SPANS_PATH),
        poll_timeout_seconds=_positive_float(
            _optional(env, POLL_TIMEOUT_ENV) or str(DEFAULT_POLL_TIMEOUT_SECONDS),
            POLL_TIMEOUT_ENV,
        ),
        poll_interval_seconds=_positive_float(
            _optional(env, POLL_INTERVAL_ENV) or str(DEFAULT_POLL_INTERVAL_SECONDS),
            POLL_INTERVAL_ENV,
        ),
    )


def _resolve_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path


def _positive_float(value: str, env_name: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise LiveOtelExportCheckError(f"{env_name} must be a positive number.") from exc
    if parsed <= 0:
        raise LiveOtelExportCheckError(f"{env_name} must be positive.")
    return parsed


def _run_markers(run_id: str) -> RunMarkers:
    return RunMarkers(
        run_id=run_id,
        trace_id=f"tr_live_otel_export_check_{run_id}",
        tenant_id=f"live-otel-check-tenant-{run_id}",
        secret_value=f"live-otel-check-secret-{run_id}",
        message_marker=f"live-otel-check-message-{run_id}",
    )


def _wait_for_api_ready(config: LiveOtelExportCheckConfig) -> None:
    deadline = time.monotonic() + config.poll_timeout_seconds
    url = config.api_base_url.rstrip("/") + "/health"
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        time.sleep(1)
    raise LiveOtelExportCheckError(f"API at {config.api_base_url} did not become ready: {last_error}")


def _generate_traffic(
    config: LiveOtelExportCheckConfig,
    markers: RunMarkers,
    post_fn: HttpPost,
) -> None:
    headers = {
        "Content-Type": "application/json",
        "x-tenant-id": markers.tenant_id,
        "x-trace-id": markers.trace_id,
    }
    post_fn(
        config,
        "/verification/run",
        {
            "tenant_id": markers.tenant_id,
            "message_text": "OK.",
            "task_type": "chat",
            "message_id": f"msg_{markers.message_marker}",
            "execution_artifacts": {"live_check_secret": markers.secret_value},
        },
        headers,
        (200,),
    )
    post_fn(
        config,
        "/policy/evaluate",
        {
            "subject": "live-otel-check-agent",
            "action": "read",
            "resource": "repo",
            "risk_level": "low",
            "attributes": {
                "resource_tenant_id": markers.tenant_id,
                "note": markers.secret_value,
                "context": markers.message_marker,
            },
        },
        headers,
        (200,),
    )
    post_fn(
        config,
        "/repo/checks/run",
        {
            "repo_ref": "..",
            "commands": [f"echo {markers.secret_value} {markers.message_marker}"],
            "network_policy": "deny",
        },
        headers,
        (400,),
    )


def _http_post_json(
    config: LiveOtelExportCheckConfig,
    path: str,
    body: Mapping[str, object],
    headers: Mapping[str, str],
    expected_statuses: Sequence[int],
) -> None:
    url = config.api_base_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=dict(headers), method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            status = response.status
            payload = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read()
    except urllib.error.URLError as exc:
        raise LiveOtelExportCheckError(f"failed to reach {url}: {exc}") from exc
    if status not in expected_statuses:
        raise LiveOtelExportCheckError(
            f"unexpected status {status} from {path}: "
            f"{payload.decode('utf-8', errors='replace')[:500]}"
        )


def _poll_for_required_spans(
    config: LiveOtelExportCheckConfig,
    start_offset: int,
    sleep_fn: Callable[[float], None],
) -> set[str]:
    deadline = time.monotonic() + config.poll_timeout_seconds
    offset = start_offset
    found_names: set[str] = set()

    while time.monotonic() < deadline:
        if config.spans_path.exists():
            size = config.spans_path.stat().st_size
            if size < offset:
                offset = 0
            if size > offset:
                found_names.update(_span_names_since(config.spans_path, offset))
                offset = size
        missing = _missing_required_spans(found_names)
        if not missing:
            return found_names
        sleep_fn(config.poll_interval_seconds)

    missing = _missing_required_spans(found_names)
    raise LiveOtelExportCheckError(
        f"timed out waiting for required spans in {config.spans_path}: "
        f"missing {', '.join(missing)}; seen {sorted(found_names)}"
    )


def _missing_required_spans(found_names: set[str]) -> list[str]:
    missing: list[str] = []
    if not any(name.startswith("HTTP ") for name in found_names):
        missing.append("HTTP *")
    if not any(name.startswith("verification.") for name in found_names):
        missing.append("verification.*")
    missing.extend(name for name in REQUIRED_EXACT_SPAN_NAMES if name not in found_names)
    return missing


def _span_names_since(path: Path, start_offset: int) -> Iterator[str]:
    with path.open("rb") as handle:
        handle.seek(start_offset)
        for raw_line in handle:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield from _span_names_from_payload(payload)


def _span_names_from_payload(payload: object) -> Iterator[str]:
    for span in _spans_from_payload(payload):
        name = span.get("name")
        if isinstance(name, str):
            yield name


def _assert_no_sensitive_leak(spans_path: Path, start_offset: int, markers: RunMarkers) -> None:
    if not spans_path.exists():
        raise LiveOtelExportCheckError(f"{spans_path} does not exist")
    with spans_path.open("rb") as handle:
        size = spans_path.stat().st_size
        handle.seek(start_offset if start_offset <= size else 0)
        content = handle.read().decode("utf-8", errors="replace")

    lower_content = content.lower()
    leaked_values = [marker for marker in markers.leak_markers() if marker.lower() in lower_content]
    if leaked_values:
        raise LiveOtelExportCheckError(f"sensitive marker values leaked into exported spans: {leaked_values}")

    leaked_keys = sorted(_sensitive_attribute_keys(content))
    if leaked_keys:
        raise LiveOtelExportCheckError(f"sensitive span attributes were exported: {leaked_keys}")


def _sensitive_attribute_keys(content: str) -> set[str]:
    leaked: set[str] = set()
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        for span in _spans_from_payload(payload):
            attributes = span.get("attributes")
            if not isinstance(attributes, Sequence) or isinstance(attributes, (str, bytes)):
                continue
            for attribute in attributes:
                if not isinstance(attribute, Mapping):
                    continue
                key = attribute.get("key")
                if isinstance(key, str) and _sensitive_attribute_key(key):
                    leaked.add(key)
    return leaked


def _sensitive_attribute_key(key: str) -> bool:
    normalized = key.lower()
    return any(fragment in normalized for fragment in SENSITIVE_ATTRIBUTE_KEY_FRAGMENTS)


def _spans_from_payload(payload: object) -> Iterator[Mapping[str, object]]:
    if not isinstance(payload, Mapping):
        return
    resource_spans = payload.get("resourceSpans")
    if not isinstance(resource_spans, Sequence) or isinstance(resource_spans, (str, bytes)):
        return
    for resource_span in resource_spans:
        if not isinstance(resource_span, Mapping):
            continue
        scope_spans = resource_span.get("scopeSpans")
        if not isinstance(scope_spans, Sequence) or isinstance(scope_spans, (str, bytes)):
            continue
        for scope_span in scope_spans:
            if not isinstance(scope_span, Mapping):
                continue
            spans = scope_span.get("spans")
            if not isinstance(spans, Sequence) or isinstance(spans, (str, bytes)):
                continue
            for span in spans:
                if isinstance(span, Mapping):
                    yield span


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def main() -> None:
    try:
        result = run_from_env()
    except LiveOtelExportCheckError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2, sort_keys=True))
        sys.exit(1)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
