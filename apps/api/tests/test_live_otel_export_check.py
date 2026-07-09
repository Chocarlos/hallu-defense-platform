from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from scripts.dev import live_otel_export_check as check


def _span_line(name: str, attributes: Mapping[str, str] | None = None) -> str:
    attrs = [
        {"key": key, "value": {"stringValue": value}}
        for key, value in (attributes or {}).items()
    ]
    payload = {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": name,
                                "attributes": attrs,
                            }
                        ]
                    }
                ]
            }
        ]
    }
    return json.dumps(payload) + "\n"


def _base_env(tmp_path: Path) -> dict[str, str]:
    return {
        check.ENABLED_ENV: "true",
        check.SPANS_PATH_ENV: str(tmp_path / "spans.jsonl"),
        check.POLL_TIMEOUT_ENV: "0.2",
        check.POLL_INTERVAL_ENV: "0.01",
    }


def _no_op_wait(_config: check.LiveOtelExportCheckConfig) -> None:
    return None


def _make_fake_post(spans_path: Path, *, leaked_key: str | None = None, leaked_value: str | None = None):
    def _fake_post(
        config: check.LiveOtelExportCheckConfig,
        path: str,
        body: Mapping[str, object],
        headers: Mapping[str, str],
        expected_statuses: Sequence[int],
    ) -> None:
        del body, headers
        assert config.spans_path == spans_path
        if path == "/verification/run":
            assert 200 in expected_statuses
            lines = _span_line("HTTP POST") + _span_line("verification.extract_claims")
        elif path == "/policy/evaluate":
            assert 200 in expected_statuses
            lines = _span_line("HTTP POST") + _span_line("policy.evaluate")
        elif path == "/repo/checks/run":
            assert 400 in expected_statuses
            attributes = {"sandbox.command_count": "1"}
            if leaked_key is not None:
                attributes[leaked_key] = "bad"
            if leaked_value is not None:
                attributes["app.low_cardinality_probe"] = leaked_value
            lines = _span_line("HTTP POST") + _span_line("sandbox.run", attributes)
        else:  # pragma: no cover
            raise AssertionError(f"unexpected path {path}")
        with spans_path.open("a", encoding="utf-8") as handle:
            handle.write(lines)

    return _fake_post


def test_live_otel_export_check_skips_by_default() -> None:
    result = check.run_from_env({})

    assert result["status"] == "skipped"
    assert check.ENABLED_ENV in result["reason"]


def test_live_otel_export_check_passes_with_injected_fakes(tmp_path: Path) -> None:
    spans_path = tmp_path / "spans.jsonl"
    spans_path.write_text("", encoding="utf-8")

    result = check.run_from_env(
        _base_env(tmp_path),
        http_post=_make_fake_post(spans_path),
        wait_ready=_no_op_wait,
        sleep=lambda _seconds: None,
        run_id="fixedrun01",
    )

    assert result["status"] == "passed"
    assert result["run_id"] == "fixedrun01"
    assert result["span_names_seen"] == [
        "HTTP POST",
        "policy.evaluate",
        "sandbox.run",
        "verification.extract_claims",
    ]


def test_live_otel_export_check_rejects_sensitive_marker_value(tmp_path: Path) -> None:
    spans_path = tmp_path / "spans.jsonl"
    spans_path.write_text("", encoding="utf-8")
    run_id = "leakrun01"
    markers = check._run_markers(run_id)

    with pytest.raises(check.LiveOtelExportCheckError, match="marker values leaked"):
        check.run_from_env(
            _base_env(tmp_path),
            http_post=_make_fake_post(spans_path, leaked_value=markers.secret_value),
            wait_ready=_no_op_wait,
            sleep=lambda _seconds: None,
            run_id=run_id,
        )


def test_live_otel_export_check_rejects_sensitive_attribute_key(tmp_path: Path) -> None:
    spans_path = tmp_path / "spans.jsonl"
    spans_path.write_text("", encoding="utf-8")

    with pytest.raises(check.LiveOtelExportCheckError, match="sensitive span attributes"):
        check.run_from_env(
            _base_env(tmp_path),
            http_post=_make_fake_post(spans_path, leaked_key="request.payload"),
            wait_ready=_no_op_wait,
            sleep=lambda _seconds: None,
            run_id="keyleak01",
        )


def test_live_otel_export_check_times_out_when_required_span_missing(tmp_path: Path) -> None:
    spans_path = tmp_path / "spans.jsonl"
    spans_path.write_text("", encoding="utf-8")

    def _post_without_sandbox_span(
        config: check.LiveOtelExportCheckConfig,
        path: str,
        body: Mapping[str, object],
        headers: Mapping[str, str],
        expected_statuses: Sequence[int],
    ) -> None:
        del body, headers
        if path == "/repo/checks/run":
            assert 400 in expected_statuses
            return
        assert 200 in expected_statuses
        lines = _span_line("HTTP POST")
        lines += _span_line("verification.extract_claims" if path == "/verification/run" else "policy.evaluate")
        with config.spans_path.open("a", encoding="utf-8") as handle:
            handle.write(lines)

    with pytest.raises(check.LiveOtelExportCheckError, match="sandbox.run"):
        check.run_from_env(
            _base_env(tmp_path),
            http_post=_post_without_sandbox_span,
            wait_ready=_no_op_wait,
            sleep=lambda _seconds: None,
            run_id="timeoutrun01",
        )


def test_poll_for_required_spans_resets_offset_after_rotation(tmp_path: Path) -> None:
    spans_path = tmp_path / "spans.jsonl"
    spans_path.write_text(
        _span_line("HTTP POST")
        + _span_line("verification.extract_claims")
        + _span_line("policy.evaluate"),
        encoding="utf-8",
    )
    config = check.LiveOtelExportCheckConfig(
        api_base_url="http://unused.invalid",
        spans_path=spans_path,
        poll_timeout_seconds=1.0,
        poll_interval_seconds=0.0,
    )
    large_offset = spans_path.stat().st_size + 1000
    calls = 0

    def _sleep_and_rotate(_seconds: float) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            spans_path.write_text(_span_line("sandbox.run"), encoding="utf-8")

    found = check._poll_for_required_spans(config, large_offset, _sleep_and_rotate)

    assert "sandbox.run" in found


def test_sensitive_attribute_key_allows_low_cardinality_count() -> None:
    assert not check._sensitive_attribute_key("sandbox.command_count")
    assert check._sensitive_attribute_key("request.payload")
