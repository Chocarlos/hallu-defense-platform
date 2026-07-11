from __future__ import annotations

from hallu_defense.services.metrics import PrometheusMetrics


def test_http_method_metric_cardinality_is_bounded() -> None:
    metrics = _metrics()
    for index in range(500):
        metrics.record_http_request(
            method=f"SENTINEL_METHOD_{index}",
            path="/__unmatched__",
            status_code=400,
            duration_seconds=0.01,
        )
    metrics.record_http_request(
        method="get",
        path="/health",
        status_code=200,
        duration_seconds=0.01,
    )

    rendered = metrics.render()
    assert "SENTINEL_METHOD" not in rendered
    assert 'method="__other__",path="/__unmatched__"' in rendered
    assert 'method="GET",path="/health"' in rendered


def test_eval_suite_metric_cardinality_is_bounded() -> None:
    metrics = _metrics()
    for index in range(500):
        metrics.record_eval_report(
            suite=f"SENTINEL_SUITE_{index}",
            pass_rate=0.5,
            p95_latency_ms=10,
            scenario_count=1,
            groundedness=None,
            faithfulness=None,
        )
    metrics.record_eval_report(
        suite="smoke",
        pass_rate=1,
        p95_latency_ms=5,
        scenario_count=2,
        groundedness=None,
        faithfulness=None,
    )

    rendered = metrics.render()
    assert "SENTINEL_SUITE" not in rendered
    assert rendered.count('suite="custom"') == 3
    assert rendered.count('suite="smoke"') == 3


def _metrics() -> PrometheusMetrics:
    return PrometheusMetrics(
        service_name="test",
        service_version="test",
        environment="test",
    )
