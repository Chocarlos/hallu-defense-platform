from __future__ import annotations

from collections import defaultdict
from collections.abc import Hashable
from dataclasses import dataclass
from threading import Lock
from typing import Final, Protocol, TypeVar

PROMETHEUS_CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"
HTTP_DURATION_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
TMetricLabels = TypeVar("TMetricLabels", bound=Hashable)
TLabelText = TypeVar("TLabelText", bound=Hashable, contravariant=True)


class LabelTextFn(Protocol[TLabelText]):
    def __call__(self, labels: TLabelText, *extra: tuple[str, str]) -> str: ...


@dataclass(frozen=True)
class HttpRequestLabels:
    method: str
    path: str
    status_code: str
    outcome: str


@dataclass(frozen=True)
class VerificationRunLabels:
    final_decision: str


@dataclass(frozen=True)
class ClaimVerdictLabels:
    status: str
    action: str


@dataclass(frozen=True)
class PolicyDecisionLabels:
    allowed: str
    action: str
    rule: str


@dataclass(frozen=True)
class ApprovalRequestLabels:
    risk_level: str


@dataclass(frozen=True)
class ApprovalDecisionLabels:
    decision: str
    status: str
    risk_level: str


@dataclass(frozen=True)
class SandboxRunLabels:
    verdict: str
    network_policy: str
    outcome: str


class PrometheusMetrics:
    def __init__(self, *, service_name: str, service_version: str, environment: str) -> None:
        self._service_name = service_name
        self._service_version = service_version
        self._environment = environment
        self._lock = Lock()
        self._request_totals: defaultdict[HttpRequestLabels, int] = defaultdict(int)
        self._duration_sums: defaultdict[HttpRequestLabels, float] = defaultdict(float)
        self._duration_buckets: defaultdict[tuple[HttpRequestLabels, float], int] = defaultdict(int)
        self._verification_totals: defaultdict[VerificationRunLabels, int] = defaultdict(int)
        self._verification_duration_sums: defaultdict[VerificationRunLabels, float] = defaultdict(float)
        self._verification_duration_buckets: defaultdict[tuple[VerificationRunLabels, float], int] = defaultdict(int)
        self._claim_verdict_totals: defaultdict[ClaimVerdictLabels, int] = defaultdict(int)
        self._policy_decision_totals: defaultdict[PolicyDecisionLabels, int] = defaultdict(int)
        self._policy_duration_sums: defaultdict[PolicyDecisionLabels, float] = defaultdict(float)
        self._policy_duration_buckets: defaultdict[tuple[PolicyDecisionLabels, float], int] = defaultdict(int)
        self._approval_request_totals: defaultdict[ApprovalRequestLabels, int] = defaultdict(int)
        self._approval_decision_totals: defaultdict[ApprovalDecisionLabels, int] = defaultdict(int)
        self._sandbox_run_totals: defaultdict[SandboxRunLabels, int] = defaultdict(int)
        self._sandbox_duration_sums: defaultdict[SandboxRunLabels, float] = defaultdict(float)
        self._sandbox_duration_buckets: defaultdict[tuple[SandboxRunLabels, float], int] = defaultdict(int)

    def record_http_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        labels = HttpRequestLabels(
            method=method.upper(),
            path=path,
            status_code=str(status_code),
            outcome="success" if status_code < 400 else "error",
        )
        with self._lock:
            self._request_totals[labels] += 1
            self._duration_sums[labels] += max(duration_seconds, 0.0)
            for bucket in HTTP_DURATION_BUCKETS:
                if duration_seconds <= bucket:
                    self._duration_buckets[(labels, bucket)] += 1
            self._duration_buckets[(labels, float("inf"))] += 1

    def record_verification_run(self, *, final_decision: str, duration_seconds: float) -> None:
        labels = VerificationRunLabels(final_decision=final_decision)
        with self._lock:
            self._verification_totals[labels] += 1
            self._verification_duration_sums[labels] += max(duration_seconds, 0.0)
            for bucket in HTTP_DURATION_BUCKETS:
                if duration_seconds <= bucket:
                    self._verification_duration_buckets[(labels, bucket)] += 1
            self._verification_duration_buckets[(labels, float("inf"))] += 1

    def record_claim_verdict(self, *, status: str, action: str) -> None:
        labels = ClaimVerdictLabels(status=status, action=action)
        with self._lock:
            self._claim_verdict_totals[labels] += 1

    def record_policy_decision(
        self,
        *,
        allowed: bool,
        action: str,
        matched_rules: list[str],
        duration_seconds: float,
    ) -> None:
        primary_rule = matched_rules[0] if matched_rules else "none"
        labels = PolicyDecisionLabels(
            allowed=str(allowed).lower(),
            action=action,
            rule=primary_rule,
        )
        with self._lock:
            self._policy_decision_totals[labels] += 1
            self._policy_duration_sums[labels] += max(duration_seconds, 0.0)
            for bucket in HTTP_DURATION_BUCKETS:
                if duration_seconds <= bucket:
                    self._policy_duration_buckets[(labels, bucket)] += 1
            self._policy_duration_buckets[(labels, float("inf"))] += 1

    def record_approval_request(self, *, risk_level: str) -> None:
        labels = ApprovalRequestLabels(risk_level=risk_level)
        with self._lock:
            self._approval_request_totals[labels] += 1

    def record_approval_decision(self, *, decision: str, status: str, risk_level: str) -> None:
        labels = ApprovalDecisionLabels(decision=decision, status=status, risk_level=risk_level)
        with self._lock:
            self._approval_decision_totals[labels] += 1

    def record_sandbox_run(
        self,
        *,
        verdict: str,
        network_policy: str,
        outcome: str,
        duration_seconds: float,
    ) -> None:
        labels = SandboxRunLabels(verdict=verdict, network_policy=network_policy, outcome=outcome)
        with self._lock:
            self._sandbox_run_totals[labels] += 1
            self._sandbox_duration_sums[labels] += max(duration_seconds, 0.0)
            for bucket in HTTP_DURATION_BUCKETS:
                if duration_seconds <= bucket:
                    self._sandbox_duration_buckets[(labels, bucket)] += 1
            self._sandbox_duration_buckets[(labels, float("inf"))] += 1

    def render(self) -> str:
        with self._lock:
            request_totals = dict(self._request_totals)
            duration_sums = dict(self._duration_sums)
            duration_buckets = dict(self._duration_buckets)
            verification_totals = dict(self._verification_totals)
            verification_duration_sums = dict(self._verification_duration_sums)
            verification_duration_buckets = dict(self._verification_duration_buckets)
            claim_verdict_totals = dict(self._claim_verdict_totals)
            policy_decision_totals = dict(self._policy_decision_totals)
            policy_duration_sums = dict(self._policy_duration_sums)
            policy_duration_buckets = dict(self._policy_duration_buckets)
            approval_request_totals = dict(self._approval_request_totals)
            approval_decision_totals = dict(self._approval_decision_totals)
            sandbox_run_totals = dict(self._sandbox_run_totals)
            sandbox_duration_sums = dict(self._sandbox_duration_sums)
            sandbox_duration_buckets = dict(self._sandbox_duration_buckets)

        lines = [
            "# HELP hallu_api_build_info API service build and environment metadata.",
            "# TYPE hallu_api_build_info gauge",
            "hallu_api_build_info"
            f"{_label_text(('service', self._service_name), ('version', self._service_version), ('environment', self._environment))} 1",
            "# HELP hallu_http_requests_total Total HTTP requests observed by the API.",
            "# TYPE hallu_http_requests_total counter",
        ]

        for labels, count in sorted(request_totals.items(), key=lambda item: _label_sort_key(item[0])):
            lines.append("hallu_http_requests_total" f"{_http_label_text(labels)} {count}")

        lines.extend(
            [
                "# HELP hallu_http_request_duration_seconds HTTP request latency in seconds.",
                "# TYPE hallu_http_request_duration_seconds histogram",
            ]
        )
        for labels in sorted(request_totals, key=_label_sort_key):
            for bucket in (*HTTP_DURATION_BUCKETS, float("inf")):
                bucket_count = duration_buckets.get((labels, bucket), 0)
                le = "+Inf" if bucket == float("inf") else _format_float(bucket)
                lines.append(
                    "hallu_http_request_duration_seconds_bucket"
                    f"{_http_label_text(labels, ('le', le))} {bucket_count}"
                )
            lines.append(
                "hallu_http_request_duration_seconds_sum"
                f"{_http_label_text(labels)} {_format_float(duration_sums.get(labels, 0.0))}"
            )
            lines.append(
                "hallu_http_request_duration_seconds_count"
                f"{_http_label_text(labels)} {request_totals[labels]}"
            )

        self._append_verification_metrics(
            lines,
            verification_totals,
            verification_duration_sums,
            verification_duration_buckets,
        )
        self._append_claim_verdict_metrics(lines, claim_verdict_totals)
        self._append_policy_metrics(
            lines,
            policy_decision_totals,
            policy_duration_sums,
            policy_duration_buckets,
        )
        self._append_approval_metrics(lines, approval_request_totals, approval_decision_totals)
        self._append_sandbox_metrics(
            lines,
            sandbox_run_totals,
            sandbox_duration_sums,
            sandbox_duration_buckets,
        )

        return "\n".join(lines) + "\n"

    def _append_verification_metrics(
        self,
        lines: list[str],
        totals: dict[VerificationRunLabels, int],
        duration_sums: dict[VerificationRunLabels, float],
        duration_buckets: dict[tuple[VerificationRunLabels, float], int],
    ) -> None:
        lines.extend(
            [
                "# HELP hallu_verification_runs_total Total verification runs by final decision.",
                "# TYPE hallu_verification_runs_total counter",
            ]
        )
        for labels, count in sorted(totals.items(), key=lambda item: _verification_sort_key(item[0])):
            lines.append(
                "hallu_verification_runs_total"
                f"{_verification_label_text(labels)} {count}"
            )
        self._append_histogram(
            lines,
            metric_name="hallu_verification_run_duration_seconds",
            help_text="Verification run latency in seconds.",
            labels=sorted(totals, key=_verification_sort_key),
            label_text=_verification_label_text,
            duration_sums=duration_sums,
            duration_buckets=duration_buckets,
            counts=totals,
        )

    def _append_claim_verdict_metrics(
        self,
        lines: list[str],
        totals: dict[ClaimVerdictLabels, int],
    ) -> None:
        lines.extend(
            [
                "# HELP hallu_claim_verdicts_total Total claim verdicts by status and action.",
                "# TYPE hallu_claim_verdicts_total counter",
            ]
        )
        for labels, count in sorted(totals.items(), key=lambda item: _claim_verdict_sort_key(item[0])):
            lines.append(
                "hallu_claim_verdicts_total"
                f"{_claim_verdict_label_text(labels)} {count}"
            )

    def _append_policy_metrics(
        self,
        lines: list[str],
        totals: dict[PolicyDecisionLabels, int],
        duration_sums: dict[PolicyDecisionLabels, float],
        duration_buckets: dict[tuple[PolicyDecisionLabels, float], int],
    ) -> None:
        lines.extend(
            [
                "# HELP hallu_policy_decisions_total Total policy decisions by allow/block action and primary rule.",
                "# TYPE hallu_policy_decisions_total counter",
            ]
        )
        for labels, count in sorted(totals.items(), key=lambda item: _policy_decision_sort_key(item[0])):
            lines.append(
                "hallu_policy_decisions_total"
                f"{_policy_decision_label_text(labels)} {count}"
            )
        self._append_histogram(
            lines,
            metric_name="hallu_policy_evaluation_duration_seconds",
            help_text="Policy evaluation latency in seconds.",
            labels=sorted(totals, key=_policy_decision_sort_key),
            label_text=_policy_decision_label_text,
            duration_sums=duration_sums,
            duration_buckets=duration_buckets,
            counts=totals,
        )

    def _append_approval_metrics(
        self,
        lines: list[str],
        request_totals: dict[ApprovalRequestLabels, int],
        decision_totals: dict[ApprovalDecisionLabels, int],
    ) -> None:
        lines.extend(
            [
                "# HELP hallu_approval_requests_total Total human approval requests by risk level.",
                "# TYPE hallu_approval_requests_total counter",
            ]
        )
        for request_labels, count in sorted(
            request_totals.items(),
            key=lambda item: _approval_request_sort_key(item[0]),
        ):
            lines.append(
                "hallu_approval_requests_total"
                f"{_approval_request_label_text(request_labels)} {count}"
            )
        lines.extend(
            [
                "# HELP hallu_approval_decisions_total Total human approval decisions by result.",
                "# TYPE hallu_approval_decisions_total counter",
            ]
        )
        for decision_labels, count in sorted(
            decision_totals.items(),
            key=lambda item: _approval_decision_sort_key(item[0]),
        ):
            lines.append(
                "hallu_approval_decisions_total"
                f"{_approval_decision_label_text(decision_labels)} {count}"
            )

    def _append_sandbox_metrics(
        self,
        lines: list[str],
        totals: dict[SandboxRunLabels, int],
        duration_sums: dict[SandboxRunLabels, float],
        duration_buckets: dict[tuple[SandboxRunLabels, float], int],
    ) -> None:
        lines.extend(
            [
                "# HELP hallu_sandbox_runs_total Total sandbox runs by verdict and outcome.",
                "# TYPE hallu_sandbox_runs_total counter",
            ]
        )
        for labels, count in sorted(totals.items(), key=lambda item: _sandbox_run_sort_key(item[0])):
            lines.append(
                "hallu_sandbox_runs_total"
                f"{_sandbox_run_label_text(labels)} {count}"
            )
        self._append_histogram(
            lines,
            metric_name="hallu_sandbox_run_duration_seconds",
            help_text="Sandbox run latency in seconds.",
            labels=sorted(totals, key=_sandbox_run_sort_key),
            label_text=_sandbox_run_label_text,
            duration_sums=duration_sums,
            duration_buckets=duration_buckets,
            counts=totals,
        )

    def _append_histogram(
        self,
        lines: list[str],
        *,
        metric_name: str,
        help_text: str,
        labels: list[TMetricLabels],
        label_text: LabelTextFn[TMetricLabels],
        duration_sums: dict[TMetricLabels, float],
        duration_buckets: dict[tuple[TMetricLabels, float], int],
        counts: dict[TMetricLabels, int],
    ) -> None:
        lines.extend(
            [
                f"# HELP {metric_name} {help_text}",
                f"# TYPE {metric_name} histogram",
            ]
        )
        for label_value in labels:
            for bucket in (*HTTP_DURATION_BUCKETS, float("inf")):
                bucket_count = duration_buckets.get((label_value, bucket), 0)
                le = "+Inf" if bucket == float("inf") else _format_float(bucket)
                lines.append(f"{metric_name}_bucket{label_text(label_value, ('le', le))} {bucket_count}")
            lines.append(
                f"{metric_name}_sum{label_text(label_value)} "
                f"{_format_float(duration_sums.get(label_value, 0.0))}"
            )
            lines.append(f"{metric_name}_count{label_text(label_value)} {counts[label_value]}")


def _http_label_text(labels: HttpRequestLabels, *extra: tuple[str, str]) -> str:
    return _label_text(
        ("method", labels.method),
        ("path", labels.path),
        ("status_code", labels.status_code),
        ("outcome", labels.outcome),
        *extra,
    )


def _verification_label_text(labels: VerificationRunLabels, *extra: tuple[str, str]) -> str:
    return _label_text(("final_decision", labels.final_decision), *extra)


def _claim_verdict_label_text(labels: ClaimVerdictLabels, *extra: tuple[str, str]) -> str:
    return _label_text(("status", labels.status), ("action", labels.action), *extra)


def _policy_decision_label_text(labels: PolicyDecisionLabels, *extra: tuple[str, str]) -> str:
    return _label_text(
        ("allowed", labels.allowed),
        ("action", labels.action),
        ("rule", labels.rule),
        *extra,
    )


def _approval_request_label_text(labels: ApprovalRequestLabels, *extra: tuple[str, str]) -> str:
    return _label_text(("risk_level", labels.risk_level), *extra)


def _approval_decision_label_text(labels: ApprovalDecisionLabels, *extra: tuple[str, str]) -> str:
    return _label_text(
        ("decision", labels.decision),
        ("status", labels.status),
        ("risk_level", labels.risk_level),
        *extra,
    )


def _sandbox_run_label_text(labels: SandboxRunLabels, *extra: tuple[str, str]) -> str:
    return _label_text(
        ("verdict", labels.verdict),
        ("network_policy", labels.network_policy),
        ("outcome", labels.outcome),
        *extra,
    )


def _label_text(*labels: tuple[str, str]) -> str:
    return "{" + ",".join(f'{name}="{_escape_label_value(value)}"' for name, value in labels) + "}"


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_float(value: float) -> str:
    return f"{value:.6g}"


def _label_sort_key(labels: HttpRequestLabels) -> tuple[str, str, str, str]:
    return labels.method, labels.path, labels.status_code, labels.outcome


def _verification_sort_key(labels: VerificationRunLabels) -> tuple[str]:
    return (labels.final_decision,)


def _claim_verdict_sort_key(labels: ClaimVerdictLabels) -> tuple[str, str]:
    return labels.status, labels.action


def _policy_decision_sort_key(labels: PolicyDecisionLabels) -> tuple[str, str, str]:
    return labels.allowed, labels.action, labels.rule


def _approval_request_sort_key(labels: ApprovalRequestLabels) -> tuple[str]:
    return (labels.risk_level,)


def _approval_decision_sort_key(labels: ApprovalDecisionLabels) -> tuple[str, str, str]:
    return labels.decision, labels.status, labels.risk_level


def _sandbox_run_sort_key(labels: SandboxRunLabels) -> tuple[str, str, str]:
    return labels.verdict, labels.network_policy, labels.outcome
