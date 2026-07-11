from __future__ import annotations

import json
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import TracebackType
from typing import Self
from urllib import request

import pytest

from hallu_defense.config import (
    SandboxConfigurationError,
    Settings,
    validate_sandbox_settings,
)
from hallu_defense.services.sandbox_exec import (
    MAX_SANDBOX_WORKSPACE_BYTES,
    MAX_SANDBOX_WORKSPACE_FILES,
    SANDBOX_GIT_INSPECTOR_PATH,
    SANDBOX_TIMEOUT_RETURN_CODE,
    SandboxExecutionError,
    build_sandbox_execution_backend,
)
from hallu_defense.services.sandbox_kubernetes import (
    NETWORK_POLICY_DENY_VALUE,
    NETWORK_POLICY_LABEL,
    SANDBOX_BATCH_RUNNER_PATH,
    SANDBOX_RUNNER_PATH,
    SANDBOX_STREAM_EXPORTER_PATH,
    InClusterKubernetesTransport,
    KubernetesApiError,
    KubernetesApiTransport,
    KubernetesJobBackend,
)

JOB_NAME = "hallu-sandbox-0123456789abcdef"
JOB_UID = "11111111-2222-3333-4444-555555555555"
POD_UID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NAMESPACE = "sandbox-system"
POLICY_NAME = "sandbox-deny-egress"


@dataclass(frozen=True)
class KubernetesCall:
    method: str
    path: str
    query: Mapping[str, str | int] | None
    payload: Mapping[str, object] | None
    timeout: float


class RecordingTransport:
    def __init__(self, responses: list[bytes | Exception]) -> None:
        self._responses = list(responses)
        self.calls: list[KubernetesCall] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str | int] | None = None,
        payload: Mapping[str, object] | None = None,
        timeout: float,
    ) -> bytes:
        self.calls.append(
            KubernetesCall(
                method=method,
                path=path,
                query=query,
                payload=payload,
                timeout=timeout,
            )
        )
        if not self._responses:
            raise AssertionError(f"unexpected Kubernetes request: {method} {path}")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeHttpResponse:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, exc, traceback
        return None

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]


class RecordingUrlOpen:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.calls: list[tuple[request.Request, float, ssl.SSLContext]] = []

    def __call__(
        self,
        url_request: request.Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> FakeHttpResponse:
        self.calls.append((url_request, timeout, context))
        return FakeHttpResponse(self._body)


def test_kubernetes_backend_creates_hardened_job_and_captures_separate_streams(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            _json_bytes(
                _job(
                    status={
                        "conditions": [
                            {
                                "type": "Failed",
                                "status": "True",
                                "reason": "BackoffLimitExceeded",
                            }
                        ]
                    }
                )
            ),
            _json_bytes({"items": [_pod(runner_exit_code=7)]}),
            b"command stdout\n",
            b"command stderr\n",
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    result = backend.execute(
        ["python", "probe.py", "--flag=value with spaces"],
        cwd=repo,
        env={
            "HALLU_DEFENSE_NETWORK_POLICY": "deny",
            "API_KEY": "super-secret-value",
        },
        timeout=5,
        output_caps=1000,
    )

    assert result.returncode == 7
    assert result.stdout == "command stdout\n"
    assert result.stderr == "command stderr\n"
    assert result.timed_out is False
    assert [call.method for call in transport.calls] == [
        "GET",
        "POST",
        "GET",
        "GET",
        "GET",
        "GET",
        "DELETE",
    ]
    assert transport.calls[0].path.endswith(
        "/networkpolicies"
    )
    assert transport.calls[-1].path.endswith(f"/jobs/{JOB_NAME}")

    create_call = transport.calls[1]
    assert create_call.path == f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs"
    assert create_call.payload is not None
    manifest = create_call.payload
    assert manifest["apiVersion"] == "batch/v1"
    metadata = _dict(manifest["metadata"])
    assert metadata["name"] == JOB_NAME
    assert metadata["namespace"] == NAMESPACE
    assert _dict(metadata["labels"])[NETWORK_POLICY_LABEL] == NETWORK_POLICY_DENY_VALUE
    spec = _dict(manifest["spec"])
    assert spec["backoffLimit"] == 0
    assert spec["suspend"] is False
    assert spec["activeDeadlineSeconds"] == 5
    assert spec["ttlSecondsAfterFinished"] == 60
    template = _dict(spec["template"])
    pod_spec = _dict(_dict(template["spec"]))
    assert pod_spec["automountServiceAccountToken"] is False
    assert pod_spec["enableServiceLinks"] is False
    assert pod_spec["hostNetwork"] is False
    assert pod_spec["hostPID"] is False
    assert pod_spec["hostIPC"] is False
    assert _dict(pod_spec["securityContext"])["seccompProfile"] == {
        "type": "RuntimeDefault"
    }
    containers = _list_of_dicts(pod_spec["containers"])
    assert [container["name"] for container in containers] == [
        "runner",
        "stdout",
        "stderr",
    ]
    for container in containers:
        security_context = _dict(container["securityContext"])
        assert security_context["runAsNonRoot"] is True
        assert security_context["readOnlyRootFilesystem"] is True
        assert security_context["allowPrivilegeEscalation"] is False
        assert security_context["capabilities"] == {"drop": ["ALL"]}
        assert security_context["seccompProfile"] == {"type": "RuntimeDefault"}
    runner = containers[0]
    assert runner["workingDir"] == "/workspace"
    runner_mounts = _list_of_dicts(runner["volumeMounts"])
    source_mount = next(mount for mount in runner_mounts if mount["name"] == "source")
    assert source_mount == {
        "name": "source",
        "mountPath": "/hallu-source",
        "subPath": "repo",
        "readOnly": True,
    }
    workspace_mount = next(
        mount for mount in runner_mounts if mount["name"] == "workspace"
    )
    assert workspace_mount == {"name": "workspace", "mountPath": "/workspace"}
    assert all(
        mount["name"] != "workspace"
        for exporter in containers[1:]
        for mount in _list_of_dicts(exporter["volumeMounts"])
    )
    assert runner["args"] == [
        "256",
        str(MAX_SANDBOX_WORKSPACE_FILES),
        str(MAX_SANDBOX_WORKSPACE_BYTES),
        "python",
        "probe.py",
        "--flag=value with spaces",
    ]
    assert runner["command"] == ["python", SANDBOX_RUNNER_PATH]
    for exporter in containers[1:]:
        assert exporter["command"] == ["python", SANDBOX_STREAM_EXPORTER_PATH]
    assert _dict(_dict(runner["resources"])["limits"]) == {
        "cpu": "1",
        "memory": "512Mi",
    }
    volumes = _list_of_dicts(pod_spec["volumes"])
    source_volume = next(volume for volume in volumes if volume["name"] == "source")
    assert source_volume["persistentVolumeClaim"] == {
        "claimName": "sandbox-workspace"
    }
    workspace_volume = next(volume for volume in volumes if volume["name"] == "workspace")
    assert workspace_volume["emptyDir"] == {"sizeLimit": "512Mi"}
    serialized_manifest = json.dumps(manifest)
    assert "super-secret-value" not in serialized_manifest
    assert "API_KEY" not in serialized_manifest
    assert "secretKeyRef" not in serialized_manifest
    assert "configMap" not in serialized_manifest
    assert "envFrom" not in serialized_manifest
    assert "serviceAccountName" not in serialized_manifest
    assert transport.calls[4].query == {
        "container": "stdout",
        "limitBytes": 4000,
    }
    assert transport.calls[5].query == {
        "container": "stderr",
        "limitBytes": 4000,
    }


def test_kubernetes_backend_mounts_source_read_only_and_working_copy_ephemeral(
    tmp_path: Path,
) -> None:
    backend, _repo = _backend(tmp_path, transport=RecordingTransport([]))

    manifest = backend.build_job_manifest(
        job_name=JOB_NAME,
        argv=["python", SANDBOX_GIT_INSPECTOR_PATH, "0.625", "1024"],
        workspace_sub_path="repo",
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        timeout=5,
        output_caps=32_768,
    )

    pod_spec = _dict(_dict(_dict(manifest["spec"])["template"])["spec"])
    runner = _list_of_dicts(pod_spec["containers"])[0]
    source_mount = next(
        mount
        for mount in _list_of_dicts(runner["volumeMounts"])
        if mount["name"] == "source"
    )
    assert source_mount == {
        "name": "source",
        "mountPath": "/hallu-source",
        "subPath": "repo",
        "readOnly": True,
    }
    workspace_volume = next(
        volume
        for volume in _list_of_dicts(pod_spec["volumes"])
        if volume["name"] == "workspace"
    )
    assert workspace_volume == {
        "name": "workspace",
        "emptyDir": {"sizeLimit": "512Mi"},
    }


def test_kubernetes_batch_executes_all_commands_in_one_ephemeral_job(
    tmp_path: Path,
) -> None:
    batch_payload = {
        "schema_version": "sandbox_execution_batch.v3",
        "pre_snapshot_fingerprint": "0" * 64,
        "post_snapshot_fingerprint": "1" * 64,
        "executions": [
            {
                "returncode": 0,
                "stdout": "first\n",
                "stderr": "",
                "timed_out": False,
            },
            {
                "returncode": 2,
                "stdout": "",
                "stderr": "second failed\n",
                "timed_out": False,
            },
        ],
        "artifacts": ["artifacts/result.txt"],
    }
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            _json_bytes(_job(status={"succeeded": 1})),
            _json_bytes({"items": [_pod(runner_exit_code=0)]}),
            json.dumps(batch_payload, separators=(",", ":")).encode(),
            b"",
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    result = backend.execute_batch(
        [["python", "first.py"], ["node", "second.js"]],
        cwd=repo,
        source_cwd=repo,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        timeout=5,
        output_caps=1000,
    )

    assert [item.returncode for item in result.executions] == [0, 2]
    assert result.artifacts == ("artifacts/result.txt",)
    create_calls = [call for call in transport.calls if call.method == "POST"]
    assert len(create_calls) == 1
    manifest = create_calls[0].payload
    assert manifest is not None
    assert _dict(manifest["spec"])["activeDeadlineSeconds"] == 25
    pod_spec = _dict(_dict(_dict(manifest["spec"])["template"])["spec"])
    runner = _list_of_dicts(pod_spec["containers"])[0]
    runner_args = runner["args"]
    assert isinstance(runner_args, list)
    assert SANDBOX_BATCH_RUNNER_PATH in runner_args
    serialized_commands = runner_args[-1]
    assert json.loads(serialized_commands) == [
        ["python", "first.py"],
        ["node", "second.js"],
    ]


def test_kubernetes_backend_rejects_created_job_without_valid_uid(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job(uid="")),
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="created Job UID"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert [call.method for call in transport.calls] == ["GET", "POST", "DELETE"]


def test_kubernetes_backend_rejects_job_uid_drift_while_polling(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            _json_bytes(
                _job(
                    uid="99999999-8888-7777-6666-555555555555",
                    status={"succeeded": 1},
                )
            ),
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="Job UID changed"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )


def test_kubernetes_backend_rejects_spoofed_pod_owner_identity(
    tmp_path: Path,
) -> None:
    spoofed_pod = _pod(runner_exit_code=0)
    metadata = _dict(spoofed_pod["metadata"])
    owner_references = _list_of_dicts(metadata["ownerReferences"])
    owner_references[0]["uid"] = "99999999-8888-7777-6666-555555555555"
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            _json_bytes(_job(status={"succeeded": 1})),
            _json_bytes({"items": [spoofed_pod]}),
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="owner identity"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert not any(call.path.endswith("/log") for call in transport.calls)


@pytest.mark.parametrize(
    "pod_count",
    [0, 2],
)
def test_kubernetes_backend_rejects_missing_or_ambiguous_job_pods(
    tmp_path: Path,
    pod_count: int,
) -> None:
    pods = [_pod(runner_exit_code=0) for _index in range(pod_count)]
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            _json_bytes(_job(status={"succeeded": 1})),
            _json_bytes({"items": pods}),
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="without a Pod|unexpected number"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )


def test_kubernetes_backend_timeout_returns_partial_streams_and_deletes_job(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    active_job = _json_bytes(_job(status={"active": 1}))
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            active_job,
            _json_bytes({"items": [_pod(runner_exit_code=None)]}),
            b"partial stdout\n",
            b"partial stderr\n",
            b"{}",
        ]
    )
    backend, repo = _backend(
        tmp_path,
        transport=transport,
        clock=clock,
        poll_interval_seconds=1.0,
    )

    result = backend.execute(
        ["python", "slow.py"],
        cwd=repo,
        env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
        timeout=1,
        output_caps=1000,
    )

    assert result.returncode == SANDBOX_TIMEOUT_RETURN_CODE
    assert result.timed_out is True
    assert result.stdout == "partial stdout\n"
    assert "partial stderr" in result.stderr
    assert "timed out after 1 second(s)" in result.stderr
    assert clock.sleeps == [1.0]
    assert transport.calls[-1].method == "DELETE"


def test_kubernetes_backend_rejects_workspace_root_without_mandatory_subpath(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport([])
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="subPath is mandatory"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo.parent,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert transport.calls == []


def test_kubernetes_backend_rejects_cwd_outside_workspace_before_api_calls(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport([])
    backend, _repo = _backend(tmp_path, transport=transport)
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(SandboxExecutionError, match="escapes"):
        backend.execute(
            ["python", "probe.py"],
            cwd=outside,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert transport.calls == []


def test_kubernetes_backend_fails_closed_before_job_when_network_policy_is_permissive(
    tmp_path: Path,
) -> None:
    policy = _network_policy()
    named_policy = _list_of_dicts(policy["items"])[0]
    _dict(named_policy["spec"])["egress"] = [
        {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}
    ]
    transport = RecordingTransport([_json_bytes(policy)])
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="deny all egress"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert len(transport.calls) == 1
    assert transport.calls[0].method == "GET"


def test_kubernetes_backend_rejects_additive_egress_policy_selecting_job(
    tmp_path: Path,
) -> None:
    policy_list = _network_policy()
    _list_of_dicts(policy_list["items"]).append(
        {
            "metadata": {"name": "namespace-egress-allow"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [
                    {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}
                ],
            },
        }
    )
    transport = RecordingTransport([_json_bytes(policy_list)])
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="permits egress"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert [call.method for call in transport.calls] == ["GET"]


def test_kubernetes_backend_deletes_created_job_when_poll_payload_is_invalid(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            _json_bytes(_job()),
            b"not-json",
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(SandboxExecutionError, match="invalid JSON for poll Job"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert transport.calls[-1].method == "DELETE"
    assert transport.calls[-1].path.endswith(f"/jobs/{JOB_NAME}")


def test_kubernetes_backend_cleans_up_ambiguous_create_transport_failure(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(
        [
            _json_bytes(_network_policy()),
            KubernetesApiError("create request timed out"),
            b"{}",
        ]
    )
    backend, repo = _backend(tmp_path, transport=transport)

    with pytest.raises(KubernetesApiError, match="create request timed out"):
        backend.execute(
            ["python", "probe.py"],
            cwd=repo,
            env={"HALLU_DEFENSE_NETWORK_POLICY": "deny"},
            timeout=5,
            output_caps=1000,
        )

    assert [call.method for call in transport.calls] == ["GET", "POST", "DELETE"]


def test_in_cluster_transport_uses_service_account_token_ca_and_https(
    tmp_path: Path,
) -> None:
    token_path = tmp_path / "token"
    ca_path = tmp_path / "ca.crt"
    token_path.write_text("service-account-token\n", encoding="utf-8")
    ca_path.write_text("test-ca", encoding="utf-8")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca_calls: list[str] = []
    urlopen = RecordingUrlOpen(b'{"kind":"PodList"}')

    transport = InClusterKubernetesTransport.from_service_account(
        token_path=token_path,
        ca_path=ca_path,
        env={
            "KUBERNETES_SERVICE_HOST": "10.0.0.1",
            "KUBERNETES_SERVICE_PORT_HTTPS": "6443",
        },
        urlopen=urlopen,
        context_factory=lambda path: _record_context(path, ca_calls, ssl_context),
    )
    token_path.write_text("rotated-service-account-token\n", encoding="utf-8")

    body = transport.request(
        "GET",
        "/api/v1/namespaces/sandbox-system/pods",
        query={"limit": 1},
        timeout=2,
    )

    assert body == b'{"kind":"PodList"}'
    assert ca_calls == [str(ca_path)]
    assert len(urlopen.calls) == 1
    url_request, timeout, used_context = urlopen.calls[0]
    assert url_request.full_url == (
        "https://10.0.0.1:6443/api/v1/namespaces/sandbox-system/pods?limit=1"
    )
    assert url_request.get_header("Authorization") == (
        "Bearer rotated-service-account-token"
    )
    assert timeout == 2
    assert used_context is ssl_context
    assert "rotated-service-account-token" not in url_request.full_url


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sandbox_kubernetes_image", "", "KUBERNETES_IMAGE"),
        ("sandbox_kubernetes_namespace", "bad.namespace", "KUBERNETES_NAMESPACE"),
        ("sandbox_kubernetes_pvc_name", "", "KUBERNETES_PVC_NAME"),
        (
            "sandbox_kubernetes_workspace_mount_path",
            "workspace",
            "WORKSPACE_MOUNT_PATH",
        ),
        (
            "sandbox_kubernetes_network_policy_name",
            "",
            "NETWORK_POLICY_NAME",
        ),
        (
            "sandbox_kubernetes_tenant_id",
            "",
            "KUBERNETES_TENANT_ID",
        ),
    ],
)
def test_kubernetes_settings_fail_closed_when_explicit_values_are_invalid(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    settings = replace(_settings(tmp_path), **{field: value})

    with pytest.raises(SandboxConfigurationError, match=message):
        validate_sandbox_settings(settings)


def test_production_settings_accept_kubernetes_and_factory_keeps_docker_host_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = RecordingTransport([])
    settings = _settings(tmp_path, environment="production")
    monkeypatch.setattr(
        InClusterKubernetesTransport,
        "from_service_account",
        staticmethod(lambda: transport),
    )

    validate_sandbox_settings(settings)
    backend = build_sandbox_execution_backend(settings)

    assert isinstance(backend, KubernetesJobBackend)


def _backend(
    tmp_path: Path,
    *,
    transport: KubernetesApiTransport,
    clock: FakeClock | None = None,
    poll_interval_seconds: float = 0.25,
) -> tuple[KubernetesJobBackend, Path]:
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    effective_clock = clock or FakeClock()
    backend = KubernetesJobBackend(
        image="registry.example/sandbox:2026-07-09",
        namespace=NAMESPACE,
        pvc_name="sandbox-workspace",
        workspace_root=workspace,
        workspace_mount_path="/workspace",
        network_policy_name=POLICY_NAME,
        memory_mb=512,
        cpus=1.0,
        pids_limit=256,
        poll_interval_seconds=poll_interval_seconds,
        job_ttl_seconds=60,
        api_request_timeout_seconds=2,
        setup_grace_seconds=15,
        timeout_grace_seconds=2,
        transport=transport,
        monotonic=effective_clock.monotonic,
        sleep=effective_clock.sleep,
        name_factory=lambda: JOB_NAME,
    )
    return backend, repo


def _settings(
    tmp_path: Path,
    *,
    environment: str = "test",
) -> Settings:
    return Settings(
        environment=environment,
        policy_version="test",
        auth_required=False,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        sandbox_backend="kubernetes",
        sandbox_kubernetes_image=(
            "registry.example/sandbox@sha256:"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        sandbox_kubernetes_namespace=NAMESPACE,
        sandbox_kubernetes_pvc_name="sandbox-workspace",
        sandbox_kubernetes_workspace_mount_path="/workspace",
        sandbox_kubernetes_network_policy_name=POLICY_NAME,
        sandbox_kubernetes_tenant_id="tenant-a",
    )


def test_production_kubernetes_settings_require_digest_pinned_image(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(tmp_path, environment="production"),
        sandbox_kubernetes_image="registry.example/sandbox:2026-07-09",
    )

    with pytest.raises(SandboxConfigurationError, match="pinned by sha256 digest"):
        validate_sandbox_settings(settings)


def test_kind_profile_accepts_only_the_isolated_local_sandbox_image(tmp_path: Path) -> None:
    settings = replace(
        _settings(tmp_path, environment="production"),
        sandbox_kubernetes_image="hallu-defense-sandbox:ci",
        sandbox_kubernetes_kind_local_image=True,
    )

    validate_sandbox_settings(settings)


def test_kind_profile_rejects_any_other_mutable_sandbox_image(tmp_path: Path) -> None:
    settings = replace(
        _settings(tmp_path, environment="production"),
        sandbox_kubernetes_image="registry.example/sandbox:ci",
        sandbox_kubernetes_kind_local_image=True,
    )

    with pytest.raises(SandboxConfigurationError, match="permits only the isolated"):
        validate_sandbox_settings(settings)


def _network_policy() -> dict[str, object]:
    return {
        "items": [
            {
                "metadata": {"name": POLICY_NAME},
                "spec": {
                    "podSelector": {
                        "matchLabels": {
                            NETWORK_POLICY_LABEL: NETWORK_POLICY_DENY_VALUE
                        }
                    },
                    "policyTypes": ["Egress"],
                    "egress": [],
                },
            },
        ]
    }


def _pod(*, runner_exit_code: int | None) -> dict[str, object]:
    statuses: list[dict[str, object]] = []
    if runner_exit_code is not None:
        statuses = [
            _terminated_status("runner", runner_exit_code),
            _terminated_status("stdout", 0),
            _terminated_status("stderr", 0),
        ]
    return {
        "metadata": {
            "name": f"{JOB_NAME}-pod",
            "namespace": NAMESPACE,
            "uid": POD_UID,
            "labels": {
                "job-name": JOB_NAME,
                "batch.kubernetes.io/job-name": JOB_NAME,
            },
            "ownerReferences": [
                {
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": JOB_NAME,
                    "uid": JOB_UID,
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
            ],
        },
        "status": {"containerStatuses": statuses},
    }


def _job(
    *,
    uid: str = JOB_UID,
    status: Mapping[str, object] | None = None,
) -> dict[str, object]:
    job: dict[str, object] = {
        "metadata": {
            "name": JOB_NAME,
            "namespace": NAMESPACE,
            "uid": uid,
        }
    }
    if status is not None:
        job["status"] = dict(status)
    return job


def _terminated_status(name: str, exit_code: int) -> dict[str, object]:
    return {
        "name": name,
        "state": {"terminated": {"exitCode": exit_code}},
    }


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value).encode("utf-8")


def _dict(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    assert all(isinstance(item, dict) for item in value)
    return value


def _record_context(
    path: str,
    calls: list[str],
    context: ssl.SSLContext,
) -> ssl.SSLContext:
    calls.append(path)
    return context
