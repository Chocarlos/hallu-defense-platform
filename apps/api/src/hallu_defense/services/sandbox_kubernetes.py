from __future__ import annotations

import json
import ipaddress
import math
import os
import re
import secrets
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Protocol, Self, cast
from urllib import error, parse, request

from hallu_defense.config import Settings
from hallu_defense.outbound_http import OutboundHttpRedirectError, open_url_no_redirect
from hallu_defense.services.sandbox_exec import (
    MAX_SANDBOX_BATCH_CONTROL_CHARS,
    MAX_SANDBOX_WORKSPACE_BYTES,
    MAX_SANDBOX_WORKSPACE_FILES,
    MAX_SANDBOX_OUTPUT_CHARS,
    SANDBOX_TIMEOUT_RETURN_CODE,
    ExecutionResult,
    SandboxExecutionBatchResult,
    SandboxExecutionConfigurationError,
    SandboxExecutionError,
    decode_sandbox_execution_batch,
    sanitized_container_environment,
)
from hallu_defense.services.text import bounded

SERVICE_ACCOUNT_TOKEN_PATH = Path("/run/hallu-defense/kubernetes/token")
SERVICE_ACCOUNT_CA_PATH = Path("/run/hallu-defense/kubernetes/ca.crt")
NETWORK_POLICY_LABEL = "hallu-defense.openai.com/network-policy"
NETWORK_POLICY_DENY_VALUE = "deny-egress"
SANDBOX_LABEL = "hallu-defense.openai.com/sandbox"
JOB_NAME_LABEL = "batch.kubernetes.io/job-name"
RUNNER_CONTAINER = "runner"
STDOUT_CONTAINER = "stdout"
STDERR_CONTAINER = "stderr"
RESULTS_MOUNT_PATH = "/hallu-results"
SOURCE_MOUNT_PATH = "/hallu-source"
MAX_KUBERNETES_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_JOB_NAME_LENGTH = 63
MAX_COMMAND_ARGUMENTS = 256
MAX_COMMAND_BYTES = 32 * 1024
MAX_ENV_VALUE_CHARS = 1024
MAX_CLEANUP_WAIT_SECONDS = 30.0
SANDBOX_RUNNER_PATH = "/opt/hallu-defense/sandbox_runner.py"
SANDBOX_BATCH_RUNNER_PATH = "/opt/hallu-defense/sandbox_batch_runner.py"
SANDBOX_STREAM_EXPORTER_PATH = "/opt/hallu-defense/sandbox_stream_exporter.py"
PIDS_LIMIT_ANNOTATION = "hallu-defense.openai.com/requested-pids-limit"
KUBERNETES_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
KUBERNETES_SUBDOMAIN_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
KUBERNETES_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class KubernetesApiError(SandboxExecutionError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class KubernetesApiTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str | int] | None = None,
        payload: Mapping[str, object] | None = None,
        timeout: float,
    ) -> bytes: ...


class KubernetesHttpResponse(Protocol):
    status: int

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def read(self, amount: int = -1) -> bytes: ...


class KubernetesUrlOpen(Protocol):
    def __call__(
        self,
        url_request: request.Request,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> KubernetesHttpResponse: ...


@dataclass(frozen=True)
class KubernetesJobState:
    terminal: bool
    timed_out: bool


class InClusterKubernetesTransport:
    def __init__(
        self,
        *,
        api_server: str,
        token: str | None = None,
        token_loader: Callable[[], str] | None = None,
        ssl_context: ssl.SSLContext,
        urlopen: KubernetesUrlOpen | None = None,
    ) -> None:
        normalized_server = api_server.strip().rstrip("/")
        parsed_server = parse.urlsplit(normalized_server)
        if (
            parsed_server.scheme != "https"
            or parsed_server.hostname is None
            or parsed_server.username is not None
            or parsed_server.password is not None
            or parsed_server.path
            or parsed_server.query
            or parsed_server.fragment
        ):
            raise SandboxExecutionConfigurationError("Kubernetes API server must use https.")
        if (token is None) == (token_loader is None):
            raise SandboxExecutionConfigurationError(
                "Configure exactly one Kubernetes ServiceAccount token source."
            )
        if token is not None:
            _validate_service_account_token(token)
            token_loader = _fixed_token_loader(token)
        assert token_loader is not None
        _validate_service_account_token(token_loader())
        self._api_server = normalized_server
        self._token_loader = token_loader
        self._ssl_context = ssl_context
        self._urlopen = urlopen or cast(KubernetesUrlOpen, open_url_no_redirect)

    @classmethod
    def from_service_account(
        cls,
        *,
        token_path: Path = SERVICE_ACCOUNT_TOKEN_PATH,
        ca_path: Path = SERVICE_ACCOUNT_CA_PATH,
        env: Mapping[str, str] | None = None,
        urlopen: KubernetesUrlOpen | None = None,
        context_factory: Callable[[str], ssl.SSLContext] | None = None,
    ) -> InClusterKubernetesTransport:
        effective_env = os.environ if env is None else env
        api_server = _in_cluster_api_server(effective_env)

        def token_loader() -> str:
            return _read_service_account_token(token_path)

        build_context = context_factory or _ssl_context_from_ca
        try:
            ssl_context = build_context(str(ca_path))
        except (OSError, ssl.SSLError) as exc:
            raise SandboxExecutionConfigurationError(
                "Kubernetes ServiceAccount CA bundle is unavailable or invalid."
            ) from exc
        return cls(
            api_server=api_server,
            token_loader=token_loader,
            ssl_context=ssl_context,
            urlopen=urlopen,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str | int] | None = None,
        payload: Mapping[str, object] | None = None,
        timeout: float,
    ) -> bytes:
        normalized_method = method.upper()
        if normalized_method not in {"GET", "POST", "DELETE"}:
            raise KubernetesApiError("Kubernetes API method is not allowed.")
        if not _safe_api_path(path):
            raise KubernetesApiError("Kubernetes API path is invalid.")
        if timeout <= 0 or not math.isfinite(timeout):
            raise KubernetesApiError("Kubernetes API timeout must be positive.")
        url = f"{self._api_server}{path}"
        if query:
            url = f"{url}?{parse.urlencode(query)}"
        data = None
        service_account_credential = self._token_loader()
        _validate_service_account_token(service_account_credential)
        headers = {
            "Accept": "*/*",
            "Authorization": f"Bearer {service_account_credential.strip()}",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        url_request = request.Request(
            url,
            data=data,
            headers=headers,
            method=normalized_method,
        )
        try:
            with self._urlopen(
                url_request,
                timeout=timeout,
                context=self._ssl_context,
            ) as response:
                body = response.read(MAX_KUBERNETES_RESPONSE_BYTES + 1)
                status = response.status
        except OutboundHttpRedirectError:
            raise KubernetesApiError(
                f"Kubernetes API {normalized_method} redirects are not allowed."
            ) from None
        except error.HTTPError as exc:
            status_code = exc.code
            try:
                exc.close()
            finally:
                raise KubernetesApiError(
                    f"Kubernetes API {normalized_method} failed with HTTP {status_code}.",
                    status_code=status_code,
                ) from None
        except (error.URLError, TimeoutError, OSError):
            raise KubernetesApiError(
                f"Kubernetes API {normalized_method} request failed."
            ) from None
        if status < 200 or status >= 300:
            raise KubernetesApiError(
                f"Kubernetes API {normalized_method} failed with HTTP {status}.",
                status_code=status,
            )
        if len(body) > MAX_KUBERNETES_RESPONSE_BYTES:
            raise KubernetesApiError("Kubernetes API response exceeded the safety limit.")
        return body


class KubernetesJobBackend:
    """Run one sandbox command batch per Kubernetes Job through the in-cluster API.

    Jobs carry ``NETWORK_POLICY_LABEL=deny-egress``. The source PVC is mounted
    read-only and copied into one bounded ``emptyDir`` working tree. The
    deployment chart must
    create the configured default-deny Egress NetworkPolicy selecting that
    exact label; this backend verifies the policy before every Job and fails
    closed when it is absent or permits any egress rule.
    """

    def __init__(
        self,
        *,
        image: str,
        namespace: str,
        pvc_name: str,
        workspace_root: Path,
        workspace_mount_path: str,
        network_policy_name: str,
        memory_mb: int,
        cpus: float,
        pids_limit: int,
        poll_interval_seconds: float,
        job_ttl_seconds: int,
        api_request_timeout_seconds: float,
        setup_grace_seconds: float,
        timeout_grace_seconds: float,
        cleanup_grace_seconds: float = 20.0,
        transport: KubernetesApiTransport,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        name_factory: Callable[[], str] | None = None,
    ) -> None:
        _validate_backend_configuration(
            image=image,
            namespace=namespace,
            pvc_name=pvc_name,
            workspace_root=workspace_root,
            workspace_mount_path=workspace_mount_path,
            network_policy_name=network_policy_name,
            memory_mb=memory_mb,
            cpus=cpus,
            pids_limit=pids_limit,
            poll_interval_seconds=poll_interval_seconds,
            job_ttl_seconds=job_ttl_seconds,
            api_request_timeout_seconds=api_request_timeout_seconds,
            setup_grace_seconds=setup_grace_seconds,
            timeout_grace_seconds=timeout_grace_seconds,
            cleanup_grace_seconds=cleanup_grace_seconds,
        )
        self._image = image
        self._namespace = namespace
        self._pvc_name = pvc_name
        self._workspace_root = workspace_root.resolve()
        self._workspace_mount_path = workspace_mount_path
        self._network_policy_name = network_policy_name
        self._memory_mb = memory_mb
        self._cpus = cpus
        self._pids_limit = pids_limit
        self._poll_interval_seconds = poll_interval_seconds
        self._job_ttl_seconds = job_ttl_seconds
        self._api_request_timeout_seconds = api_request_timeout_seconds
        self._setup_grace_seconds = setup_grace_seconds
        self._timeout_grace_seconds = timeout_grace_seconds
        self._cleanup_grace_seconds = cleanup_grace_seconds
        self._transport = transport
        self._monotonic = monotonic
        self._sleep = sleep
        self._name_factory = name_factory or (lambda: f"hallu-sandbox-{secrets.token_hex(8)}")

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: KubernetesApiTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        name_factory: Callable[[], str] | None = None,
    ) -> KubernetesJobBackend:
        return cls(
            image=settings.sandbox_kubernetes_image,
            namespace=settings.sandbox_kubernetes_namespace,
            pvc_name=settings.sandbox_kubernetes_pvc_name,
            workspace_root=settings.allowed_workspace,
            workspace_mount_path=settings.sandbox_kubernetes_workspace_mount_path,
            network_policy_name=settings.sandbox_kubernetes_network_policy_name,
            memory_mb=settings.sandbox_docker_memory_mb,
            cpus=settings.sandbox_docker_cpus,
            pids_limit=settings.sandbox_docker_pids_limit,
            poll_interval_seconds=settings.sandbox_kubernetes_poll_interval_seconds,
            job_ttl_seconds=settings.sandbox_kubernetes_job_ttl_seconds,
            api_request_timeout_seconds=(settings.sandbox_kubernetes_api_request_timeout_seconds),
            setup_grace_seconds=settings.sandbox_kubernetes_setup_grace_seconds,
            timeout_grace_seconds=settings.sandbox_docker_timeout_grace_seconds,
            cleanup_grace_seconds=(settings.sandbox_kubernetes_cleanup_grace_seconds),
            transport=transport or InClusterKubernetesTransport.from_service_account(),
            monotonic=monotonic,
            sleep=sleep,
            name_factory=name_factory,
        )

    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
        source_cwd: Path | None = None,
    ) -> ExecutionResult:
        return self._execute_control_command(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            output_caps=output_caps,
            source_cwd=source_cwd,
            max_output_caps=MAX_SANDBOX_OUTPUT_CHARS,
        )

    def _execute_control_command(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
        source_cwd: Path | None,
        max_output_caps: int,
    ) -> ExecutionResult:
        _validate_execution_request(
            argv,
            timeout=timeout,
            output_caps=output_caps,
            max_output_caps=max_output_caps,
        )
        effective_source_cwd = cwd if source_cwd is None else source_cwd
        if effective_source_cwd.resolve() != cwd.resolve():
            raise SandboxExecutionError(
                "Kubernetes source cwd must match the tenant-bound repository cwd."
            )
        workspace_sub_path = self._workspace_sub_path(cwd)
        job_name = self._new_job_name()
        request_timeout = min(self._api_request_timeout_seconds, timeout)
        self._assert_default_deny_network_policy(
            request_timeout,
            job_name=job_name,
        )
        manifest = self.build_job_manifest(
            job_name=job_name,
            argv=argv,
            workspace_sub_path=workspace_sub_path,
            env=env,
            timeout=timeout,
            output_caps=output_caps,
        )
        jobs_path = self._jobs_path()
        job_uid: str | None = None
        primary_error: Exception | None = None
        started_at = self._monotonic()
        try:
            try:
                created_job = self._request_json(
                    "POST",
                    jobs_path,
                    payload=manifest,
                    timeout=request_timeout,
                    label="create Job",
                )
            except SandboxExecutionError as exc:
                if (
                    isinstance(exc, KubernetesApiError)
                    and exc.status_code is not None
                    and 400 <= exc.status_code < 500
                ):
                    raise
                try:
                    job_uid = self._reconcile_ambiguous_job_creation(
                        job_name,
                        timeout=self._cleanup_grace_seconds,
                    )
                except Exception as reconciliation_exc:
                    exc.add_note(
                        "Kubernetes sandbox Job creation could not be reconciled; "
                        "no name-only cleanup was attempted "
                        f"({type(reconciliation_exc).__name__})."
                    )
                    raise exc from reconciliation_exc
                if job_uid is None:
                    exc.add_note(
                        "Kubernetes sandbox Job creation reconciliation found no Job; "
                        "no cleanup was attempted."
                    )
                else:
                    exc.add_note(
                        "Kubernetes sandbox Job creation reconciliation validated a Job UID; "
                        "UID-bound foreground cleanup was attempted."
                    )
                raise
            try:
                job_uid = _validated_managed_job_identity(
                    created_job,
                    expected_name=job_name,
                    expected_namespace=self._namespace,
                    expected_pids_limit=self._pids_limit,
                    label="created Job",
                )
            except SandboxExecutionError as identity_exc:
                try:
                    job_uid = self._reconcile_ambiguous_job_creation(
                        job_name,
                        timeout=self._cleanup_grace_seconds,
                    )
                except Exception as reconciliation_exc:
                    identity_exc.add_note(
                        "Kubernetes sandbox created-Job identity could not be reconciled; "
                        "no name-only cleanup was attempted "
                        f"({type(reconciliation_exc).__name__})."
                    )
                    raise identity_exc from reconciliation_exc
                if job_uid is None:
                    identity_exc.add_note(
                        "Kubernetes sandbox created-Job identity reconciliation found no Job; "
                        "no cleanup was attempted."
                    )
                else:
                    identity_exc.add_note(
                        "Kubernetes sandbox created-Job identity was recovered by a validated "
                        "GET; UID-bound foreground cleanup was attempted."
                    )
                raise

            state = self._wait_for_job(
                job_name,
                job_uid=job_uid,
                deadline=started_at + timeout,
            )
            pod = self._pod_for_job(
                job_name,
                job_uid=job_uid,
                required=not state.timed_out,
            )
            if pod is None:
                stdout = ""
                stderr = ""
            else:
                pod_name = _metadata_name(pod)
                if not _valid_dns_subdomain(pod_name):
                    raise SandboxExecutionError("Kubernetes Job returned an invalid Pod name.")
                stdout = self._pod_log(
                    pod_name,
                    STDOUT_CONTAINER,
                    output_caps=output_caps,
                )
                stderr = self._pod_log(
                    pod_name,
                    STDERR_CONTAINER,
                    output_caps=output_caps,
                )
            if state.timed_out:
                timeout_message = f"kubernetes sandbox command timed out after {timeout} second(s)"
                return ExecutionResult(
                    returncode=SANDBOX_TIMEOUT_RETURN_CODE,
                    stdout=bounded(stdout, output_caps),
                    stderr=bounded(
                        "\n".join(part for part in [stderr.rstrip(), timeout_message] if part)
                        + "\n",
                        output_caps,
                    ),
                    timed_out=True,
                )
            if pod is None:
                raise SandboxExecutionError("Kubernetes Job completed without a Pod result.")
            returncode = _runner_exit_code(pod)
            _assert_exporters_succeeded(pod)
            return ExecutionResult(
                returncode=returncode,
                stdout=bounded(stdout, output_caps),
                stderr=bounded(stderr, output_caps),
                timed_out=False,
            )
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            if job_uid is not None:
                try:
                    self._delete_job(job_name, job_uid=job_uid)
                except Exception as cleanup_exc:
                    if primary_error is None:
                        raise
                    cleanup_detail = bounded(str(cleanup_exc), 256)
                    primary_error.add_note(
                        "Kubernetes sandbox UID-bound foreground cleanup also failed "
                        f"({type(cleanup_exc).__name__}: {cleanup_detail}); "
                        "the primary execution error "
                        "was preserved."
                    )

    def execute_batch(
        self,
        commands: Sequence[Sequence[str]],
        *,
        cwd: Path,
        source_cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> SandboxExecutionBatchResult:
        if not commands or len(commands) > 10:
            raise SandboxExecutionError(
                "Kubernetes sandbox batch must contain between 1 and 10 commands."
            )
        normalized_commands = [list(command) for command in commands]
        for command in normalized_commands:
            _validate_execution_request(
                command,
                timeout=timeout,
                output_caps=output_caps,
            )
        serialized_commands = json.dumps(
            normalized_commands,
            separators=(",", ":"),
        )
        total_timeout = timeout * len(normalized_commands) + self._setup_grace_seconds
        control_output_caps = min(
            MAX_SANDBOX_BATCH_CONTROL_CHARS,
            max(65_536, output_caps * len(normalized_commands) * 4),
        )
        completed = self._execute_control_command(
            [
                "python",
                SANDBOX_BATCH_RUNNER_PATH,
                f"{timeout:.6f}",
                str(output_caps),
                serialized_commands,
            ],
            cwd=cwd,
            source_cwd=source_cwd,
            env=env,
            timeout=total_timeout,
            output_caps=control_output_caps,
            max_output_caps=MAX_SANDBOX_BATCH_CONTROL_CHARS,
        )
        if completed.returncode != 0 or completed.timed_out:
            raise SandboxExecutionError("Kubernetes sandbox batch orchestration failed.")
        return decode_sandbox_execution_batch(
            completed.stdout,
            expected_count=len(normalized_commands),
            output_caps=output_caps,
        )

    def build_job_manifest(
        self,
        *,
        job_name: str,
        argv: Sequence[str],
        workspace_sub_path: str | None,
        env: Mapping[str, str],
        timeout: float,
        output_caps: int,
    ) -> dict[str, object]:
        labels = {
            SANDBOX_LABEL: "true",
            NETWORK_POLICY_LABEL: NETWORK_POLICY_DENY_VALUE,
        }
        runner_resources = {
            "requests": {
                "cpu": _cpu_quantity(self._cpus),
                "memory": f"{self._memory_mb}Mi",
            },
            "limits": {
                "cpu": _cpu_quantity(self._cpus),
                "memory": f"{self._memory_mb}Mi",
            },
        }
        exporter_resources = {
            "requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"},
        }
        source_mount: dict[str, object] = {
            "name": "source",
            "mountPath": SOURCE_MOUNT_PATH,
            "readOnly": True,
        }
        if workspace_sub_path is not None:
            source_mount["subPath"] = workspace_sub_path
        runner_mounts: list[dict[str, object]] = [
            source_mount,
            {"name": "workspace", "mountPath": self._workspace_mount_path},
            {"name": "results", "mountPath": RESULTS_MOUNT_PATH},
            {"name": "tmp", "mountPath": "/tmp"},
        ]
        exporter_mounts: list[dict[str, object]] = [
            {"name": "results", "mountPath": RESULTS_MOUNT_PATH},
            {"name": "tmp", "mountPath": "/tmp"},
        ]
        sanitized_env = sanitized_container_environment(env)
        if any(
            len(key) > 128 or len(value) > MAX_ENV_VALUE_CHARS
            for key, value in sanitized_env.items()
        ):
            raise SandboxExecutionError("Kubernetes sandbox environment exceeded the safety limit.")
        container_env = [
            {"name": key, "value": value} for key, value in sorted(sanitized_env.items())
        ]
        security_context = _container_security_context()
        result_size_mib = max(1, min(16, math.ceil(output_caps * 4 / (1024 * 1024))))
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": self._namespace,
                "labels": labels,
                "annotations": {PIDS_LIMIT_ANNOTATION: str(self._pids_limit)},
            },
            "spec": {
                "backoffLimit": 0,
                "completions": 1,
                "parallelism": 1,
                "suspend": False,
                "activeDeadlineSeconds": max(1, math.ceil(timeout)),
                "ttlSecondsAfterFinished": self._job_ttl_seconds,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "restartPolicy": "Never",
                        "automountServiceAccountToken": False,
                        "enableServiceLinks": False,
                        "hostIPC": False,
                        "hostNetwork": False,
                        "hostPID": False,
                        "shareProcessNamespace": False,
                        "terminationGracePeriodSeconds": max(
                            1, math.ceil(self._timeout_grace_seconds)
                        ),
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "fsGroup": 10001,
                            "fsGroupChangePolicy": "OnRootMismatch",
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "containers": [
                            {
                                "name": RUNNER_CONTAINER,
                                "image": self._image,
                                "imagePullPolicy": "IfNotPresent",
                                "command": ["python", SANDBOX_RUNNER_PATH],
                                "args": [
                                    str(self._pids_limit),
                                    str(MAX_SANDBOX_WORKSPACE_FILES),
                                    str(MAX_SANDBOX_WORKSPACE_BYTES),
                                    *list(argv),
                                ],
                                "workingDir": self._workspace_mount_path,
                                "env": container_env,
                                "resources": runner_resources,
                                "securityContext": security_context,
                                "volumeMounts": runner_mounts,
                                "stdin": False,
                                "tty": False,
                            },
                            _exporter_container(
                                name=STDOUT_CONTAINER,
                                source=f"{RESULTS_MOUNT_PATH}/stdout",
                                image=self._image,
                                mounts=exporter_mounts,
                                resources=exporter_resources,
                                security_context=security_context,
                            ),
                            _exporter_container(
                                name=STDERR_CONTAINER,
                                source=f"{RESULTS_MOUNT_PATH}/stderr",
                                image=self._image,
                                mounts=exporter_mounts,
                                resources=exporter_resources,
                                security_context=security_context,
                            ),
                        ],
                        "volumes": [
                            {
                                "name": "source",
                                "persistentVolumeClaim": {"claimName": self._pvc_name},
                            },
                            {
                                "name": "workspace",
                                "emptyDir": {
                                    "sizeLimit": f"{MAX_SANDBOX_WORKSPACE_BYTES // (1024 * 1024)}Mi"
                                },
                            },
                            {
                                "name": "results",
                                "emptyDir": {"sizeLimit": f"{result_size_mib}Mi"},
                            },
                            {
                                "name": "tmp",
                                "emptyDir": {"sizeLimit": "64Mi"},
                            },
                        ],
                    },
                },
            },
        }

    def _assert_default_deny_network_policy(
        self,
        timeout: float,
        *,
        job_name: str,
    ) -> None:
        policy_list = self._request_json(
            "GET",
            f"/apis/networking.k8s.io/v1/namespaces/{self._namespace}/networkpolicies",
            timeout=timeout,
            label="list NetworkPolicies",
        )
        raw_items = policy_list.get("items")
        if not isinstance(raw_items, list) or not all(
            isinstance(item, Mapping) for item in raw_items
        ):
            raise SandboxExecutionError("Kubernetes NetworkPolicy list returned invalid items.")
        policies = [cast(Mapping[str, object], item) for item in raw_items]
        named_policy = next(
            (policy for policy in policies if _metadata_name(policy) == self._network_policy_name),
            None,
        )
        if named_policy is None:
            raise SandboxExecutionError("Kubernetes sandbox default-deny NetworkPolicy is missing.")
        self._assert_named_default_deny_policy(named_policy)
        pod_labels = {
            SANDBOX_LABEL: "true",
            NETWORK_POLICY_LABEL: NETWORK_POLICY_DENY_VALUE,
            JOB_NAME_LABEL: job_name,
        }
        for policy in policies:
            spec = _mapping(policy.get("spec"), "NetworkPolicy spec")
            egress = spec.get("egress", [])
            if not isinstance(egress, list):
                raise SandboxExecutionError(
                    "Kubernetes NetworkPolicy returned invalid egress rules."
                )
            if not egress:
                continue
            selector = _mapping(
                spec.get("podSelector"),
                "NetworkPolicy podSelector",
            )
            if _selector_may_match(pod_labels, selector):
                raise SandboxExecutionError(
                    "A Kubernetes NetworkPolicy selecting sandbox Jobs permits egress."
                )

    def _assert_named_default_deny_policy(
        self,
        policy: Mapping[str, object],
    ) -> None:
        spec = _mapping(policy.get("spec"), "NetworkPolicy spec")
        pod_selector = _mapping(
            spec.get("podSelector"),
            "NetworkPolicy podSelector",
        )
        match_labels = _mapping(
            pod_selector.get("matchLabels"),
            "NetworkPolicy podSelector.matchLabels",
        )
        match_expressions = pod_selector.get("matchExpressions", [])
        policy_types = spec.get("policyTypes")
        egress = spec.get("egress", [])
        if match_labels != {
            NETWORK_POLICY_LABEL: NETWORK_POLICY_DENY_VALUE
        } or match_expressions not in (None, []):
            raise SandboxExecutionError(
                "Kubernetes sandbox NetworkPolicy does not select deny-egress Jobs."
            )
        if not isinstance(policy_types, list) or "Egress" not in policy_types:
            raise SandboxExecutionError(
                "Kubernetes sandbox NetworkPolicy must include Egress policy type."
            )
        if not isinstance(egress, list) or egress:
            raise SandboxExecutionError("Kubernetes sandbox NetworkPolicy must deny all egress.")

    def _wait_for_job(
        self,
        job_name: str,
        *,
        job_uid: str,
        deadline: float,
    ) -> KubernetesJobState:
        path = f"{self._jobs_path()}/{job_name}"
        while True:
            now = self._monotonic()
            if now >= deadline:
                return KubernetesJobState(terminal=False, timed_out=True)
            job = self._request_json(
                "GET",
                path,
                timeout=min(self._api_request_timeout_seconds, deadline - now),
                label="poll Job",
            )
            observed_uid = _validated_managed_job_identity(
                job,
                expected_name=job_name,
                expected_namespace=self._namespace,
                expected_pids_limit=self._pids_limit,
                label="polled Job",
            )
            if observed_uid != job_uid:
                raise SandboxExecutionError("Kubernetes Job UID changed during sandbox execution.")
            state = _job_state(job)
            if state.terminal:
                return state
            now = self._monotonic()
            if now >= deadline:
                return KubernetesJobState(terminal=False, timed_out=True)
            self._sleep(min(self._poll_interval_seconds, deadline - now))

    def _pod_for_job(
        self,
        job_name: str,
        *,
        job_uid: str,
        required: bool,
    ) -> Mapping[str, object] | None:
        pod_list = self._request_json(
            "GET",
            f"/api/v1/namespaces/{self._namespace}/pods",
            query={"labelSelector": f"{JOB_NAME_LABEL}={job_name}"},
            timeout=self._api_request_timeout_seconds,
            label="list Job Pods",
        )
        items = pod_list.get("items")
        if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
            raise SandboxExecutionError("Kubernetes Pod list returned an invalid items collection.")
        if not items:
            if required:
                raise SandboxExecutionError("Kubernetes Job completed without a Pod.")
            return None
        if len(items) != 1:
            raise SandboxExecutionError("Kubernetes Job produced an unexpected number of Pods.")
        pod = cast(Mapping[str, object], items[0])
        _validate_job_pod_identity(
            pod,
            job_name=job_name,
            job_uid=job_uid,
            expected_namespace=self._namespace,
        )
        return pod

    def _pod_log(
        self,
        pod_name: str,
        container_name: str,
        *,
        output_caps: int,
    ) -> str:
        log_limit_bytes = min(
            MAX_KUBERNETES_RESPONSE_BYTES,
            max(1024, output_caps * 4),
        )
        body = self._transport.request(
            "GET",
            f"/api/v1/namespaces/{self._namespace}/pods/{pod_name}/log",
            query={
                "container": container_name,
                "limitBytes": log_limit_bytes,
            },
            timeout=self._api_request_timeout_seconds,
        )
        return body.decode("utf-8", errors="replace")

    def _reconcile_ambiguous_job_creation(
        self,
        job_name: str,
        *,
        timeout: float,
    ) -> str | None:
        deadline = self._monotonic() + timeout
        job_path = f"{self._jobs_path()}/{job_name}"
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return None
            try:
                job = self._request_json(
                    "GET",
                    job_path,
                    timeout=min(self._api_request_timeout_seconds, remaining),
                    label="reconcile Job creation",
                )
            except KubernetesApiError as exc:
                if exc.status_code is not None and exc.status_code != 404 and exc.status_code < 500:
                    raise
            except SandboxExecutionError:
                pass
            else:
                return _validated_managed_job_identity(
                    job,
                    expected_name=job_name,
                    expected_namespace=self._namespace,
                    expected_pids_limit=self._pids_limit,
                    label="reconciled Job",
                )
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return None
            self._sleep(min(self._poll_interval_seconds, remaining))
            continue

    def _delete_job(self, job_name: str, *, job_uid: str) -> None:
        cleanup_deadline = self._monotonic() + min(
            self._cleanup_grace_seconds,
            MAX_CLEANUP_WAIT_SECONDS,
        )
        delete_payload = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "gracePeriodSeconds": 0,
            "propagationPolicy": "Foreground",
            "preconditions": {"uid": job_uid},
        }
        while True:
            try:
                self._transport.request(
                    "DELETE",
                    f"{self._jobs_path()}/{job_name}",
                    payload=delete_payload,
                    timeout=min(
                        self._api_request_timeout_seconds,
                        self._remaining_cleanup_time(cleanup_deadline),
                    ),
                )
            except KubernetesApiError as exc:
                if exc.status_code in {404, 409}:
                    break
                if exc.status_code is not None and exc.status_code < 500:
                    raise
                remaining = self._remaining_cleanup_time(cleanup_deadline)
                self._sleep(min(self._poll_interval_seconds, remaining))
                continue
            break
        self._wait_for_job_deletion(
            job_name,
            job_uid=job_uid,
            deadline=cleanup_deadline,
        )

    def _wait_for_job_deletion(
        self,
        job_name: str,
        *,
        job_uid: str,
        deadline: float,
    ) -> None:
        job_path = f"{self._jobs_path()}/{job_name}"
        while True:
            target_job_absent = False
            try:
                job = self._request_json(
                    "GET",
                    job_path,
                    timeout=min(
                        self._api_request_timeout_seconds,
                        self._remaining_cleanup_time(deadline),
                    ),
                    label="confirm Job deletion",
                )
            except KubernetesApiError as exc:
                if exc.status_code != 404:
                    raise
                target_job_absent = True
            else:
                observed_uid = _validated_managed_job_identity(
                    job,
                    expected_name=job_name,
                    expected_namespace=self._namespace,
                    expected_pids_limit=self._pids_limit,
                    label="cleanup Job",
                )
                target_job_absent = observed_uid != job_uid

            if target_job_absent and not self._job_owned_pods_remain(
                job_name,
                job_uid=job_uid,
                deadline=deadline,
            ):
                return

            remaining = self._remaining_cleanup_time(deadline)
            self._sleep(min(self._poll_interval_seconds, remaining))

    def _job_owned_pods_remain(
        self,
        job_name: str,
        *,
        job_uid: str,
        deadline: float,
    ) -> bool:
        pod_list = self._request_json(
            "GET",
            f"/api/v1/namespaces/{self._namespace}/pods",
            query={"labelSelector": f"{JOB_NAME_LABEL}={job_name}"},
            timeout=min(
                self._api_request_timeout_seconds,
                self._remaining_cleanup_time(deadline),
            ),
            label="confirm Job Pod deletion",
        )
        items = pod_list.get("items")
        if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
            raise SandboxExecutionError("Kubernetes cleanup Pod list returned invalid items.")
        return any(
            _pod_is_owned_by_job_uid(
                cast(Mapping[str, object], item),
                job_name=job_name,
                job_uid=job_uid,
                expected_namespace=self._namespace,
            )
            for item in items
        )

    def _remaining_cleanup_time(self, deadline: float) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise SandboxExecutionError(
                "Kubernetes sandbox foreground cleanup confirmation timed out."
            )
        return remaining

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str | int] | None = None,
        payload: Mapping[str, object] | None = None,
        timeout: float,
        label: str,
    ) -> Mapping[str, object]:
        body = self._transport.request(
            method,
            path,
            query=query,
            payload=payload,
            timeout=timeout,
        )
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SandboxExecutionError(
                f"Kubernetes API returned invalid JSON for {label}."
            ) from None
        if not isinstance(decoded, Mapping):
            raise SandboxExecutionError(f"Kubernetes API returned a non-object for {label}.")
        return decoded

    def _jobs_path(self) -> str:
        return f"/apis/batch/v1/namespaces/{self._namespace}/jobs"

    def _workspace_sub_path(self, cwd: Path) -> str | None:
        resolved_cwd = cwd.resolve()
        if not resolved_cwd.is_dir():
            raise SandboxExecutionError("Kubernetes sandbox cwd must be an existing directory.")
        try:
            relative = resolved_cwd.relative_to(self._workspace_root)
        except ValueError as exc:
            raise SandboxExecutionError(
                "Kubernetes sandbox cwd escapes the configured workspace root."
            ) from exc
        if relative == Path("."):
            raise SandboxExecutionError(
                "Kubernetes sandbox cwd must be a child repository so the PVC subPath is mandatory."
            )
        if any(
            part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part
            for part in relative.parts
        ):
            raise SandboxExecutionError("Kubernetes sandbox cwd produced an invalid PVC subPath.")
        sub_path = str(PurePosixPath(*relative.parts))
        if not sub_path or sub_path.startswith("/") or ".." in PurePosixPath(sub_path).parts:
            raise SandboxExecutionError("Kubernetes sandbox cwd produced an unsafe PVC subPath.")
        return sub_path

    def _new_job_name(self) -> str:
        name = self._name_factory()
        if (
            len(name) > MAX_JOB_NAME_LENGTH
            or KUBERNETES_NAME_RE.fullmatch(name) is None
            or not name.startswith("hallu-sandbox-")
        ):
            raise SandboxExecutionError(
                "Kubernetes sandbox Job name factory returned an invalid name."
            )
        return name


def _exporter_container(
    *,
    name: str,
    source: str,
    image: str,
    mounts: list[dict[str, object]],
    resources: Mapping[str, object],
    security_context: Mapping[str, object],
) -> dict[str, object]:
    return {
        "name": name,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", SANDBOX_STREAM_EXPORTER_PATH],
        "args": [source, f"{RESULTS_MOUNT_PATH}/done"],
        "workingDir": "/tmp",
        "env": [
            {"name": "HOME", "value": "/tmp"},
            {"name": "PYTHONUNBUFFERED", "value": "1"},
        ],
        "resources": dict(resources),
        "securityContext": dict(security_context),
        "volumeMounts": mounts,
        "stdin": False,
        "tty": False,
    }


def _container_security_context() -> dict[str, object]:
    return {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _job_state(job: Mapping[str, object]) -> KubernetesJobState:
    status = job.get("status", {})
    if not isinstance(status, Mapping):
        raise SandboxExecutionError("Kubernetes Job returned an invalid status.")
    conditions = status.get("conditions", [])
    if not isinstance(conditions, list):
        raise SandboxExecutionError("Kubernetes Job returned invalid conditions.")
    for condition in conditions:
        if not isinstance(condition, Mapping) or condition.get("status") != "True":
            continue
        condition_type = condition.get("type")
        if condition_type == "Complete":
            return KubernetesJobState(terminal=True, timed_out=False)
        if condition_type == "Failed":
            return KubernetesJobState(
                terminal=True,
                timed_out=condition.get("reason") == "DeadlineExceeded",
            )
    if _positive_status_count(status.get("succeeded")):
        return KubernetesJobState(terminal=True, timed_out=False)
    if _positive_status_count(status.get("failed")):
        return KubernetesJobState(terminal=True, timed_out=False)
    return KubernetesJobState(terminal=False, timed_out=False)


def _positive_status_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _runner_exit_code(pod: Mapping[str, object]) -> int:
    statuses = _container_statuses(pod)
    return _terminated_exit_code(statuses, RUNNER_CONTAINER)


def _assert_exporters_succeeded(pod: Mapping[str, object]) -> None:
    statuses = _container_statuses(pod)
    for container_name in (STDOUT_CONTAINER, STDERR_CONTAINER):
        if _terminated_exit_code(statuses, container_name) != 0:
            raise SandboxExecutionError(f"Kubernetes sandbox {container_name} exporter failed.")


def _container_statuses(
    pod: Mapping[str, object],
) -> Mapping[str, Mapping[str, object]]:
    status = _mapping(pod.get("status"), "Pod status")
    raw_statuses = status.get("containerStatuses")
    if not isinstance(raw_statuses, list):
        raise SandboxExecutionError("Kubernetes Pod returned invalid container statuses.")
    statuses: dict[str, Mapping[str, object]] = {}
    for item in raw_statuses:
        if not isinstance(item, Mapping):
            raise SandboxExecutionError("Kubernetes Pod returned an invalid container status.")
        name = item.get("name")
        if not isinstance(name, str):
            raise SandboxExecutionError("Kubernetes Pod container status is missing a name.")
        statuses[name] = cast(Mapping[str, object], item)
    return statuses


def _terminated_exit_code(
    statuses: Mapping[str, Mapping[str, object]],
    container_name: str,
) -> int:
    container_status = statuses.get(container_name)
    if container_status is None:
        raise SandboxExecutionError(f"Kubernetes Pod is missing {container_name} container status.")
    state = _mapping(container_status.get("state"), f"{container_name} state")
    terminated = _mapping(
        state.get("terminated"),
        f"{container_name} terminated state",
    )
    exit_code = terminated.get("exitCode")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise SandboxExecutionError(
            f"Kubernetes Pod returned an invalid {container_name} exit code."
        )
    return exit_code


def _metadata_name(resource: Mapping[str, object]) -> str:
    metadata = _mapping(resource.get("metadata"), "resource metadata")
    name = metadata.get("name")
    if not isinstance(name, str) or not name:
        raise SandboxExecutionError("Kubernetes resource metadata is missing a name.")
    return name


def _validated_resource_identity(
    resource: Mapping[str, object],
    *,
    expected_name: str,
    expected_namespace: str,
    label: str,
) -> str:
    metadata = _mapping(resource.get("metadata"), f"{label} metadata")
    if metadata.get("name") != expected_name:
        raise SandboxExecutionError(f"Kubernetes API returned an unexpected {label} name.")
    if metadata.get("namespace") != expected_namespace:
        raise SandboxExecutionError(f"Kubernetes API returned an unexpected {label} namespace.")
    uid = metadata.get("uid")
    if not isinstance(uid, str) or KUBERNETES_UID_RE.fullmatch(uid) is None:
        raise SandboxExecutionError(f"Kubernetes API returned an invalid {label} UID.")
    return uid


def _validated_managed_job_identity(
    resource: Mapping[str, object],
    *,
    expected_name: str,
    expected_namespace: str,
    expected_pids_limit: int,
    label: str,
) -> str:
    uid = _validated_resource_identity(
        resource,
        expected_name=expected_name,
        expected_namespace=expected_namespace,
        label=label,
    )
    metadata = _mapping(resource.get("metadata"), f"{label} metadata")
    labels = _mapping(metadata.get("labels"), f"{label} metadata labels")
    if (
        labels.get(SANDBOX_LABEL) != "true"
        or labels.get(NETWORK_POLICY_LABEL) != NETWORK_POLICY_DENY_VALUE
    ):
        raise SandboxExecutionError(
            f"Kubernetes API returned an unexpected {label} sandbox identity."
        )
    annotations = _mapping(
        metadata.get("annotations"),
        f"{label} metadata annotations",
    )
    if annotations.get(PIDS_LIMIT_ANNOTATION) != str(expected_pids_limit):
        raise SandboxExecutionError(
            f"Kubernetes API returned an unexpected {label} execution identity."
        )
    return uid


def _pod_is_owned_by_job_uid(
    pod: Mapping[str, object],
    *,
    job_name: str,
    job_uid: str,
    expected_namespace: str,
) -> bool:
    metadata = _mapping(pod.get("metadata"), "cleanup Pod metadata")
    if metadata.get("namespace") != expected_namespace:
        raise SandboxExecutionError("Kubernetes cleanup Pod belongs to an unexpected namespace.")
    owner_references = metadata.get("ownerReferences", [])
    if not isinstance(owner_references, list) or not all(
        isinstance(owner, Mapping) for owner in owner_references
    ):
        raise SandboxExecutionError("Kubernetes cleanup Pod returned invalid owner references.")
    for raw_owner in owner_references:
        owner = cast(Mapping[str, object], raw_owner)
        if owner.get("uid") != job_uid:
            continue
        if (
            owner.get("apiVersion") != "batch/v1"
            or owner.get("kind") != "Job"
            or owner.get("name") != job_name
            or owner.get("controller") is not True
        ):
            raise SandboxExecutionError("Kubernetes cleanup Pod owner identity is invalid.")
        return True
    return False


def _validate_job_pod_identity(
    pod: Mapping[str, object],
    *,
    job_name: str,
    job_uid: str,
    expected_namespace: str,
) -> None:
    metadata = _mapping(pod.get("metadata"), "Job Pod metadata")
    pod_name = metadata.get("name")
    if not isinstance(pod_name, str) or not _valid_dns_subdomain(pod_name):
        raise SandboxExecutionError("Kubernetes Job returned an invalid Pod name.")
    if metadata.get("namespace") != expected_namespace:
        raise SandboxExecutionError("Kubernetes Job Pod belongs to an unexpected namespace.")
    pod_uid = metadata.get("uid")
    if not isinstance(pod_uid, str) or KUBERNETES_UID_RE.fullmatch(pod_uid) is None:
        raise SandboxExecutionError("Kubernetes Job Pod has an invalid UID.")

    labels = _mapping(metadata.get("labels"), "Job Pod labels")
    if labels.get(JOB_NAME_LABEL) != job_name or labels.get("job-name") != job_name:
        raise SandboxExecutionError("Kubernetes Job Pod labels do not match the created Job.")
    owner_references = metadata.get("ownerReferences")
    if (
        not isinstance(owner_references, list)
        or len(owner_references) != 1
        or not isinstance(owner_references[0], Mapping)
    ):
        raise SandboxExecutionError(
            "Kubernetes Job Pod must have exactly one controller owner reference."
        )
    owner = cast(Mapping[str, object], owner_references[0])
    if (
        owner.get("apiVersion") != "batch/v1"
        or owner.get("kind") != "Job"
        or owner.get("name") != job_name
        or owner.get("uid") != job_uid
        or owner.get("controller") is not True
    ):
        raise SandboxExecutionError(
            "Kubernetes Job Pod owner identity does not match the created Job."
        )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SandboxExecutionError(f"Kubernetes {label} must be an object.")
    return cast(Mapping[str, object], value)


def _selector_may_match(
    labels: Mapping[str, str],
    selector: Mapping[str, object],
) -> bool:
    match_labels = selector.get("matchLabels", {})
    if not isinstance(match_labels, Mapping):
        raise SandboxExecutionError(
            "Kubernetes NetworkPolicy selector matchLabels must be an object."
        )
    for key, value in match_labels.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise SandboxExecutionError("Kubernetes NetworkPolicy selector labels must be strings.")
        if labels.get(key) != value:
            return False
    expressions = selector.get("matchExpressions", [])
    if not isinstance(expressions, list):
        raise SandboxExecutionError(
            "Kubernetes NetworkPolicy selector matchExpressions must be a list."
        )
    for expression in expressions:
        if not isinstance(expression, Mapping):
            raise SandboxExecutionError(
                "Kubernetes NetworkPolicy selector expression must be an object."
            )
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values", [])
        if not isinstance(key, str) or operator not in {
            "In",
            "NotIn",
            "Exists",
            "DoesNotExist",
        }:
            raise SandboxExecutionError(
                "Kubernetes NetworkPolicy selector expression is unsupported."
            )
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise SandboxExecutionError("Kubernetes NetworkPolicy selector values must be strings.")
        label_value = labels.get(key)
        if operator == "In" and (label_value is None or label_value not in values):
            return False
        if operator == "NotIn" and label_value in values:
            return False
        if operator == "Exists" and label_value is None:
            return False
        if operator == "DoesNotExist" and label_value is not None:
            return False
    return True


def _validate_backend_configuration(
    *,
    image: str,
    namespace: str,
    pvc_name: str,
    workspace_root: Path,
    workspace_mount_path: str,
    network_policy_name: str,
    memory_mb: int,
    cpus: float,
    pids_limit: int,
    poll_interval_seconds: float,
    job_ttl_seconds: int,
    api_request_timeout_seconds: float,
    setup_grace_seconds: float,
    timeout_grace_seconds: float,
    cleanup_grace_seconds: float,
) -> None:
    errors: list[str] = []
    if not _valid_image_reference(image):
        errors.append("Kubernetes sandbox image must be a non-latest image reference.")
    if not _valid_dns_label(namespace, max_length=63):
        errors.append("Kubernetes sandbox namespace must be a valid DNS label.")
    if not _valid_dns_subdomain(pvc_name):
        errors.append("Kubernetes sandbox PVC name must be a valid DNS subdomain.")
    if not _valid_dns_subdomain(network_policy_name):
        errors.append("Kubernetes sandbox NetworkPolicy name must be a valid DNS subdomain.")
    if not workspace_root.is_absolute() or not workspace_root.is_dir():
        errors.append("Kubernetes sandbox workspace root must be an existing absolute directory.")
    if not _valid_mount_path(workspace_mount_path):
        errors.append(
            "Kubernetes sandbox workspace mount must be an absolute canonical non-root path."
        )
    for integer_value, label in (
        (memory_mb, "memory_mb"),
        (pids_limit, "pids_limit"),
        (job_ttl_seconds, "job_ttl_seconds"),
    ):
        if integer_value <= 0:
            errors.append(f"Kubernetes sandbox {label} must be positive.")
    for float_value, label in (
        (cpus, "cpus"),
        (poll_interval_seconds, "poll_interval_seconds"),
        (api_request_timeout_seconds, "api_request_timeout_seconds"),
        (setup_grace_seconds, "setup_grace_seconds"),
        (timeout_grace_seconds, "timeout_grace_seconds"),
        (cleanup_grace_seconds, "cleanup_grace_seconds"),
    ):
        if float_value <= 0 or not math.isfinite(float_value):
            errors.append(f"Kubernetes sandbox {label} must be finite and positive.")
    if not 15 <= cleanup_grace_seconds <= MAX_CLEANUP_WAIT_SECONDS:
        errors.append(
            "Kubernetes sandbox cleanup_grace_seconds must be at least 15 and at most 30."
        )
    if errors:
        raise SandboxExecutionConfigurationError("\n".join(errors))


def _validate_execution_request(
    argv: Sequence[str],
    *,
    timeout: float,
    output_caps: int,
    max_output_caps: int = MAX_SANDBOX_OUTPUT_CHARS,
) -> None:
    if (
        not argv
        or len(argv) > MAX_COMMAND_ARGUMENTS
        or any(not isinstance(part, str) or not part or "\x00" in part for part in argv)
    ):
        raise SandboxExecutionError(
            "Kubernetes sandbox argv must contain non-empty NUL-free strings."
        )
    if sum(len(part.encode("utf-8")) for part in argv) > MAX_COMMAND_BYTES:
        raise SandboxExecutionError("Kubernetes sandbox argv exceeded the safety limit.")
    if timeout <= 0 or not math.isfinite(timeout):
        raise SandboxExecutionError("Kubernetes sandbox timeout must be finite and positive.")
    if not 0 < output_caps <= max_output_caps:
        raise SandboxExecutionError("Kubernetes sandbox output cap must be positive and bounded.")


def _valid_dns_label(value: str, *, max_length: int) -> bool:
    return (
        value == value.strip()
        and 0 < len(value) <= max_length
        and KUBERNETES_NAME_RE.fullmatch(value) is not None
    )


def _valid_dns_subdomain(value: str) -> bool:
    if (
        value != value.strip()
        or not 0 < len(value) <= 253
        or KUBERNETES_SUBDOMAIN_RE.fullmatch(value) is None
    ):
        return False
    return all(_valid_dns_label(part, max_length=63) for part in value.split("."))


def _valid_mount_path(value: str) -> bool:
    if value != value.strip() or not value.startswith("/") or value == "/":
        return False
    path = PurePosixPath(value)
    reserved_roots = (
        PurePosixPath("/tmp"),
        PurePosixPath(RESULTS_MOUNT_PATH),
        PurePosixPath("/var/run/secrets"),
    )
    return str(path) == value and not any(
        path == root or root in path.parents for root in reserved_roots
    )


def _valid_image_reference(value: str) -> bool:
    normalized = value.strip()
    image_name = normalized.rsplit("/", 1)[-1]
    has_tag = ":" in image_name and not image_name.endswith(":")
    has_digest = re.search(r"@sha256:[0-9a-fA-F]{64}$", normalized) is not None
    return (
        normalized == value
        and bool(normalized)
        and not normalized.endswith(":latest")
        and not any(character.isspace() for character in normalized)
        and (has_tag or has_digest)
    )


def _cpu_quantity(cpus: float) -> str:
    if cpus.is_integer():
        return str(int(cpus))
    return f"{math.ceil(cpus * 1000)}m"


def _in_cluster_api_server(env: Mapping[str, str]) -> str:
    host = env.get("KUBERNETES_SERVICE_HOST", "").strip()
    raw_port = env.get("KUBERNETES_SERVICE_PORT_HTTPS", "443").strip()
    if not _valid_api_host(host):
        raise SandboxExecutionConfigurationError(
            "KUBERNETES_SERVICE_HOST is unavailable or invalid."
        )
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise SandboxExecutionConfigurationError(
            "KUBERNETES_SERVICE_PORT_HTTPS must be an integer."
        ) from exc
    if port < 1 or port > 65535:
        raise SandboxExecutionConfigurationError(
            "KUBERNETES_SERVICE_PORT_HTTPS must be between 1 and 65535."
        )
    normalized_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"https://{normalized_host}:{port}"


def _valid_api_host(host: str) -> bool:
    if not host or any(character.isspace() for character in host):
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ipaddress.AddressValueError:
            return False
        return True
    return (
        len(host) <= 253
        and re.fullmatch(r"[A-Za-z0-9.-]+", host) is not None
        and all(
            0 < len(label) <= 63 and label[0].isalnum() and label[-1].isalnum()
            for label in host.split(".")
        )
    )


def _ssl_context_from_ca(ca_path: str) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_path)


def _read_service_account_token(token_path: Path) -> str:
    try:
        credential = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SandboxExecutionConfigurationError(
            "Kubernetes ServiceAccount token is unavailable."
        ) from exc
    _validate_service_account_token(credential)
    return credential


def _validate_service_account_token(token: str) -> None:
    normalized = token.strip()
    if not normalized or any(character.isspace() for character in normalized):
        raise SandboxExecutionConfigurationError(
            "Kubernetes ServiceAccount token must not be empty or contain whitespace."
        )


def _fixed_token_loader(token: str) -> Callable[[], str]:
    def load_token() -> str:
        return token

    return load_token


def _safe_api_path(path: str) -> bool:
    return (
        path.startswith("/")
        and not path.startswith("//")
        and "://" not in path
        and ".." not in PurePosixPath(path).parts
    )
