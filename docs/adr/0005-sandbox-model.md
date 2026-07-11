# ADR 0005: Sandbox Model

## Status

Accepted for foundation.

## Context

Code agents can hallucinate about files, functions, tests, builds, and diffs. Text-only verification is not enough.

## Decision

Sandbox defaults:

- Network denied.
- Filesystem scoped to configured workspace.
- Commands are allowlisted.
- stdout, stderr, exit codes, and artifacts are captured.
- Claims about repo/test/build success require `SandboxRun` or equivalent deterministic evidence.

Runtime model:

- `SandboxRunner` keeps command parsing, destructive/network preflight regex
  checks, no-follow static inspection, and in-memory inspection evidence. Git runs
  through a baked inspector in the selected execution backend, never in the API
  process; production mounts the repository read-only for that inspector.
- Command execution goes through `SandboxExecutionBackend`.
- Local development defaults to `DockerContainerBackend`. A host subprocess is
  not an isolation boundary and is rejected in every environment.
- `KubernetesJobBackend` is selected with
  `HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes`; the Helm production default uses
  this backend and never mounts the Docker socket.
- Production and staging accept only the tenant-bound `kubernetes` backend.
  `docker` remains local/CI-only and fails configuration before backend
  construction in production-like environments.
- `network_policy=allowlisted` fails closed until the request contract carries
  an exact destination allowlist and a valid approval grant. Regex checks are
  defense in depth; they are never the network isolation boundary.
- Docker execution uses argv lists only and pins isolation flags:
  `--rm`, `--network=none`, `--read-only`, `--tmpfs /tmp`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`,
  `--memory`, `--cpus`, `--user 10001`, a read-only source bind at
  `/hallu-source`, a distinct bounded temporary working copy at `/workspace`,
  and `--workdir /workspace`. The working copy is deleted after every
  `SandboxRun`; the Git inspector observes only that disposable copy. The source tree
  is fingerprinted before and after the run and is never an artifact sink.
- Batch control results use the internal `sandbox_execution_batch.v3` envelope
  with independently validated pre- and post-execution content fingerprints.
  Normal build/test commands may change their disposable copy, but Git
  inspection is accepted only when source, pre, and post fingerprints are
  identical and no artifact was emitted. Repository-local executable Git
  configuration (`include*`, filters, external diff commands, and textconv) is
  rejected before `status` or `diff`; system/global config, hooks, replacement
  objects, attributes overrides, submodule recursion, and file-mode noise are
  disabled. Fingerprints and artifact signatures stream file contents instead
  of materializing the bounded workspace in memory.
- The sandbox image is `infra/docker/sandbox.Dockerfile`: digest-pinned Python
  3.12 Alpine and Node LTS stages, hash-locked Python wheels, a checksum- and
  integrity-verified npm archive, pinned Git, UID 10001 non-root, and immutable
  baked runner/exporter/Git-inspector entrypoints.
- Kubernetes execution uses a digest-pinned image, a tenant-scoped source PVC
  mounted read-only at `/hallu-source`, a bounded `emptyDir` working copy at
  `/workspace`, a mandatory repository `subPath`, exact RBAC in a dedicated sandbox namespace,
  deny-all ingress/egress, and a fail-closed ValidatingAdmissionPolicy tied to
  the API ServiceAccount and sandbox namespace. The admission layer prevents
  `jobs.create` from becoming a privileged Pod or Secret/PVC-root escape.
- The sandbox Role still needs namespace-wide Job lifecycle, Pod list/log, and
  NetworkPolicy list verbs because native RBAC cannot label-scope those dynamic
  objects. This residual is confined to the one-tenant sandbox namespace; the
  API identity has no workload RBAC in the application namespace. Object-level
  reduction would require a dedicated controller/result channel.

## Consequences

- Sandbox checks may be slower than text validation but are required for correctness.
- Docker startup cost may require tuning `HALLU_DEFENSE_MAX_COMMAND_SECONDS` and
  `HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS` for local/CI validation.
- Kubernetes API pods never receive `/var/run/docker.sock`; Docker is not an
  accepted production/staging sandbox boundary.
- Docker live smoke remains opt-in locally and runs in the live workflow.
- Inspection evidence uses `sandbox://inspection` and remains in the API
  response; no `reports/sandbox-inspection.json` is written into source.
- The kind/Helm smoke uses a digest-pinned Kubernetes 1.36.1 node with Kind's
  built-in kindnet provider, exercises the authenticated endpoint, proves ten
  admission rejections and real egress failure, and verifies timeout cleanup
  with no residual Jobs.
