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
  `--rm`, `--network=none`, `--read-only`,
  `--tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777`,
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
  configuration (`include*`, filters, external diff commands, textconv,
  color, no-prefix/mnemonic-prefix output, pagers, and other `diff.*`
  directives) is rejected before `status` or `diff`. Index flags that can hide
  changes (`assume-unchanged`, `skip-worktree`, or an `FSMN` fsmonitor
  extension) and unmerged stages are rejected. The inspector uses a bounded
  private copy of the index and reconstructs its entries through
  `update-index --index-info`, leaving stat fields zero so a same-size change
  with a restored mtime cannot be accepted as racy-clean. Git never refreshes
  the source index, and repeated-inspection tests compare every source `.git`
  byte and an aggregate hash. Repository and nested attributes are queried for every tracked path
  from a NUL-delimited index inventory before any status/diff is trusted;
  `-diff`, `binary`, diff drivers, filters, `ident`, legacy `crlf`, EOL or
  encoding transforms, and equivalent specified attributes fail closed.
  System/global config, hooks, replacement objects, command-line attributes
  overrides, submodule recursion, and file-mode noise are disabled.
- Git evidence is generated with a canonical patch contract:
  `--no-color`, fixed `--src-prefix=a/` and `--dst-prefix=b/`, `--text`, no
  external diff/textconv, `--full-index`, pinned case matching, and
  NUL-delimited file inventories. Patch paths must
  correspond exactly to that inventory, so spaces and header-like filenames
  cannot reattribute changed ranges. The result records a bounded sorted
  configuration-key inventory without values even when a repository guard
  rejects the input, plus detected index flags and content fingerprints for both the workspace
  and Git control files before and after inspection. Any inspector/guard error
  or drift preserves diagnostics but empties all diff files, lines, ranges and
  symbols, so downstream claim verification cannot consume tainted evidence.
- Before the first Git subprocess, a bounded no-follow preflight rejects
  gitlinks/submodules in either HEAD or the index, worktree or indexed
  case-variant `.gitmodules`, missing-index HEAD hazards, `.git/modules`,
  submodule config, nested `.git` directories or gitfiles anywhere in the
  workspace (including ignored trees), alternate/http-alternate object stores,
  effective `.git/info/exclude`, and `core.excludesFile` or
  `core.attributesFile`. Static bounded config parsing also rejects BOM-prefixed
  files and `include`/`includeIf` before Git can load them. The index is parsed directly under a byte/entry cap;
  no status/diff command can run first and hide these control surfaces.
- Workspace validation permits at most 50,000 regular files, 512 MiB of total
  file content, 75,000 combined file/directory paths, 4,096 UTF-8 bytes in one
  relative path, and 64 MiB of aggregate relative-path bytes. It accepts a
  zero-byte file even when it appears exactly at the content boundary; exact
  limits pass and the first byte/path beyond them fails. API-retained output is
  capped at 100,000 characters per stream. Directory enumeration, copies,
  fingerprints, artifact hashes, and subprocess output capture are bounded and
  streaming; opened-file identity is checked around reads and copies. POSIX
  mode bits are deliberately normalized across Windows host/Linux bind mounts,
  while direct workspace executable paths are rejected by the command allowlist.
  Windows path creation time is never compared with descriptor write/change
  time across different APIs; size/mode/identity remain checked at open and
  size/mode/mtime/ctime are compared only before/after on the same descriptor.
- The Linux batch runner becomes a child subreaper and terminates/reaps bounded
  process-tree descendants, including a grandchild that starts a new session,
  before artifact capture and the post-execution fingerprint.
- Host-side Docker and Git CLI capture starts each Windows process suspended,
  assigns it to a kill-on-close Job Object, and only then resumes it. POSIX uses
  a new process group. Success and timeout paths terminate descendants, join
  bounded pipe-drain threads, capture thread read/close failures, write Git
  stdin from a bounded cleanup-owned thread, and propagate assignment or
  termination errors instead of accepting partial cleanup.
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
- Kubernetes Job cleanup is tied to the UID returned by a validated managed
  Job. Ambiguous transport, invalid-JSON and invalid-shape create responses are
  reconciled with bounded polling before deletion; cleanup uses
  `deleteOptions.preconditions.uid`, `propagationPolicy=Foreground`, and waits
  for the old Job to return `404` and for Pods owned by that UID to disappear.
  A same-name replacement is never deleted. Production tenant isolation still
  requires one sandbox namespace, release, ServiceAccount, and PVC boundary per
  tenant; names and labels are defense in depth, not cross-tenant authorization.
  Foreground Job/owned-Pod reconciliation uses the Kubernetes-specific
  `HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS`, default 20 seconds
  and valid only from 15 through 30 seconds. Docker's default two-second
  timeout grace remains the Pod termination setting and is not the cleanup
  deadline. When execution and cleanup both fail, the primary exception is
  preserved with a bounded cleanup type/message note.

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
  with no residual Jobs. Front D must extend success and timeout assertions to
  prove that no Pod owned by either sandbox Job UID remains.
