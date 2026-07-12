# Kubernetes sandbox Jobs

The `kubernetes` sandbox backend creates one namespaced `batch/v1` Job per
validated `SandboxRun` through the in-cluster HTTPS API. All commands execute
sequentially in that Job and share one ephemeral working copy. It is the Helm
production default and the chart requires Kubernetes 1.34 or newer. The chart creates a dedicated API
ServiceAccount and projects its short-lived token only into the API container;
init containers, worker, console, migrations, pgvector, OpenSearch, Vault, and
sandbox Jobs all disable ServiceAccount-token automount.

Repositories with Git metadata may require one additional inspector Job. That
control-plane read observes its own ephemeral copy and cannot mutate source;
all user-requested commands still run together in exactly one batch Job.

The Role is installed only in the required dedicated `sandbox.namespace` and is
deliberately exact: `jobs` get `create/get/delete`,
`pods` gets `list`, `pods/log` gets `get`, and `networkpolicies` gets `list`.
There are no policy or Secret mutation verbs and the RoleBinding names only the
API ServiceAccount. These permissions alone are not a sufficient admission
boundary because `jobs.create` could otherwise submit a privileged Pod.

This is the minimum permission set for the current direct Kubernetes-API
backend, but it is not object-level least privilege. The Kubernetes
[RBAC restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
cannot
apply a label selector to `pods list`, cannot wildcard the generated Job/Pod
names in `resourceNames`, and cannot constrain `create` by resource name. A
compromised API ServiceAccount can therefore list Pod metadata, read logs, and
get/delete Jobs outside the generated sandbox set in that dedicated namespace
even though normal backend code validates names, owners, and labels. It has no
Role in the application namespace; the live smoke proves list Pods, get Pod
logs, and delete Jobs are denied there. The sandbox namespace must contain one
tenant only and no unrelated workloads; labels remain defense in depth, not
authorization.

Production must provide all configured runtime assets before enabling this
backend:

- an immutable sandbox image in `repository@sha256:<64 lowercase hex>` form;
- a precreated sandbox namespace distinct from the application namespace;
- an application-namespace claim mounted read-only by the API and a
  sandbox-namespace claim mounted read-only by Jobs, both operator-attested
  views of the same tenant-scoped storage backend;
- a `networking.k8s.io/v1` NetworkPolicy whose selector is exactly
  `hallu-defense.openai.com/network-policy: deny-egress`, whose policy types are
  `Ingress` and `Egress`, and whose ingress and egress lists are empty.

`sandbox.workspace.createClaim=true` and the repository fixture are rejected
unless `kindDependencies.enabled=true`. The kind overlay creates two namespaced
RWO PV/PVC views backed by one isolated, hash-scoped hostPath; only the fixture
receives the write-capable view, while API and sandbox Job
source views are mounted read-only. Production operators provision both views and attest
their shared backend identity.
Each release also requires `sandbox.tenantId`; the API rejects a request whose
authenticated tenant differs from that value. Multi-tenant installations use a
separate namespace, release, ServiceAccount, and PVC per tenant. A shared claim
must never contain repositories for a different tenant boundary.

The backend lists NetworkPolicies before every Job, verifies the named deny
policy, and refuses creation if another policy selecting the Job labels adds an
egress rule. Kubernetes combines matching policies additively, so checking a
single deny policy is insufficient. The CNI must enforce the standard
NetworkPolicy API.

The chart installs a fail-closed `admissionregistration.k8s.io/v1`
`ValidatingAdmissionPolicy` and `Deny` binding. It is scoped by `userInfo` to the
API ServiceAccount and by namespace selector/request namespace to the dedicated
sandbox namespace. Its cluster-scoped name hashes both namespaces, so
two namespaced releases cannot collide. The policy accepts only the managed Job
prefix and labels, exact sandbox image, bounded deadline/TTL/resources, literal
non-secret environment allowlist, fixed three-container layout, non-root
RuntimeDefault contexts, dropped capabilities, masked proc mount, confined
AppArmor, no sysctls/ports/host namespaces/token, and exactly the configured
PVC plus bounded `emptyDir` volumes. `hostPath`, Secret or ConfigMap environment
sources, extra workspace mounts, PVC-root mounts, unbounded limits, and
privileged or unconfined contexts are denied. `failurePolicy=Fail` is mandatory.

Each admitted Job uses a read-only root filesystem, UID/GID 10001, a process
limit lowered with Linux `RLIMIT_NPROC`, an active deadline, TTL, and explicit
cleanup. Separate stdout and stderr exporter containers stream files from a
bounded `emptyDir`; the backend reads both logs independently and returns the
runner exit code. No sensitive inherited environment value, Secret, ConfigMap,
or ServiceAccount token is mounted.

Creation and cleanup use object identity, not a reusable Job name. The backend
accepts a create response only after validating the generated name, namespace,
managed labels, process-limit annotation, and Kubernetes UID. If the create
request has an ambiguous transport failure, invalid JSON, or a non-object
response, it polls with a bounded deadline and reconciles only that same
managed identity. Cleanup sends
`deleteOptions.preconditions.uid` with `propagationPolicy: Foreground` and zero
grace, then waits until GET returns `404` (or observes a same-name replacement)
and until no listed Pods remain whose owner UID is the deleted Job UID. A
missing or unvalidated UID prevents name-only deletion. Cleanup failure is
reported without replacing the primary execution failure, and a bounded
cleanup type/message is attached to the primary diagnostic.

Foreground deletion and owned-Pod confirmation have a Kubernetes-specific
budget: `HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS` defaults to 20
seconds and accepts only 15 through 30 seconds. It is independent of
`HALLU_DEFENSE_SANDBOX_DOCKER_TIMEOUT_GRACE_SECONDS` (default 2 seconds), which
still controls the admitted Pod's termination grace rather than the complete
Job/Pod cleanup lifecycle. Each individual API call remains capped by the
Kubernetes API request timeout and the remaining cleanup deadline.

Only the selected repository is mounted read-only at `/hallu-source` through a
validated, non-empty PVC `subPath`; sibling repositories and the PVC root are
never exposed. Before commands start, the immutable runner rejects links and
special files, enforces 50,000-file and 512 MiB bounds, and copies the source
into a bounded `emptyDir` at `/workspace`. Deleting the Job discards that
working copy. The
Kubernetes backend rejects the configured workspace root itself because every
admitted Job must target a child repository. Validation and copy permit at most
50,000 regular files, 512 MiB of total content, 75,000 combined file/directory
paths, 4,096 UTF-8 bytes per relative path, and 64 MiB of aggregate
relative-path bytes. API-retained output is capped at 100,000 characters per
stream. Directory enumeration, fingerprints, copies, artifacts, and output
capture remain bounded, accept zero-byte files at an exact content boundary,
and reject the first file, path, or byte beyond a configured limit. The Linux
batch runner reaps even new-session descendants before its artifact snapshot.

Tenant routing is checked before a Job is created and the source claim,
namespace, release, ServiceAccount, and repository root remain dedicated to
one canonical tenant. Job names and labels are not an authorization boundary.
The chart/admission front must keep the existing exact RBAC verbs and, when it
adopts a tenant marker, require a non-reversible canonical tenant-scope digest
rather than a raw tenant identifier; that change must be made atomically with
its ValidatingAdmissionPolicy and checker.

The kind smoke uses the built-in kindnet native NetworkPolicy implementation
with Kind 0.32.0 and leaves the default CNI enabled. It pins the Kubernetes
1.36.1 node image to
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
an environment override is accepted only when it equals that exact immutable
reference. No external CNI manifest is downloaded or applied. The smoke waits
for every node to become Ready before image loading, Helm rendering, and chart
installation, then treats real denied connections as the enforcement evidence.

The authenticated live check calls `/repo/checks/run` with an ephemeral signed
OIDC JWT and verifies two commands execute as one batch with ordered exit codes,
distinct stdout/stderr, artifact capture,
workspace escape rejection, timeout code and cleanup, a real failed TCP egress
attempt, and zero residual sandbox Jobs. Front D must extend the success and
timeout probes to list Pods by sandbox labels, correlate owner UIDs, and require
zero residual Pods owned by either Job UID. The current check also proves the API workspace mount
rejects writes, impersonates the API ServiceAccount to verify application
namespace denials and sandbox namespace grants, and proves admission rejects
privileged/hostPath, Secret-env, writable-source/PVC-root mount, oversized-resource,
unmasked-proc, and control-field probes before accepting the endpoint-generated
Job.
