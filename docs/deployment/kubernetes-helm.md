# Kubernetes Helm Deployment

The Helm chart lives at `infra/k8s/helm/hallu-defense` and requires Kubernetes
1.34 or newer. Production defaults keep all in-cluster test dependencies
disabled. `values-kind.yaml` explicitly enables the pgvector, OpenSearch, TLS
Vault, and TLS Redis fixtures used only by the live installation smoke.

Deployment-specific OIDC, Vault, provider, CORS, outbound HTTPS, managed CA,
and console/API endpoint values default empty and are enforced with Helm
`required` calls. The kind overlay keeps production transport validation enabled
without weakening `HALLU_DEFENSE_ENV=production`.

`values.schema.json` is JSON Schema Draft 7 and is intentionally closed: every
top-level key is required, every object shape sets `additionalProperties=false`,
and critical replicas, ports, commands, timeouts, quantities, URLs, CIDRs, image
references, and Secret keys have explicit types and bounds. Misspelled or
unknown keys therefore fail `helm lint`, `helm template`, install, and upgrade
instead of being silently ignored. The worker contract is pinned to enabled,
one-or-more bounded replicas, the production command, metrics port 9090, and a
bounded `setupGraceSeconds`; the migration count and checksum inventory are
also immutable chart inputs.

The API receives only the logical approval commitment secret name and opaque
non-secret key ID from `approvalCommitment.activeSecretName` and
`approvalCommitment.activeKeyId`. Production operators must provision the Vault
path with at least 32 bytes of random key material before rollout; the chart
never renders the key into Helm history or a raw environment variable. A
rotation sets `previousSecretName`, `previousKeyId`, and `previousValidUntil`
together; partial values fail render and the API limits overlap to seven days.
The disposable Kind Vault bootstrap generates and seeds a distinct ephemeral
value for this path alongside the provider and metrics credentials.

The chart includes API, console, and worker Deployments, a migration Job that
runs `scripts/dev/apply_postgres_migrations.py`, secret templates, the
Kubernetes sandbox boundary, and single-replica kind dependencies. The worker
defaults to `worker.enabled=true` because the Batch 6 ingestion worker runtime
is part of the charted runtime.

Roadmap dependency marker: Batch 6 ingestion worker runtime.

## Console production OIDC contract

The Console Deployment is runtime-configured and always emits
`HALLU_DEFENSE_ENV=production` plus
`HALLU_DEFENSE_CONSOLE_AUTH_MODE=oidc`. Deployments must supply the canonical
HTTPS `console.publicOrigin`, `console.apiOrigin`, and `console.oidc.issuer`,
plus `console.oidc.clientId` and `console.oidc.apiAudience`. The Console issuer
and audience must exactly match the API `oidc.issuer` and `oidc.audience`, and
the public origin must appear exactly in `cors.allowOrigins`. The chart pins
tenant claim `tenant_id`, roles claim `roles`, and required roles
`verifier,approval_reviewer,policy_evaluator,sandbox_runner,tool_operator`.
There is deliberately no `NEXT_PUBLIC_*`, insecure/unsigned `ALLOW_*`, or local
identity `LOCAL_*` Helm contract; browser-safe runtime configuration is derived
server-side by the Console.
`values.schema.json`, the render-time guard, and the static gate keep
`console.replicas` fail-closed at exactly `1`: OIDC transaction and session
state are currently process-local, so horizontal replicas would lose callbacks
without affinity/shared storage. Restarting the Console invalidates active
transactions and sessions. A shared store is required before relaxing this
chart invariant.

## Inbound request size boundary

The API enforces a 1 MiB request-body ceiling before routing by default. Set
`HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES` only within the application-supported
1-byte to 16-MiB range, and configure the ingress/controller limit to the same
or a smaller value. Malformed or conflicting framing is rejected with 400;
declared and streamed bodies over the limit are rejected with 413 while actual
ASGI chunks are counted. Set `HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS`
between 1 and 60 seconds (default 15); expired body reads return 408. Large corpora should be split into bounded ingestion
chunks or upload batches rather than sent as one oversized JSON request.

## Immutable images and supply chain

Every first-party production workload image (`api`, `console`, `worker`, and
`migrations`) and the sandbox image must be supplied as
`repository@sha256:<64 hex>`. Mutable tags are accepted only by the kind overlay,
where the smoke builds and loads the images into its private cluster. Every
external third-party runtime image used by kind is digest-pinned in the base
values or replaced by a locally built derivative. pgvector is a locally built
hardened derivative from a digest-pinned PostgreSQL 16.14 Alpine base and an
exact pgvector commit; it removes `gosu`, runs as the native Alpine postgres
UID/GID 70, and is scanned as
`hallu-defense-pgvector:ci`. The Kind OpenSearch fixture is a core-only 3.7
derivative built from a digest-pinned base; it removes every optional plugin
and the unused ingest-geoip module and is loaded as
`hallu-defense-opensearch:ci`. Regular CI validates this inventory, and the
security workflow scans the resulting runtime images with Trivy.

The live smoke overrides each `:ci` fixture reference with one exact
`:kind-<run-id>` scratch tag. The chart permits only the five expected local
repositories with `:ci` or that bounded scratch-tag form; arbitrary registries,
repositories, or mutable tags fail rendering.
Kind pins both local-image pull policies to `IfNotPresent`; `Always` is rejected
so a node cannot replace a locally loaded scratch tag from a remote registry.
The Vault and Redis fixtures remain fixed to their exact verified third-party
digests and cannot be overridden by the Kind overlay.

The test-only env `HALLU_DEFENSE_SANDBOX_KUBERNETES_KIND_LOCAL_IMAGE=true` is
emitted exclusively when `kindDependencies.enabled=true` and accepts only the
exact local `hallu-defense-sandbox:ci` reference or the smoke-owned
`hallu-defense-sandbox:kind-<run-id>` tag. It is absent from base production
values and `docker-compose.prod.yml`; any other mutable reference is rejected
even when the flag is set, and non-Kubernetes backends reject the flag instead
of ignoring it.

The API image packages the migration applier, OpenSearch schema bootstrap,
`infra/rag/pgvector/*.sql`, the versioned OpenSearch template, OPA, and its policy
bundle. The sandbox image packages immutable runner and stream exporter
entrypoints. The static gate rejects image definitions that would make Jobs or
init containers reference absent runtime files.

## Migrations and process health

The revision-scoped migration Job first waits for PostgreSQL and then applies
all fourteen schema migrations, including `011_rag_lifecycle_outbox.sql`,
`012_rag_tenant_deletion_fence.sql`, and `013_audit_history_integrity.sql`. API
and worker pods wait for the migration ledger before starting. `values.yaml`
records the canonical SHA-256 of the UTF-8 SQL text for every migration, and the
static/live gates require the exact fourteen `(filename, checksum)` pairs with
no null, missing, extra, or drifted entry. A mandatory
`bootstrap-opensearch-schema` init container then installs and reads back the v3
index template under the pinned `opensearch-bootstrap` runtime role. That role
receives only the outbound allowlist, SecretManager/Vault token and CA, exact
`opensearch` backend, timeout, endpoint/index, and production OpenSearch
credential/CA inputs; it receives no PostgreSQL, JWKS, Redis, provider, OTLP, or
sandbox configuration. API and worker containers never start when the template
is unacknowledged or an existing v1 index requires reindexing. Worker liveness
checks its real PID 1 command; readiness invokes
`python -m hallu_defense.worker --check-ready`, which checks the migration ledger
and the hybrid OpenSearch health endpoint. API liveness uses `/health`; `/ready`
stays false until its PostgreSQL, JWKS, Vault, provider, and persistent RAG
dependencies are ready. The v3 template requires one replica. The single-node
Kind fixture accepts `green` or `yellow` cluster health with at least one data
node; staging and production require `green` health with at least two data nodes.
Worker readiness uses the bounded `worker.setupGraceSeconds` initial delay;
liveness adds ten seconds to the same grace. The Deployment progress deadline
also includes that grace after the migration wait budget.

PostgreSQL privilege is split across two precreated Secret objects. API, worker,
and their readiness init containers mount only
`secrets.runtime.name/secrets.runtime.postgresDsnKey` at
`/run/secrets/hallu_defense_postgres_dsn`; the migration Pod mounts only
`secrets.migrations.name/secrets.migrations.postgresDsnKey` at that same generic
container path. The two Secret names must be distinct, and neither credential is
rendered into Helm release history or exposed as a raw environment value. Helm
cannot compare opaque Secret contents: before each production rollout, the
operator must attest that the runtime identity has only required read/DML
privileges, the migration identity alone has DDL privileges, and the two refs
represent distinct database principals. No Pod receives both PostgreSQL refs.
Production and staging must also provide `postgres.caSecretName`; the CA is
mounted read-only into API, worker, migration, and their PostgreSQL wait
containers at `postgres.caPath`. Both opaque DSNs must set
`sslmode=verify-full` and an absolute `sslrootcert` equal to that path. The
DSNs must additionally set `ssl_min_protocol_version=TLSv1.3` and
`gssencmode=disable` so libpq cannot prefer GSS encryption. The
disposable Kind fixture alone sets
`HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED=true` and uses the exact
`hallu-defense-pgvector:5432` host with explicit `sslmode=disable` and
`gssencmode=disable`; validation
rejects that exception in staging, outside the exact host/port, or when mixed
with a CA. Kind may use the same ephemeral superuser URL behind the two distinct
Secret identities; this is not a production privilege claim.

The kind pgvector StatefulSet uses
`PGDATA=/var/lib/postgresql/data/pgdata`, below the PVC mount root, so uid 70
does not need to chmod the local-path mount itself. The core-only Kind
OpenSearch fixture has no security-plugin admin credential, password Secret, or
password value. Its HTTP endpoint remains reachable only inside the disposable
cluster and is constrained by the chart's ingress and egress NetworkPolicies;
its root filesystem is read-only, with writes limited to the data PVC, bounded
tmp/logs volumes, and an exact 16Mi in-memory config volume restored from the
image's immutable template at each start. Bouncy Castle FIPS is forced to its
Java implementation, so the fixture does not require executable scratch space.
The single-node transport listener is bound to `127.0.0.1:9300`; the live smoke
reads the Pod's kernel listener table and separately proves an unauthorized
probe Pod cannot connect directly to the OpenSearch Pod IP on port 9300.
Production continues to use managed
OpenSearch trust and authorization inputs.

The chart does not deploy an OpenTelemetry Collector. Production defaults keep
OTLP enabled and require `otel.endpoint`; kind sets `otel.enabled=false` to
avoid a retry loop against a nonexistent service.

## Vault, Redis, and outbound trust

Kind generates ephemeral RSA JWKS plus one-day CA and server certificates for
Vault and Redis. A revision-scoped bootstrap Job writes the generated provider
secret and metrics bearer token directly to their logical Vault KV v2 paths.
The API stays on `HALLU_DEFENSE_SECRETS_BACKEND=vault`; no production env-secret
backend or readiness bypass is introduced. Vault dev mode and its root token
are confined to disabled-by-default `kindDependencies`. Its implicit plaintext
listener is bound to `127.0.0.1:18200`; the Service targets only TLS port 8200.

Production must provide `vault.caSecretName` and
`rateLimit.redis.caSecretName`. A private OpenSearch PKI additionally sets
`opensearch.caSecretName`; public-PKI endpoints can leave it empty. The chart
mounts only the selected CA keys into their API/worker consumers, read-only with
mode `0440`, and points each client at that file.
Runtime and OpenSearch-bootstrap Vault tokens come from distinct precreated
Secret refs and are mounted read-only at
`/run/secrets/hallu_defense_vault_token`; only the non-sensitive
`HALLU_DEFENSE_VAULT_TOKEN_FILE` pointer enters the process environment. The
Redis URL remains a logical Vault reference. No token, DSN, certificate, or JWKS
value is accepted through Helm values; the kind smoke creates its ephemeral
Secrets with `kubectl` before Helm runs.

Kind Redis is a native sidecar of a short-lived bootstrap Deployment. It exposes
TLS only, requires TLS 1.2 or newer, disables the default account, and generates
an ephemeral ACL credential restricted to the rate-limit key prefix. The seeder
writes the resulting `rediss://` URL directly to Vault and removes its transient
file. Only Redis mounts its server certificate and key; the API mounts only its
CA. NetworkPolicies restrict Redis ingress to the API on port 6379 and Redis
egress to DNS and Vault. Production never deploys this fixture and must use a
managed Redis service.

The `apiEnv` and `workerEnv` helpers are separate. OPA configuration is emitted
only for the API. The worker receives its role, Vault SecretManager inputs, the
logical metrics bearer-token name, PostgreSQL DSN, hybrid pgvector/OpenSearch
settings, async ingestion mode, and a Downward API worker ID; it does not
receive JWKS, provider, CORS, OPA, Redis limiter, or sandbox configuration. Its
Pod exposes only container port 9090 for authenticated `/metrics`, publishes
exact Prometheus annotations, and accepts ingress only from
`networkPolicy.ingress.worker.metricsScrapers`; the default allowlist is empty
and production must name namespace plus Pod labels. API and worker both receive the explicit
`outboundHttps.allowedOrigins` allowlist, and production rejects an empty list.
Both executables pin their expected role and fail closed on a mismatch.

## API and worker egress isolation

The chart selects every workload Pod with an explicit egress NetworkPolicy.
API and worker permit DNS only to Pods labeled `k8s-app: kube-dns` in the
immutable `kube-system` namespace, and internal kind dependencies only through
exact release/component pod selectors and ports. The API alone receives the
`networkPolicy.kubernetesApi` CIDR/port list; the worker never does. Console
permits cluster DNS and, outside Kind, its dedicated
`networkPolicy.console.external` single-host OIDC gateway entries. pgvector,
single-node OpenSearch, and Vault deny all egress. The migration Job
permits only DNS plus PostgreSQL (the exact kind selector or its own dedicated
production CIDR list), while the kind Vault bootstrap Job permits only DNS and
Vault port 8200. Redis retains exactly DNS and Vault:8200 because its one-shot
seeder must store the generated TLS URL in Vault; its guard and server receive
no broader destination.

The Kind live gate does not assume that a CNI evaluates the Kubernetes Service
VIP before translation. It validates the `default/kubernetes` Service, its sole
Ready EndpointSlice endpoint, and the sole control-plane Node InternalIP, then
passes exactly two API-only peers to every Helm operation: the Service VIP on
443 and the matching post-DNAT endpoint on 6443. This covers kindnet's current
post-DNAT evaluation without broadening the allowlist; any ambiguity, mismatch,
extra endpoint, or unexpected port fails the gate. Production operators must
perform the equivalent validation for their chosen CNI because Service
translation and NetworkPolicy ordering are implementation-dependent.

Kind dependency ingress is equally explicit: pgvector accepts only API, worker,
and migrations on 5432; OpenSearch accepts only API and worker Pods (including
their schema init containers) on 9200; Vault accepts only API, worker,
vault-bootstrap, and Redis on 8200. Redis accepts only API on 6379. These
selectors are release- and component-scoped. Externally managed production
dependencies remain responsible for equivalent firewall/security-group policy.

Production external peers are role-specific named CIDR/port entries, including
a migration-only list that cannot inherit API or worker destinations. Every
CIDR must identify exactly one host (`/32` for IPv4 or `/128` for IPv6); broad
prefixes such as paired `/1` routes, invalid/non-canonical CIDRs, duplicate
peers, invalid ports, and address-family wildcards fail the chart gate. FQDN
peers are not claimed because standard NetworkPolicy cannot enforce them;
production should route provider, Vault, PostgreSQL, Redis, OpenSearch, and OTLP
traffic through stable single-host egress gateways.

Ingress is default-deny for the application namespace and for the dedicated
sandbox namespace. API and console accept traffic only from explicit
namespace-plus-pod-label caller allowlists; the API has a separate explicit
Prometheus scraper peer, and Console has its own distinct
`networkPolicy.ingress.console.metricsScrapers` allowlist for `/metrics`.
Kind proves an unlabeled Pod cannot reach either
service, then proves only the `api`, `console`, and `metrics` caller labels reach
their intended port. Dependency ingress remains component-scoped as described
above.

NetworkPolicy processing relative to Service DNAT is CNI-dependent. The kind
fixture pins `10.96.0.1/32:443` and proves it with the built-in
kindnet native NetworkPolicy provider. This is not a portable production
guarantee. Every environment must validate its Kubernetes API destinations with
its actual CNI, or use a service-aware policy/egress proxy.

The runtime Kubernetes Secret has no metrics bearer token, and `values.yaml`
has no plaintext equivalent. This chart does not deploy Prometheus; an external
Prometheus must use the
[metrics token materializer](metrics-bearer-token-materializer.md) to write the
API Vault value to its private file mount. Console metrics use the separate
file-backed bearer in `secretRefs.demo.metricsBearerKey`; the managed
Prometheus must receive the same bytes at
`/run/secrets/hallu_console_metrics_bearer` and must not reuse the API token.
The stock Console Service is HTTP on port 3000, so the bearer travels only on
the explicitly allowlisted in-cluster path. If the environment requires
encrypted east-west traffic, deploy a real TLS/mTLS sidecar or service-mesh
listener and configure Prometheus CA/SNI against that listener; the chart does
not claim TLS merely by changing a scrape scheme.

## Kubernetes sandbox boundary

The API submits checks through the Kubernetes backend; neither the chart nor the
smoke mounts a Docker socket. Its dedicated projected service-account token is
mounted only in the non-root API container, rotates hourly, and uses mode
`0440` through pod fsGroup 10001. API init containers never receive it. Every
other workload explicitly disables token automounting. The API Role is
intentionally exact: Jobs can be created, read, and deleted; Pods can be listed;
pod logs can be read; and NetworkPolicies can only be listed.

Those verbs are namespace-scoped, not label-scoped. The Role and RoleBinding now
live only in the required `sandbox.namespace`, which must differ from the Helm
release/application namespace; the binding subject is the API ServiceAccount in
the application namespace. A live impersonation check proves that identity
cannot list Pods, read Pod logs, or delete Jobs in the application namespace,
while it can perform the exact Job/Pod-log/NetworkPolicy operations in the
sandbox namespace. Native RBAC still cannot label-scope those sandbox-namespace
verbs, so that namespace must contain one tenant and no unrelated workloads.

Each sandbox Job is admitted by a fail-closed `ValidatingAdmissionPolicy` scoped
to that API service account and the dedicated sandbox namespace. The policy locks the sandbox image, command,
arguments, working directory, resources, security contexts, volume types and
mounts, workspace subPath, deadline, TTL, and metadata. It rejects host access,
privilege escalation, secret-derived environment input, mutable execution
shape, attacker-controlled selectors/finalizers, and root workspace mounts. It
accepts only the two managed sandbox labels plus the four Job labels generated
by the Kubernetes API server, with both legacy and prefixed values tied to the
Job name/UID and its generated selector. A deny-all ingress-and-egress
NetworkPolicy selects every sandbox Job pod.

Production must precreate two namespaced RWX claim refs over the same
tenant-scoped storage backend: `sandbox.workspace.apiExistingClaim` in the
application namespace and `sandbox.workspace.existingClaim` in
`sandbox.namespace`. The API mounts only the first view with `readOnly: true`;
the sandbox runtime mounts the second view only as a read-only `source` at
`/hallu-source` with a mandatory child-repository `subPath`. Only the Kind
fixture preparation Job writes the source claim. Each runtime Job copies that
source into a distinct 512Mi `emptyDir` at `/workspace`, enforcing 50,000-file
and 512MiB copy bounds and rejecting links or special files before executing.
No sandbox command can mutate the PVC; Job deletion discards the writable copy.
Operators must attest that both claims address the same storage/tenant boundary.
The chart cannot prove CSI backend identity from claim names alone. Kind creates
two static PV/PVC views of one isolated hostPath and prepares the fixture in a
Job in the sandbox namespace. `sandbox.workspace.createClaim` and
`sandbox.fixture.enabled` remain kind-only. The backend rejects the workspace
root and path escapes. The live smoke proves the API and sandbox source mounts
reject writes while commands write only their disposable workspace. Multi-tenant deployments
require separate Helm releases, application/sandbox namespaces, service
accounts, storage views, and tenant IDs. See
[`kubernetes-sandbox-jobs.md`](kubernetes-sandbox-jobs.md) for the complete
runtime and admission contract.

`sandbox.cleanupGraceSeconds` defaults to 20 seconds and is schema-bounded from
15 through 30 inclusive. For the Kubernetes backend the chart maps it only into
the API container as
`HALLU_DEFENSE_SANDBOX_KUBERNETES_CLEANUP_GRACE_SECONDS`; it is distinct from
the Docker timeout grace. The converged Front C/runtime contract consumes that
variable as `sandbox_kubernetes_cleanup_grace_seconds`, with the same default
20 and finite inclusive range 15 through 30, and uses it as a post-`DELETE`
convergence deadline: the exact created Job must be absent and no Pod may
retain an `ownerReferences[].uid` equal to that Job UID. Absence by label or
Job name alone is not sufficient cleanup evidence. The live smoke independently
proves the same exact Job/Pod convergence against the Kubernetes API within the
bounded window.

## Static validation

`scripts/ci/check_helm_chart.py` enforces:

- non-root pod/container security contexts, disabled privilege escalation,
  dropped capabilities, resource bounds, probes, and disabled default service
  account token automounting, plus a bounded 64Mi `/tmp` `emptyDir` for every
  first-party runtime and bootstrap workload;
- production fail-closed API configuration for OIDC, Vault, PostgreSQL
  persistence, provider, Kubernetes sandbox, OPA, outbound HTTPS, and OTLP, plus
  exact worker environment isolation;
- digest-only production workload and sandbox images and digest-pinned kind
  dependencies;
- migration assets and coordination, API `/ready`, valid ephemeral JWKS/TLS,
  a distinct DDL migration DSN, Vault bootstrap, and the absence of duplicate
  plaintext runtime secrets;
- managed Vault/Redis CA mounts, Redis URL bootstrap through Vault, TLS/ACL
  confinement, and Redis NetworkPolicies;
- exact sandbox RBAC, API-only projected credentials, fail-closed admission,
  deny-egress, existing RWX production claims, and tenant/PVC isolation; and
- production-disabled kind fixtures plus an explicit `values-kind.yaml` test
  overlay.

The Kind fixture preparation Job carries the Helm revision label on both Job
and Pod, writes an ephemeral readiness marker only after the Git repository and
all fixture files exist on the isolated scratch workspace, exposes a
`readinessProbe` that rechecks those files, and remains Running for the bounded
setup grace (minimum five seconds, default fifteen). The live gate must observe
the exact revision-owned Pod, its `prepare-sandbox-fixture` container, and the
installed readiness probe in `Ready=True` with zero restarts before it accepts
Job completion.

Run the static check:

```text
python scripts/ci/check_helm_chart.py
```

With Helm installed, the checker runs `helm lint` and renders both kind and
synthetic production values. It also renders negative configurations and
requires unknown/typo keys, invalid types, out-of-range replicas/ports/timeouts,
disabled required workers/dependency fixtures, arbitrary mutable images,
missing claims or CAs, production-created PVCs, fixtures, overlong release
names, and namespace identity collisions to fail.
Regular CI and the security workflow install checksum-pinned Helm 4.2.2 before
the API tests/checker, so these Helm and negative-value gates cannot silently
degrade to the local no-Helm skip path.

## Live kind validation

`scripts/dev/live_kind_helm_smoke.py` is env-gated and skip-safe only while it is
disabled. Once `HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED=true`, missing
`docker`, `kind`, `kubectl`, or `helm` is a failure. Each execution derives a
DNS-safe run ID, a unique `hallu-defense-smoke-<run-id>` cluster, and five exact
`:kind-<run-id>` image tags. An explicit run ID is available for CI auditability.
The smoke refuses to overwrite a pre-existing scratch tag. It builds and loads
API, console, sandbox, hardened pgvector, and core-only OpenSearch images. It creates
Kind 0.32.0 with its default kindnet CNI left enabled and pins the Kubernetes
1.36.1 node image to
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
`HALLU_DEFENSE_LIVE_KIND_NODE_IMAGE`, when set, must equal that exact reference;
tag-only or different-digest overrides fail closed. No external CNI manifest is
downloaded or applied. Non-amd64 Docker servers fail before cluster creation.
Kind writes only to a kubeconfig inside the smoke's temporary directory; every
kubectl and cluster-facing Helm command names that file and the exact context,
so concurrent executions do not mutate the user's global kubeconfig.
The smoke server-side dry-runs the rendered VAP on a clean control plane and
waits for all nodes to become Ready before loading images. CEL/schema or native
network failures therefore stop before Helm rendering. It lets the node pull
each external dependency by its exact digest before performing an initial
`helm upgrade --install`. Custom revision-scoped waits first observe the fixture
Pod Ready, then require the revision-1 fixture, migration, and Vault bootstrap
Jobs to complete and all rollouts to converge. The three 600-second-TTL Jobs are
polled as one revision set; once completion is observed a finished component is
not queried again, so an early completion cannot disappear before a later Job
is checked. It then performs a second real
`helm upgrade` with only the one-shot fixture disabled, requires the revision-2
migration and Vault bootstrap Jobs plus rollouts, and captures the revision-2
migration Pod status and bounded logs immediately when that Job completes,
before any rollout wait. It reads Helm history back as
revision 1 `superseded` and revision 2 `deployed`. This verifies idempotent
upgrade behavior without asking Helm itself to create a second fixture Job
through the active sandbox admission boundary. The remaining checks verify
migrations, OpenSearch schema v3 provisioning/readback, its one-replica setting,
`green|yellow` Kind health with at least one data node, rollouts, worker hybrid
readiness, and `/health` plus `/ready` against the deployed API.
It also executes a probe inside the Console Pod that requires the exact
production/OIDC environment, proves `NEXT_PUBLIC_*`, `ALLOW_*`, and `LOCAL_*`
variables absent, and requires the runtime-configured Console page to return
HTTP 200.

The smoke authenticates `/repo/checks/run` with an ephemeral signed OIDC token
and verifies stdout, stderr, exit code, artifact export, path-escape rejection,
and timeout cleanup. During the timeout request one foreground in-Pod observer
captures the new Pod's controller Job name and UID, joins the HTTP request, and
uses the bounded cleanup grace to require both an exact-Job 404 and zero Pods
whose `ownerReferences[].uid` matches that UID. Final label inventories must
also contain zero sandbox Jobs and zero sandbox Pods; a Jobs-only empty result
cannot pass. Every child HTTP timeout is derived from the 15-second setup
budget, 30 seconds per requested command, the selected 15..30-second cleanup
grace, and a 15-second Kubernetes API/poll allowance. A plain surrounding exec
adds a named five-second request margin. The cleanup observer's outer timeout
separately includes its initial five-second Pod inventory, the 15-second UID
capture allowance, the bounded request-thread join (including its request
margin), the selected post-response convergence grace, and a distinct named
five-second outer margin. Capture-phase Kubernetes calls use the smaller of the
five-second API budget and the capture deadline's remaining time. Consequently
the outer timeout strictly exceeds every substituted inner phase instead of
depending on concurrent completion. It server-side dry-runs the exact
backend Job through the real admission policy and proves malicious variants are
denied with server-side dry-runs, so no intentionally malicious pod is ever
started. It also verifies Redis through Vault, TLS, and the managed CA, proves an
allowed rate-limit script succeeds, rejects out-of-prefix keys, forbidden ACL
commands, invalid AUTH, and plaintext Redis traffic. Runtime kindnet evidence
inventories the exact policy for every workload, proves API access to the
Kubernetes API, worker denial to that API, denial of `1.1.1.1:443` from
API/worker/console, denial from a cleaned-up unauthorized probe Pod to
pgvector/OpenSearch/Vault, and real sandbox egress denial. The result records
both bootstrap Jobs complete, every long-running workload Pod as Running/Ready
with zero restarts, successful non-revealing reads of both projected runtime
files inside API and worker, the migration Job's successful consumption of its
separate projected DSN with zero migration-container restarts, the VAP observed
generation and fifteen malicious-Job denials (including lifecycle and all probe
execution hooks), migrations, schema, and network
evidence.
The smoke also updates the precreated runtime Secret through stdin with
server-side apply (so no client-side last-applied secret annotation is stored),
waits for the API projection to change, and proves `load_settings` preserves the lexical
path while `VaultSecretManager` observes the rotated token fingerprint. It then
restores the original token, proves that revision visible again, and rechecks
all workload Pods with zero restarts; raw token bytes are never printed or
passed through Helm values/history. The smoke reads the manifest and complete
values for both revisions and rejects any rendered Secret object, raw DSN,
private key, sensitive value field, or changed precreated-Secret reference.
Inside the same API Pod, a lifecycle probe writes one real hybrid evidence row,
executes coordinated tenant deletion, and requires a completed journal entry,
one durable `rag_tenant_deletion_tombstones` row, and exact zero counts in both
PostgreSQL and OpenSearch. Reingesting the deleted tenant must raise
`RagIndexTenantDeletedError`; the probe then rechecks both stores at zero, which
proves the rejection occurred before an OpenSearch write and that the SQL fence
remained authoritative.
Cleanup is successful only after `kind delete` succeeds, a fresh inventory
proves the exact owned cluster absent, every exact scratch image tag is removed,
and subsequent image inspection proves all five absent. Baseline and post-run
inventories are recorded as evidence, but unrelated concurrent cluster changes
are not mistaken for this run's cleanup responsibility. A failed `kind create`
never authorizes deletion of a cluster it did not establish. Cleanup removes no
Docker volume, performs no prune, and never touches the repository's primary
services or data. Cleanup failure does not mask a primary smoke failure, and
diagnostics redact signed tokens, credential-bearing URLs, sensitive
assignments, and private keys.

The smoke does not call the synthetic provider endpoint; end-to-end provider
connectivity remains covered by the separate live provider smoke.

The `kind-helm-live` workflow installs kind 0.32.0, Helm 4.2.2, and kubectl
1.36.1 with checksum verification. It supplies a GitHub-run/attempt-derived
scratch ID and has an `always()` teardown that targets only that exact cluster
and those exact five image tags, then verifies their absence. The smoke uses a
digest-pinned Kubernetes 1.36.1 kind node and runs on `workflow_dispatch` and
the weekly schedule. Kind
is CI infrastructure for this live lane, not a production workload or deployed
runtime image. The lane does not run on every push because the static chart gate
remains in regular CI.
