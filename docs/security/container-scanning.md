# Container Scanning

The security workflow treats every runnable container as release input. Its first-party
matrix builds and scans the current `api`, `console`, `sandbox`, `pgvector`, `keycloak`,
`grafana`, `opensearch`, and `seaweedfs` Dockerfiles before a change is accepted. The
exact sandbox row binds `infra/docker/sandbox.Dockerfile` to
`hallu-defense-sandbox:ci`; neither the name, Dockerfile nor scan tag is inferred from
caller-controlled input. The
matrix uses `fail-fast: false` and `max-parallel: 1`, so one vulnerable image does not
prevent the remaining images from producing results while all Docker/Trivy work is
serialized; each vulnerable matrix cell still fails.

The workflow also scans every third-party runtime image declared in
`requirements/container-images.json`. The inventory records the exact tag and
manifest digest, digest type, and repository source for each deployed Compose,
Helm, MinIO, observability, identity, and persistence image. Runtime
configuration and the workflow matrix must match that inventory exactly; a
missing image, mutable tag, changed digest, or untracked reference fails the
static gate.

Required behavior:

- Run Trivy 0.72.0 through the commit-pinned 0.36.0 action.
- Scan OS and application/library packages in all eight first-party images.
- Scan the immutable third-party image matrix from the maintained inventory.
- Fail on every `HIGH` or `CRITICAL` finding; do not use `ignore-unfixed`,
  `continue-on-error`, or a severity waiver.
- Create an exact empty Trivy config and ignore file under the runner's external
  temporary directory before any build or scan, make both read-only, and pass their
  absolute paths explicitly. Repository `.trivyignore`, `trivy.yaml`, environment
  overrides, extra actions, matrix exclusions, conditional scans, and additional
  suppression inputs are rejected by the config gate.
- Preserve every finding, including vulnerabilities with no upstream fix. A network,
  registry, scanner-database, build, or CVE failure is a failed/incomplete gate and must
  be reported as such; it is never converted into a clean result.
- Keep workflow permissions read-only, action refs commit-pinned, and every job
  bounded by an explicit timeout.
- Use digest-pinned build bases, exact hashed Python locks, `npm ci`, and a
  checksum-and-integrity-verified npm archive for the sandbox runtime.
- Run first-party images as non-root with an image-specific identity (`10001` for API,
  sandbox, Keycloak, and SeaweedFS; the base-image `node` identity for Console;
  `472:472` for Grafana; `1000` for OpenSearch; and `postgres` for pgvector), while
  executable code/config remains root-owned and read-only at runtime.

`scripts/ci/check_container_scan_config.py` enforces the workflow, inventory,
Dockerfile, and source-discovery invariants. It parses the actual Compose and
Helm references, Kind node and kindnet boundary constants, and MinIO helper
scripts instead of trusting a hand-maintained summary.
`scripts/ci/check_python_reproducibility.py`
separately verifies the platform-explicit Python lock manifest, Node lock
policy, sandbox npm archive, and CI toolchain pins.

Static validation proves configuration shape. Acceptance still requires the Docker
builds and Trivy scans produced by every matrix cell in CI (or by a recorded local run
using the same pinned scanner and exact image tags). A partial matrix is partial
evidence, not a passing scan.

## Kind CI substrate boundary

The Kind node is CI infrastructure, not an image deployed by the product. It is
therefore excluded from the deployed-image acceptance matrix; this does not
claim that the node image is vulnerability-free. A Trivy 0.72.0 audit on
2026-07-10 reported 166 HIGH and 3 CRITICAL findings in the Kind 1.36.1 node.

The residual exposure is isolated to the secretless `kind-helm-live` validation
job. That job runs only on an explicit trusted dispatch or the weekly schedule,
has read-only repository permission, receives no secrets, and always tears down
the ephemeral cluster. The workflow and smoke script must agree on the exact
`kindest/node:v1.36.1` manifest digest; the Kind, Helm, and kubectl client
binaries are independently version- and SHA-256-pinned. Kind and its CNI are
not included in, published with, or deployed as part of the hallu-defense
runtime.
