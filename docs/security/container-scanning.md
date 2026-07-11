# Container Scanning

The security workflow treats every runnable container as release input. It builds
`hallu-defense-api:ci`, `hallu-defense-console:ci`, and
`hallu-defense-sandbox:ci`, and `hallu-defense-pgvector:ci` from their
repository Dockerfiles and scans those images before a change is accepted. The sandbox build comes from
`infra/docker/sandbox.Dockerfile`.

The workflow also scans every third-party runtime image declared in
`requirements/container-images.json`. The inventory records the exact tag and
manifest digest, digest type, and repository source for each deployed Compose,
Helm, MinIO, observability, identity, and persistence image. Runtime
configuration and the workflow matrix must match that inventory exactly; a
missing image, mutable tag, changed digest, or untracked reference fails the
static gate.

Required behavior:

- Run Trivy 0.72.0 through the commit-pinned 0.36.0 action.
- Scan OS and application/library packages in all four first-party images.
- Scan the immutable third-party image matrix from the maintained inventory.
- Fail on every `HIGH` or `CRITICAL` finding; do not use `ignore-unfixed`,
  `continue-on-error`, or a severity waiver.
- Keep workflow permissions read-only, action refs commit-pinned, and every job
  bounded by an explicit timeout.
- Use digest-pinned build bases, exact hashed Python locks, `npm ci`, and a
  checksum-and-integrity-verified npm archive for the sandbox runtime.
- Run first-party images as non-root UID 10001 with application files owned by
  root and read-only at runtime.

`scripts/ci/check_container_scan_config.py` enforces the workflow, inventory,
Dockerfile, and source-discovery invariants. It parses the actual Compose and
Helm references, Kind node and kindnet boundary constants, and MinIO helper
scripts instead of trusting a hand-maintained summary.
`scripts/ci/check_python_reproducibility.py`
separately verifies the platform-explicit Python lock manifest, Node lock
policy, sandbox npm archive, and CI toolchain pins.

Static validation proves configuration shape. Acceptance still requires the
Docker builds, read-only runtime smokes, and Trivy scans produced by CI (or by a
recorded local run using the same pinned scanner and exact image tags).

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
