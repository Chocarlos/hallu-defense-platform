# Container Scanning

The security workflow builds the API, console, and sandbox images from the repository Dockerfiles and scans
them with Trivy before a change is accepted.

Required behavior:

- Build `hallu-defense-api:ci` from `infra/docker/api.Dockerfile`.
- Build `hallu-defense-console:ci` from `infra/docker/console.Dockerfile`.
- Build `hallu-defense-sandbox:ci` from `infra/docker/sandbox.Dockerfile`.
- Scan all three images with `aquasecurity/trivy-action`.
- Fail the workflow on `HIGH` or `CRITICAL` vulnerabilities.
- Scan both OS and application/library packages.
- Do not use `continue-on-error`.

The local validator `scripts/ci/check_container_scan_config.py` checks that the workflow still
contains the required scan steps and that Dockerfiles keep basic hardening properties such as
non-root users, no `latest` base images, no remote `ADD`, and reproducible package installation.
For the sandbox image it also verifies pinned pytest, Node/npm runtime support, and UID `10001`.

This host may not have Docker available, so local validation proves configuration shape. Runtime image
build and vulnerability scan evidence comes from GitHub Actions.
