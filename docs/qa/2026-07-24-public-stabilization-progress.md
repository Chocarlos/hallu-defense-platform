# Public stabilization progress — 2026-07-24

## Decision

`not accepted` — this report records progress and current blockers for draft pull request #4. It does not certify the branch, a release, or a deployment.

## Scope

- Base commit: `8ea0c2cecb39f94520a0d21672f3c0ef7e96f15e`.
- Branch: `codex/public-stabilization-v0.1.0`.
- Pull request: `#4`, kept in draft.
- Default branch: unchanged.

The stabilization slice adds Apache-2.0 licensing, Xocarlos ownership and provenance documentation, contribution and community governance, security-reporting guidance, an external GitHub-control runbook, an explicit `v0.1.0` release contract, a shorter public README, a provider compatibility matrix, and failure-only CI diagnostics.

## Node dependency finding and remediation

CI run `30064075263` produced a failure-only npm audit artifact. The full and runtime reports identified a HIGH advisory in the Next-scoped `postcss@8.5.10` resolution:

- `CVE-2026-45623` / `GHSA-6g55-p6wh-862q`;
- affected versions: `<=8.5.11`;
- first patched version: `8.5.12`.

The exact npm 11.16 lock refresh advanced only the reviewed Next/PostCSS override and its governed assertions from `8.5.10` to `8.5.12`. The generated lock records the official registry tarball and integrity value. Lock-refresh run `30064270514` completed successfully and its runtime `npm audit --omit=dev --audit-level=high` passed. No advisory ignore, audit exception, resolution wildcard, or unsafe major override was added.

The existing moderate advisory chain through the MCP SDK's unused Hono HTTP adapter remains visible to the full development audit. The repository's configured gate blocks HIGH/CRITICAL findings; the moderate item remains follow-up work rather than a silent override.

## Python test diagnostic

CI run `30064075263` executed the complete API suite and reported:

- `2830 passed`;
- `11 deselected` according to the lane selector;
- `1 failed`.

The single failure was documentary: `README.md` no longer contained the required `marketing-launch.md` link after the public-guide simplification. The deployment link was restored without reverting the shorter guide or changing runtime behavior. A later exact-head CI run must prove the correction.

## Prometheus image blocker

The strict security workflow rejected the immutable image:

```text
prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80
```

A temporary read-only diagnostic workflow reproduced the scan with Trivy `v0.72.0`, exported JSON, and was removed immediately after inspection. Diagnostic run `30064513827` found the same HIGH issue in both `/usr/bin/prometheus` and `/usr/bin/promtool`:

- package: `google.golang.org/grpc`;
- installed: `v1.81.1`;
- fixed: `1.82.1`;
- advisory: `GHSA-hrxh-6v49-42gf`;
- title: `gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities`.

Prometheus tag `v3.13.1` declares `google.golang.org/grpc v1.81.1` in its upstream `go.mod`. As of this report, upstream tag `v3.13.2` is not available. The repository therefore keeps the strict HIGH/CRITICAL failure active. No Trivy ignore, severity reduction, `ignore-unfixed`, mutable image tag, or unverified digest replacement was introduced.

The release remains blocked until an immutable upstream image or independently governed replacement is available, pinned by digest, inspected, and accepted by the existing container-image gates.

## External control-plane blockers

The following settings remain external and must not be inferred from repository files:

- protected default branch;
- protected `v*` tags;
- independently reviewed `release` Environment;
- GitHub private vulnerability reporting;
- verified security-alert notification path.

The required procedures and honest status rules are documented in `docs/governance/repository-controls.md`.

## Remaining validation

Before this slice can move beyond draft:

1. all current-head `ci`, `evals`, and `security` jobs must complete;
2. the Prometheus image HIGH finding must be resolved without weakening policy;
3. traceability and worklog must identify the exact final candidate;
4. external GitHub controls must be verified and recorded;
5. a final diff and secret/provenance review must pass;
6. no historical result may be extrapolated to the final candidate.
