# Privileged Release Process

The release workflow is manually dispatched from a protected default branch and has four
fresh release stages across three execution trust domains:
`verify-tag -> build-release -> scan-release -> attest-release`. The first job uses
external public trust roots to verify and peel the annotated tag in a bare repository; it
fetches the immutable workflow-dispatch control commit by exact object ID and fails unless
the peeled source is an ancestor of that exact control commit. It never checks out or
executes tag code and has no OIDC or attestation permission. The
unprivileged build job checks out and executes only that verified peeled commit, but has
only `contents: read`. A fresh unprivileged scan job has `permissions: {}`, never checks
out or executes tag/artifact code, and treats the build upload as inert data. The build
and scan jobs receive no Environment, signing material, OIDC token, or attestation
permission. The separate privileged attestation job receives OIDC and attestation
permissions only after scanning succeeds; it never checks out or executes the signed tag.
It handles downloaded files strictly as inert data. A fifth `release-verdict` job has no
token permissions or Environment and uses `if: always()` to observe all four stage results.
It fails unless every stage succeeded, so a trust job that was skipped, cancelled, or failed
cannot leave a visually green workflow with no release artifacts.

This split is mandatory. A tag-triggered workflow executes workflow code from the tag and
therefore cannot safely bootstrap trust by verifying itself after obtaining privileged
credentials. Repository controls cannot be proven by the workflow itself.

## External control-plane requirements

Before enabling releases, operators must configure all of the following outside the
repository:

- protect the default branch with required review/status checks and prevent force pushes;
- protect `v*` tags against creation, update, and deletion by ordinary writers;
- configure the `release` GitHub Environment with required independent reviewers,
  prevent self-review, and permit deployments only from the protected default branch;
- store `RELEASE_SIGNING_PUBLIC_KEYS_B64` only as a protected `release` Environment
  secret sourced from an independently governed public-key trust store;
- constrain accepted GitHub attestations to the expected repository, protected default
  branch workflow identity (`signer-workflow`), Environment, and control-workflow commit;
  independently require the signed tag object and source commit in `RELEASE_SOURCE`;
- provision deployment-encryption trust roots, authenticated replay state, and monotonic
  sequence/CAS state externally. A release bundle must never supply its own trust root,
  schema, policy, verification key, or replay authority.

If these controls are absent or cannot be independently attested, artifacts may exist but
the consumer must report `compliance_asserted: false`. A repository file, release bundle,
CLI override, operator assertion, or successful GitHub job cannot substitute for external
policy and trust.

## Trusted tag verification, unprivileged build, and fresh scan

The `verify-tag` job first validates a canonical `vMAJOR.MINOR.PATCH` input and a protected
`main`/`master` control ref. It decodes the externally supplied public-key bundle, rejects
`sec`/`ssb` packets before and after import, and requests only the exact `GITHUB_SHA` control
commit plus the requested tag through explicit refspecs into a bare repository. It verifies
the annotated tag signature and emits only the exact tag-object and peeled-commit SHAs. The
immutable workflow-dispatch control commit is never rediscovered from a mutable branch tip;
the job verifies the fetched object ID and requires the peeled commit to be its ancestor. It
cleans the keyring, bundle, credential helper, and bare repository on success or failure. It
has no checkout step and cannot execute subject code.

The `build-release` job depends on successful `verify-tag`, validates the immutable SHA
handoff, and checks out exactly the verified peeled commit without persisted Git
credentials or tag fetching. It compares `HEAD` to that SHA before running pinned, locked
security, test, and build tooling. This ensures signing trust material and Environment
access are gone before any subject code runs.

The build job builds the eight current first-party Dockerfiles: API, console, sandbox,
pgvector, Keycloak, Grafana, OpenSearch, and SeaweedFS. Builds and scans run sequentially;
the release workflow contains no Docker matrix or background builds. Each built image is
exported as a classic, uncompressed Docker archive with an explicit `--tag`, exporter
`name`, and `oci-mediatypes=false`. This removes Docker/OCI exporter ambiguity and makes
the archive's `RepoTags` and raw layer bytes independently verifiable. The image-config
JSON is hashed to obtain the immutable image-config digest. This is deliberately recorded as `digest_kind:
docker-image-config`; it is not presented as an OCI registry manifest digest. Because this
workflow does not push images, `registry_manifest_digest` remains `null`. A later authorized
publication/deployment process must record and attest the resulting registry manifest digest
and must not substitute the config digest for an `image@sha256:...` deployment reference.

All generated package and image subjects are written under `${RUNNER_TEMP}/release-build`,
outside the checked-out Docker context. The workflow also fails if generated `release`,
`scan-input`, or `attestation-input` directories appear in that context. Consequently an
earlier archive or scan result cannot silently enter a later image build. The success-only
build upload exposes only its immutable upload-artifact ID and digest.

On a fresh runner, the scan job downloads exactly that artifact ID, validates its exact file
inventory and `BUILD_SHA256SUMS`, then downloads Trivy at the pinned version and verifies its
archive SHA-256. It creates a trusted empty Trivy config (`{}\n`) and an empty ignore file
after download, invokes Trivy through `env -i`, and passes both files explicitly. The tag and
build artifact therefore cannot inject repository config, ignore rules, credentials, or a
home-directory override. Every image is scanned by archive `--input` for HIGH/CRITICAL OS
and library vulnerabilities without an `ignore-unfixed` waiver. Each scan writes
machine-readable Trivy JSON. A controller loop records every return code and continues
through all eight scans so one finding cannot hide later results; it then fails the job if
any scan failed. For Trivy 0.72.0 Docker-archive input, the raw `ArtifactName` must equal
the exact normalized relative archive path `images/<name>.docker.tar`. Absolute paths,
backslashes, traversal, dot segments, alternate names, and alternate extensions are
rejected rather than normalized into acceptance. `Metadata.RepoTags` independently must
be the singleton exact `hallu-defense-<name>:<tag>` identity: missing, duplicate, extra,
or different tags fail. `Metadata.ImageID` and `DiffIDs` bind the image-config digest and
layer sequence independently. The evidence v2 producer records those raw fields, and the
privileged consumer revalidates all four bindings from downloaded bytes.

`image-evidence.json` binds each image-config digest to its signed-source Dockerfile hash,
source/tag OCI labels, archive, scan report, scan-report digest, and exact scan policy.
`SHA256SUMS` covers the release source statement, nested build checksum manifest and
artifact ID/digest binding, wheel/source archive, API and Node SBOMs, both exact runtime
locks used as SBOM subjects, all eight image archives and digests, trusted Trivy policy
inputs, every Trivy result/status file, and the binding manifests. The scan upload runs even
after a failed scan so machine-readable diagnostics survive, but a failed scan job cannot
reach attestation.

Jobs pass only immutable upload-artifact IDs and digests. They pass no workspace, process
state, Docker daemon, environment file, or credential.

## Privileged verification and attestation

On a fresh runner, `attest-release` downloads exactly the artifact ID produced by the
successful scan job. Independently of the upstream `verify-tag` result, it creates a
temporary bare Git repository and re-fetches only the canonical tag metadata; there is no
checkout or working tree. It decodes the externally managed public-key bundle into a
temporary directory, inspects it before import, and rejects secret-key packets (`sec`/`ssb`).
A second post-import check rejects any secret key that reached the temporary keyring.

The job verifies the annotated tag signature, resolves its tag object and exact peeled
commit, and independently fetches the immutable `GITHUB_SHA` control object.
It revalidates the same ancestry before reading the eight Dockerfile blobs plus both runtime
lock blobs only to compute their hashes. It then deletes the key
file, `GNUPGHOME`, credential helper, and bare repository and unsets credential variables.
Cleanup is guarded by a trap on both success and failure and completes before downloaded
data is parsed or an OIDC-backed action runs.

An isolated (`python -I -S`) inline control-plane validator (embedded in the protected
workflow, not downloaded from
the tag) rejects symlinks, non-regular files, unsafe paths, duplicate manifest entries,
unexpected files, checksum mismatches, source/control metadata mismatches, Dockerfile-hash
drift, weakened scan policy, nonzero scan status, incomplete image coverage, and any Trivy
 report not bound to its image-config digest. It never imports or executes a downloaded module,
binary, script, archive, or container.

Docker archives are inspected without extraction or `docker load`. The validator bounds
compressed size, declared uncompressed size, compression ratio, member count, parsed JSON,
SBOM, and digest-file sizes; rejects absolute/traversing paths, duplicates, links, devices,
and special entries; requires one `manifest.json` entry and the exact repository tag; hashes
the config JSON to the recorded image-config digest; checks the source/tag labels; requires
`rootfs.type: layers`; and stream-hashes every referenced uncompressed layer tar in manifest
order against `rootfs.diff_ids`. Executable gate regressions exercise a valid synthetic
archive plus forged `RepoTags`, config digest, labels, layer inventory, `rootfs.type`, and
`rootfs.diff_ids`, so leaving marker text in dead code does not satisfy the release gate.
Separate executable Trivy-report regressions exercise raw archive-path and exact singleton
tag binding, including absolute, traversing, and wrong-extension `ArtifactName` values plus
missing and extra `RepoTags`. Thus the attested archive bytes, archive path, image identity,
image config, layers, signed source, tag, and Trivy metadata are one verified binding
rather than adjacent unverified claims.

Only after these checks does the job attest:

1. both build and scanned upload-artifact envelope digests, named by immutable artifact IDs;
2. every subject listed in the validated `SHA256SUMS`;
3. `api-runtime-lock.txt` against the API CycloneDX SBOM; and
4. `node-runtime-lock.json` against the Node CycloneDX SBOM. Both subjects are byte-for-byte
   copies of lock blobs read from the exact peeled signed commit, and the privileged verifier
   compares their digests before attesting them. The wheel remains a checksummed provenance
   subject; the workflow does not misleadingly attach a dependency SBOM to a broader binary
   or whole-repository source tar.

Registry pushes and package-write permission are absent. Publication remains a separate
authorized operation.

## Verification, replay, and rollback

Consumers independently verify the attestation signer/workflow identity, control commit,
artifact envelope digest, subject checksums, signed tag object, and peeled source commit.
Deployment encryption evidence is a separate fail-closed decision using externally
provisioned trust roots and authenticated replay/monotonic state; repository-self-authored
evidence never establishes compliance.

Never rerun a release after moving a tag. Create a higher signed SemVer tag and record the
supersession. A rollback uses a newly signed, higher-sequence deployment statement pointing
to an approved prior digest; it never lowers sequence or reuses a nonce. Local nonce caches
are bounded defense in depth. Global anti-replay and rollback protection come from the
external monotonic CAS anchor.
