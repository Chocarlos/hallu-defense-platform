# Release encryption evidence verification

`scripts/ci/verify_release_encryption_evidence.py` verifies a release evidence bundle against trust
material that the bundle cannot supply or override. The CLI accepts only `--bundle` and `--report`.
Policy and schemas are anchored to the checked-out repository; there are no CLI switches for a key,
policy, schema, trust store, replay state, time, tenant, or environment.

## Protected inputs

The release controller must inject all of these environment values from protected configuration:

| Variable | Meaning |
|---|---|
| `HALLU_DEFENSE_RELEASE_DEPLOYMENT_SUBJECT_PATH` | Absolute path to the external deployment subject |
| `HALLU_DEFENSE_RELEASE_TRUST_STORE_PATH` | Absolute path to tenant/environment trust bindings and rotation policy |
| `HALLU_DEFENSE_RELEASE_KEYRING_PATH` | Absolute path to Ed25519 public keys and HMAC key material |
| `HALLU_DEFENSE_RELEASE_REPLAY_STATE_PATH` | Absolute path to the authenticated replay state |
| `HALLU_DEFENSE_RELEASE_EXPECTED_TENANT_ID` | Control-plane tenant identity |
| `HALLU_DEFENSE_RELEASE_EXPECTED_ENVIRONMENT` | `staging` or `production` |
| `HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_STORE_ID` | Expected trust-store identity |
| `HALLU_DEFENSE_RELEASE_EXPECTED_TRUST_ROOT_ID` | Expected binding/root identity |
| `HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256` | Digest read from an independent monotonic CAS/ledger |

The four input paths must be absolute regular files, must resolve without `..`, symlinks, junctions,
or other reparse points, must be mutually distinct, and must be outside the untrusted bundle's
directory. Reads use a no-follow file descriptor and verify the file identity did not change. The
directories still require restrictive owner/ACL controls: path checks do not compensate for an
attacker who controls the trusted directory or the release controller.

`--report` must also be absolute, distinct from every input, outside the bundle directory, and in a
trusted output directory. Never place the trust store, keyring, replay state, or report in an
artifact directory writable by the bundle producer.

The keyring is sensitive. Ed25519 entries are public verification keys, while commitment,
replay-state, and verification-report entries are HMAC secrets of at least 32 bytes. It must be
provisioned from a secret manager or equally protected ephemeral file and removed after the job.
The trust store binds every key ID to its purpose and material hash. A binding permits exactly one
issuer, builder, workflow, and source repository, preventing one valid key from impersonating a
different principal listed in the same binding.

## Authentication and binding

The bundle is rejected if it contains keyring, keys, policy, schema, trust-store, trust-root,
manifest, deployment-subject, or replay-state fields. JSON duplicate members and non-finite values
are also rejected.

Authentication uses domain-separated canonical JSON:

- HMAC-SHA-256 commitments cover the bundle with commitments and authenticators empty.
- Ed25519 authenticators cover the bundle with authenticators empty and therefore include every
  HMAC commitment.
- the replay-state HMAC covers the state with `state_mac` empty;
- the report HMAC covers the report with `report_authenticator` null.

The verifier uses `cryptography`'s Ed25519 backend; it does not implement signature arithmetic.
The exact deployment-subject bytes, repository policy bytes, evidence-schema bytes, trust-store
bytes, image digests, configuration hashes, workflow-definition SHA-256, PostgreSQL CA rollout, and at-rest/in-transit evidence
digests are SHA-256-bound into the signed bundle and provenance material set. Provenance materials
must be exact and unique. Encryption-policy v1 requires every declared component profile to be
exactly `active`; an unknown/disabled-looking typo cannot silently remove a component from the
required attestation set. Default and component key management must be exactly
`vault-compatible-kms`, and at-rest algorithms are limited to `AES-256`, `AES-256-GCM`, or
`SSE-KMS-AES-256`; substring lookalikes fail closed.

Tenant, environment, release ID, deployment revision, source commit, repository, workflow, issuer,
builder, trust-store ID, and trust-root ID must all match their external bindings. Timestamps are
timezone-aware and preserve microsecond precision. An observation cannot predate provenance
completion or postdate the bundle's signed issue time; clock skew never licenses a future
observation. During rotation, a bundle cannot expire after the overlap deadline.

## Two-phase anti-rollback anchor

An HMAC proves state integrity, not freshness. Restoring an older replay file also restores a valid
old MAC. For that reason, compliance requires an independent monotonic compare-and-swap anchor.
`HALLU_DEFENSE_RELEASE_EXPECTED_REPLAY_STATE_SHA256` must come from that control-plane CAS, ledger,
TPM-backed register, or equivalent durable monotonic service. Never calculate it from the replay
file immediately before verification; doing so defeats rollback protection.

The protocol is deliberately two phase:

For initial provisioning, create a schema-valid replay state with an empty `bindings` array, the
active replay key ID, and a correct state HMAC. Write it through the protected control plane, compute
the SHA-256 of the exact canonical file bytes once, and create the monotonic CAS entry with that
digest. Bootstrap is an administrative operation; the verifier will not create a missing state or
derive its expected anchor.

Every replay-state file is scoped to exactly one externally selected tenant/environment pair. Its
`bindings` array is either empty only for bootstrap or contains exactly that one pair. A foreign or
second binding fails closed and is never preserved into the next state or uploaded by the workflow;
deploy a distinct protected replay state and CAS anchor for every tenant/environment pair.

1. The controller supplies CAS value `old`. The verifier requires the current replay file hash to
   equal `old`, validates the state MAC and monotonic sequence/revision/epoch/timestamp rules, then
   atomically writes the next state. The report contains `replay_state_previous_sha256: old`, the
   `replay_state_next_sha256`, `anchor_update_required: true`, and
   `compliance_asserted: false` with `anchor.update_required`.
2. The controller performs an external CAS from `old` to the reported next digest. A failed CAS is
   a release failure; the controller must not overwrite a newer value.
3. The controller invokes the verifier again with the exact same bundle bytes and the new CAS value.
   The verifier recognizes the authenticated last transition without applying it again, sets
   `anchor_finalized: true`, and only then may set `compliance_asserted: true`.

If the process crashes after the local write, repeating phase 1 with the exact bundle returns the
same update-required transition. If the replay file is restored after the CAS advanced, its digest
does not match the external anchor and verification fails closed. The verifier never reconstructs or
auto-accepts a rollback recovery.

The replay state keeps the last 256 nonces as an additional recent-duplicate signal. Global replay
prevention comes from the strictly increasing sequence plus the external monotonic anchor, not from
an unbounded nonce database. A deployment revision cannot decrease; the same revision cannot change
deployment hash; rotation epochs cannot decrease; a stable epoch cannot return to overlap; and
issued time must increase with full microsecond precision.

## Coordinated rotation

One global epoch coordinates four key groups: Ed25519 bundle authenticators, HMAC commitments,
replay-state HMACs, and report HMACs.

For an overlap epoch, the trust store contains exactly one active key and one retiring key for every
group, names both as required, requires the retiring key epoch to be exactly the active epoch minus
one, and sets an overlap deadline no more than seven days after trust-store generation. The bundle
carries both Ed25519 authenticators and both HMAC commitments. The replay
state may still be authenticated by either declared replay key; phase 1 verifies it and rewrites the
state with the active key, so the subsequent CAS/finalization proves migration. Reports use the
active report key. Bundle TTL must end inside the overlap window.

After every old-key bundle is drained, the replay state has migrated, its digest is externally
finalized, and no old execution remains, publish a stable trust store containing only active keys.
Changing trust material changes the trust-store hash, so the deployment subject and signed bundle
must be regenerated. Removing a retiring replay key before a successful state migration fails closed;
there is no automatic key-ID or MAC bypass.

## Report consumption

A true report always carries `report_authenticator` using an externally provisioned
`verification-report-hmac-sha256` key. Consumers must validate the report schema and recompute this
HMAC with the independently trusted keyring; `report_authenticator_is_valid` exposes the canonical
check for controller integration. A JSON file copied out of its trusted directory is not credible by
appearance alone. Reports produced before the trust store/keyring can be validated are intentionally
unauthenticated and can only assert false.

Failure reports contain stable failure codes, hashes, and booleans, never key material or exception
messages. The verifier exits nonzero for failed verification and exits with a distinct error when no
safe report can be written.

## Invocation

Provision protected files and environment values first, then use absolute paths:

```text
python scripts/ci/verify_release_encryption_evidence.py \
  --bundle C:/release-input/evidence.json \
  --report C:/release-control/reports/encryption-report.json
```

The first successful cryptographic pass still exits as non-compliant until the controller completes
the external CAS and repeats the exact bundle for finalization.

## Protected GitHub Actions controller lane

`.github/workflows/verify-release-encryption.yml` is the operational adapter for the two-phase
protocol. It is manual by design and runs only when the selected ref is the repository's protected
default branch. Configure the `release-encryption-verification` GitHub Environment with required
independent reviewers, prevent self-review, restrict deployments to the protected default branch,
and do not allow repository contributors to administer that Environment.

The workflow takes an immutable artifact ID, its owning workflow run ID, and either `prepare` or
`finalize`. It downloads exactly one root-level file named `release-encryption-evidence.json` by
artifact ID. Artifact names and repository paths are not accepted as subject selectors. The bundle
remains untrusted: the verifier still rejects embedded trust, checks the externally bound source
commit/workflow/materials, and does not execute any artifact content.

Provision these Environment secrets from the external control plane:

| Environment secret | Protected value |
|---|---|
| `RELEASE_ENCRYPTION_DEPLOYMENT_SUBJECT_B64` | Base64 of the external deployment subject |
| `RELEASE_ENCRYPTION_TRUST_STORE_B64` | Base64 of the external trust store |
| `RELEASE_ENCRYPTION_KEYRING_B64` | Base64 of the external public/HMAC keyring |
| `RELEASE_ENCRYPTION_REPLAY_STATE_B64` | Base64 of the authenticated current replay state |
| `RELEASE_ENCRYPTION_EXPECTED_TENANT_ID` | Expected tenant |
| `RELEASE_ENCRYPTION_EXPECTED_ENVIRONMENT` | Expected deployment environment |
| `RELEASE_ENCRYPTION_EXPECTED_TRUST_STORE_ID` | Expected trust-store identity |
| `RELEASE_ENCRYPTION_EXPECTED_TRUST_ROOT_ID` | Expected tenant/environment root identity |
| `RELEASE_ENCRYPTION_REPLAY_ANCHOR_SHA256` | Value read from the independent external monotonic CAS |

The workflow decodes the protected values into owner-only files under `RUNNER_TEMP`, verifies the
bundle, independently rechecks the portable report HMAC against the external keyring, stages only
the report, replay state, and checksums, and removes the deployment subject, trust store, keyring,
and working replay state before invoking the pinned upload action. It requests only `contents: read`
and `actions: read`; it has no ID-token, attestation, package, or signing permission.

In `prepare`, exit code 1 is the only accepted verifier result. The report must be authenticated,
must name the externally supplied old anchor, and must contain `anchor_update_required: true` and
`compliance_asserted: false`. The workflow uploads the report and authenticated next replay state,
then its separate `enforce-compliance` job fails intentionally. A failed phase-one workflow is not a
waiver; it is the expected signal that the external CAS transition is still pending.

The external controller must authenticate the report, compare its old value to
`replay_state_previous_sha256`, perform an atomic CAS from old to
`replay_state_next_sha256`, and only on success replace the protected replay-state secret and anchor
secret with those exact phase-one outputs. Updating a GitHub Environment secret by itself is not the
CAS and must never be used as one. If the CAS reports a different current value, stop and investigate;
do not overwrite it or derive a new expected value from the downloaded replay file.

Run `finalize` with the same artifact run ID, artifact ID, and exact bundle bytes. The workflow only
succeeds when the local replay-state digest equals the newly injected external anchor, the verifier
recognizes the exact authenticated transition without applying it again, the report HMAC validates,
and `compliance_asserted` is true. Re-running this exact finalization is idempotent. Replaying the
transition after a newer sequence, restoring a prior valid-MAC snapshot while the external anchor is
newer, or selecting `finalize` before the CAS all fail closed.
