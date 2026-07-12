# Encryption at rest and in transit

`infra/security/encryption-policy.json` is the repository-anchored policy for encryption controls.
It requires TLS 1.3 or newer at external boundaries, no external plaintext endpoints,
AES-256-class protection for persistent data, and Vault-compatible key management. Local
development exemptions are not production permissions.

## Evidence boundary

There are two distinct controls:

1. A deployment attestor observes the deployed resources, endpoints, KMS authorities, CA chains,
   image digests, and rollout configuration. It emits the structured at-rest and in-transit claims.
2. `scripts/ci/verify_release_encryption_evidence.py` verifies that those claims are complete for
   every active policy component, bound to the exact deployment and policy hashes, issued by the
   configured principal, authenticated by external keys, current, and replay/rollback safe.

The verifier does not probe a cluster, storage provider, KMS, or TLS endpoint. A successful report
therefore means that a trusted attestor made a cryptographically authenticated, policy-complete
observation. It is not independent live-service evidence. The attestor's implementation and its
access to deployment APIs remain part of the trust boundary.

At-rest evidence must identify every active policy component, report zero unencrypted persistent
resources, enumerate the exact policy algorithms, identify allowed KMS authorities, and bind the
attestation evidence digest as a provenance material. In-transit evidence must identify every active
component endpoint, report zero plaintext external endpoints, meet the policy TLS minimum, validate
the peer chains against externally trusted CA hashes, and bind its evidence digest as a provenance
material.

## PostgreSQL CA and rollout evidence

The external deployment subject records PostgreSQL TLS configuration explicitly:

- Kubernetes Secret resource UID, name, and CA data key;
- SHA-256 of the CA bundle;
- absolute file mount path whose basename equals the CA key;
- `sub_path: true`, preventing a directory mount from hiding sibling secret files;
- rollout revision equal to the deployment revision; and
- rollout SHA-256 included as the `postgres-ca-rollout` provenance material.

The in-transit attestation must observe the same CA bundle hash. The upstream attestor must read the
actual Secret identity and workload rollout from the deployment API; merely copying desired values
from a manifest does not constitute a runtime observation. CA rotation must create a new deployment
subject and new signed evidence. No release is compliant until the new rollout passes the external
anchor finalization described in `release-encryption-evidence.md`.

## Fail-closed behavior

Missing controls, incomplete component sets, an untrusted CA or KMS authority, policy/schema/hash
drift, stale observations, an invalid signature, a bad HMAC commitment, an unfinished key overlap,
or an unfinalized anti-rollback anchor all produce `compliance_asserted: false`. Static policy
validation alone must never be presented as proof that encryption is active in a deployment.

See `docs/security/release-encryption-evidence.md` for the trust files, canonical authentication,
two-phase anti-rollback protocol, report authentication, and rotation procedure.

For the operational controller path, dispatch `.github/workflows/verify-release-encryption.yml`
from the protected default branch with the immutable evidence artifact ID. Its `prepare` run exports
an authenticated replay-state transition but deliberately ends non-compliant; only a later
`finalize` run after an independent external CAS may succeed. Repository files, artifact names, and
locally recomputed replay-state hashes are never accepted as replacement trust roots or anchors.
