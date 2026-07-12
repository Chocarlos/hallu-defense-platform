# Coordinated Key and Trust-Root Rotation

Rotations are deployments, not isolated secret writes. Each change needs an explicit
epoch, bounded overlap, versioned external trust material, a full workload rollout,
and evidence bound to the exact deployment hashes. Never put private keys, bearer
tokens, trust roots, verification policy, or schemas inside a claimed evidence bundle.

## Approval HMAC commitment

Follow the three-rollout K1/K2 procedure in [approvals.md](approvals.md). The runtime
requires `HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_PREVIOUS_VALID_UNTIL` whenever a
previous secret and opaque key ID are configured, rejects partial inputs and windows
longer than seven days, and will not issue a K1-bound execution grant that expires
after the overlap. New v3 commitments use K2 and bind the approval ID, origin trace,
tenant, subject, normalized environment, trusted tool/action/arguments/definition,
algorithm, and operator-selected key ID. Key IDs are public labels and must never be
derived from key material. Before removing K1, reject and reissue all K1 pending
approvals and prove all K1 grants were consumed or expired.

## PostgreSQL CA and `subPath`

The API, worker, migration job, and startup preflight use
`HALLU_DEFENSE_POSTGRES_CA_CERT_PATH`; production DSNs must retain
`sslmode=verify-full` and the same `sslrootcert` path. Kubernetes mounts the selected
Secret key as a read-only file with `subPath`. A `subPath` mount does not receive an
in-place Secret projection update, so mutating one Secret is not a completed rotation.

Use this order:

1. Create an externally governed, versioned CA bundle containing the currently trusted
   issuer and the candidate issuer. Record its SHA-256 and CA certificate fingerprints
   outside the application evidence bundle; never include a CA private key.
2. Create a new versioned Kubernetes Secret and select the exact key. Update the
   deployment configuration to that Secret name/key, CA path, and expected bundle hash.
3. Roll out every API and worker replica and run the migration preflight/job. Because
   of `subPath`, verify each new pod UID and the mounted-file SHA-256; an unchanged pod
   cannot be counted as rotated. Abort if any replica or migration job still uses the
   previous deployment hash or cannot verify PostgreSQL hostname and chain.
4. Rotate the PostgreSQL server certificate, then exercise new TLS connections from
   every workload. After the old issuer has no live clients, publish a second versioned
   bundle without it and repeat the full rollout before deleting the old Secret.

The release evidence must bind tenant, environment, source commit, workflow identity,
deployment manifest hash, image digests, Secret resource identity/name/key, CA bundle
hash, rotation epoch, nonce, sequence, and validity window. Trust-store lookup stays
external. Rollback means deploying a separately signed, higher-sequence statement for
an approved prior manifest; lowering the sequence is rejected by the external CAS
anchor. The authenticated local state also rejects nonces retained in its bounded
recent-nonce window; it is not an unbounded global nonce ledger.

## Metrics scrape credential

The minimal Vault-to-file configuration and sidecar/systemd patterns are documented in
[metrics-bearer-token-materializer.md](../deployment/metrics-bearer-token-materializer.md).
The materializer atomically replaces a mode-`0600` file and retains the prior complete
file on refresh failure. A rotation is complete only after a successful refresh and an
authenticated scrape; logs and metrics must not contain the credential or its digest.

## Evidence and abort criteria

Every rotation aborts on an unverifiable signature, unknown trust-root identifier,
expired timestamp, excessive clock skew, tenant/environment mismatch, deployment hash
mismatch, a foreign/mixed replay-state binding, a nonce in the recent cache,
non-monotonic sequence/CAS, a nonadjacent retiring epoch, overlap violation, partial rollout,
or missing live connectivity evidence. In all those cases `compliance_asserted` remains
`false`; an operator assertion or CLI path override cannot turn absence of attestation
into compliance.
