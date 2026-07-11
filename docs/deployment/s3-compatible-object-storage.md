# S3-Compatible Object Storage

Local Compose keeps the service/DNS name `minio` and the public
`HALLU_DEFENSE_*MINIO*` environment variables for compatibility, but its
implementation is SeaweedFS 4.29 built by `infra/docker/seaweedfs.Dockerfile`.
Production Compose continues to remove this local dependency and requires an
operator-managed HTTPS S3-compatible service.

## Reproducible image

The first-party build fixes all inputs that affect the runtime:

- upstream tag `4.29`, commit
  `1355c7a102194d6c461baf090eff50367b575afb`, and codeload archive SHA-256
  `d4ec97a7eda952296913fbfdcb3aefc62546fb80da7ad06f8e0c85f59474c6ed`;
- Go builder `1.26.4-alpine3.24` and Alpine 3.24 runtime, both by OCI digest;
- `golang.org/x/net` 0.55.0 and `github.com/apache/thrift` 0.23.0;
- `CGO_ENABLED=0`, trimmed paths, disabled VCS stamping, and an empty Go build
  ID; and
- two independent binary outputs compared with `cmp` in the build stage.

The derivative also changes the two upstream Admin listeners that ignore
`-ip.bind`: Admin HTTP and worker gRPC are compiled to listen on loopback. The
build verifies the exact upstream source lines before and after this change, so
an upstream source drift fails instead of silently dropping the hardening.

The final image contains Alpine, the CA bundle, `/usr/local/bin/weed`, and the
small first-party `/usr/local/bin/seaweedfs-launcher`. Both Go programs are
built twice and compared byte-for-byte. The image runs as UID/GID 10001, owns
only `/data`, and exposes the S3-compatible endpoint on container port 9000.
Compose adds a read-only root filesystem, a bounded `/tmp` tmpfs,
`cap_drop: [ALL]`, and `no-new-privileges`.

The upstream image baseline was scanned with Trivy 0.72.0 and had nine HIGH
findings: three Alpine packages plus vulnerable Go stdlib, `x/net`, and Thrift
modules. The rebuilt image scan reported zero HIGH and zero CRITICAL OS/library
findings. CI rebuilds and scans the first-party image; it does not allow the
upstream runtime image as a deployment source.

## Runtime contract

SeaweedFS starts in single-node `mini` mode with S3 on port 9000. The following
buckets are created before serving local workloads:

- `hallu-backups`
- `hallu-primary`
- `hallu-backup-replica`

The launcher accepts only the committed Compose argument vector. It starts
SeaweedFS with `-ip=127.0.0.1` and `-ip.bind=127.0.0.1`, keeps S3 itself on
loopback port 8333, disables the embedded IAM API, requests Iceberg port zero,
and proxies only authenticated S3 traffic on `0.0.0.0:9000`. If the upstream
`mini` port allocator starts Iceberg anyway, it remains a
loopback-only internal listener. Filer, Admin, Master, Volume, WebDAV, Iceberg,
and their related gRPC listeners therefore cannot be reached from another
container on the Compose network.

Credentials are provided to SeaweedFS through `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. Existing Hallu Defense scripts keep their MinIO-named
variables and translate them to SigV4 requests; callers do not need a contract
rename. Host-side drills default to `http://127.0.0.1:9000`, while containers on
the Compose network use `http://minio:9000`.

`scripts/dev/s3_sigv4.py` is the operational client. It signs payload hashes,
uses path-style requests, streams uploads/downloads, bounds listing XML and
pagination, validates every listed key before a prefix deletion begins, does
not follow redirects, does not retry writes implicitly, applies one monotonic
deadline across every response read, and redacts response bodies and
credentials from exceptions. POSIX downloads use exclusive creation and mode
0600. Windows downloads are created atomically with a protected DACL granting
full control only to the current user, SYSTEM, and built-in administrators.

Production/staging clients require HTTPS and an exact origin in
`HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS`. DNS is resolved once per
connection, every returned address must be globally routable, and the validated
address is pinned for the connection while TLS still verifies the configured
hostname. Loopback, private, link-local, metadata, and other non-global targets
are rejected. Literal/private endpoints are available only in the explicit
local/test mode used by Compose.

## Persistence and migration boundary

SeaweedFS persists `/data` in the `seaweedfs-data` volume. The former MinIO
`minio-data` volume must not be mounted into SeaweedFS: the on-disk formats are
not compatible. The new Compose volume name makes accidental reinterpretation
impossible and leaves an existing MinIO volume untouched for rollback or an
explicit S3-level export.

This embedded backend is local-development infrastructure, so there is no
production volume conversion in the production profile. If a non-local MinIO
deployment is migrated, copy and verify objects through both products' S3 APIs
before changing DNS, retain the source read-only through the rollback window,
and compare bucket, key, size, and cryptographic checksum inventories. Never
copy MinIO data files directly into `/data`.

## Verification

The focused live verification uses an isolated container, network, port, and
volume. It must prove:

1. from a second container, all three buckets are reachable with SigV4 while
   Filer, Admin, Master, Volume, WebDAV, and Iceberg ports are unreachable;
2. put/get/list parity;
3. the same object is readable after a container restart with the same volume;
4. delete followed by an empty prefix listing;
5. the encrypted tenant-scoped replica/restore drill passes and cleans both
   synthetic prefixes; and
6. runtime UID, read-only root filesystem, dropped capabilities, and
   `no-new-privileges` match the Compose contract.

Do not use an anonymous request or an HTTP health response as evidence of S3
readiness; readiness is an authenticated, bounded list operation.
