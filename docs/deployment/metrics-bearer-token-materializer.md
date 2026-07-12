# Prometheus Metrics Bearer Token Materializer

Prometheus reads the API scrape credential from
`/run/secrets/hallu_defense_metrics_bearer_token` through
`authorization.credentials_file`. The credential has one runtime source:
`HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME`, resolved by the configured
`SecretManager`. There is no token-value argument, environment fallback, or
second hardcoded value in the materializer.

Run a one-shot materialization after configuring the normal Vault settings:

```text
python scripts/dev/materialize_metrics_bearer_token.py
```

The minimum materializer-specific configuration is below. It is a subset of the
normal validated application settings; the workload may require additional shared
production settings, but it must not receive a raw metrics token:

```text
HALLU_DEFENSE_SECRETS_BACKEND=vault
HALLU_DEFENSE_VAULT_ADDR=https://vault.example.internal
HALLU_DEFENSE_VAULT_MOUNT=secret
HALLU_DEFENSE_VAULT_TOKEN_FILE=/run/secrets/hallu_defense_vault_token
HALLU_DEFENSE_VAULT_CA_CERT_PATH=/run/hallu-defense/vault/ca.crt
HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME=observability/metrics-scrape-token
```

The Vault address must be HTTPS, the CA and token paths must be absolute regular
files supplied by the platform, and the logical secret name is not secret material.
Do not add a token-value environment variable or CLI flag.

Run continuous rotation:

```text
python scripts/dev/materialize_metrics_bearer_token.py \
  --watch \
  --interval-seconds 60
```

The interval must remain between 1 and 3600 seconds. `SIGINT` and `SIGTERM`
request a clean exit. A transient Vault/read/write failure retains the prior
complete file and is retried on the next watch interval. Output contains only
generic status messages; neither the Vault token nor the metrics bearer token
is printed or included in exceptions.

For rotation, update the logical Vault value, wait for one successful refresh plus
one scrape, and verify only file metadata (owner, mode, modification time, and an
operator-side commitment). Never emit the credential or its digest as a metric. Keep
the previous Vault version recoverable until the new scrape succeeds, then revoke it.

## Filesystem Contract

The materializer is intentionally POSIX-only. It opens the destination
directory without following its final symlink, rejects group/world-writable
directories, rejects an existing symlink or non-regular destination, creates a
same-directory temporary file with mode `0600`, calls `fsync` on the file,
atomically replaces the destination, and then calls `fsync` on the directory.

Create `/run/secrets` as a real directory owned by the process identity shared
with Prometheus. It should normally be mode `0700`; do not solve access by
making it group/world writable. Because the credential file is `0600`, the
materializer and Prometheus must run with the same numeric UID.

## Kubernetes Sidecar Pattern

Use an `emptyDir` mounted at `/run/secrets` in both containers. An init
container should set ownership to the Prometheus numeric UID and mode `0700`.
Run the materializer sidecar and Prometheus with that same numeric UID. Mount
the volume read-write in the sidecar and read-only in Prometheus.

The sidecar command is the watch command above. Supply the existing application
settings, including `HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME`, the Vault
address/mount/namespace settings, and the Vault authentication token from the
platform secret injection mechanism. Do not pass the metrics token itself to
the pod specification.

The Helm chart still needs these deployment-only changes:

- a materializer sidecar using the API image and watch command;
- the shared `emptyDir` and `/run/secrets` mounts;
- an init container or equivalent ownership setup that produces mode `0700`;
- matching Prometheus/materializer `runAsUser` values;
- Vault configuration and authentication-token references for the sidecar;
- startup/readiness ordering that waits for the credentials file before the
  first authenticated scrape.

## systemd Pattern

Create the runtime directory with `tmpfiles.d`:

```text
d /run/secrets 0700 prometheus prometheus -
```

Run the watcher as the Prometheus identity:

```ini
[Unit]
Description=Materialize the Hallu Defense Prometheus scrape credential
Before=prometheus.service

[Service]
Type=simple
User=prometheus
Group=prometheus
EnvironmentFile=/etc/hallu-defense/metrics-materializer.env
ExecStart=/opt/hallu-defense/.venv/bin/python /opt/hallu-defense/scripts/dev/materialize_metrics_bearer_token.py --watch --interval-seconds 60
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

The environment file must be root-owned and must configure the logical secret
name and Vault access, not contain the metrics bearer token value. Prometheus
continues to reference only
`/run/secrets/hallu_defense_metrics_bearer_token`.
