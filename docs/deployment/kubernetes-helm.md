# Kubernetes Helm Deployment

The Helm scaffold lives at `infra/k8s/helm/hallu-defense`. It is intended for
kind validation and deployment iteration, not as a finished managed Kubernetes
runbook.

The chart includes api, console, and worker deployment templates, a migration
Job that runs `scripts/dev/apply_postgres_migrations.py`, secret templates, and
single-replica pgvector and OpenSearch kind defaults. The worker template
defaults to `worker.enabled=true` because the Batch 6 ingestion worker runtime
is now part of the charted runtime.
Roadmap dependency marker: Batch 6 ingestion worker runtime.

Static invariants enforced by `scripts/ci/check_helm_chart.py`:

- non-root pod/container security contexts;
- disabled privilege escalation and dropped capabilities;
- resources requests/limits;
- liveness and readiness probes;
- production fail-closed API env (`oidc_jwt`, Vault, PostgreSQL backends,
  Docker sandbox, OTLP);
- secretKeyRef usage with empty secret defaults in `values.yaml`;
- Prometheus scrape annotations on the API pod;
- pgvector and OpenSearch kind defaults.

Run the static check:

```text
python scripts/ci/check_helm_chart.py
```

If Helm is installed, the checker also runs:

```text
helm template hallu-defense infra/k8s/helm/hallu-defense
```

with synthetic non-default secret values so the worker template is rendered. If
Helm is unavailable, the checker reports a skip for the
template phase after static validation passes.

`scripts/dev/live_kind_helm_smoke.py` is also env-gated. It skips unless
`HALLU_DEFENSE_LIVE_KIND_HELM_SMOKE_ENABLED=true`, and then requires `kind`,
`kubectl`, and `helm` on `PATH`.
