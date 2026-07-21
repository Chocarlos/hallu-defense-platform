FROM golang:1.26.5-trixie@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS opa-builder

ARG OPA_REPOSITORY=https://github.com/open-policy-agent/opa.git
ARG OPA_TAG=v1.18.2
ARG OPA_COMMIT=e695c9ef8edb0f8b9f13d014d7bc8a7fbcc57297
ARG OPA_SOURCE_TIMESTAMP=2026-07-02T13:31:31Z
ENV GOPROXY=https://proxy.golang.org
ENV GOSUMDB=sum.golang.org

COPY infra/docker/opa-no-oci.patch /tmp/opa-no-oci.patch
RUN git init /src/opa \
    && git -C /src/opa remote add origin "${OPA_REPOSITORY}" \
    && git -C /src/opa fetch --depth=1 origin "refs/tags/${OPA_TAG}:refs/tags/${OPA_TAG}" \
    && test "$(git -C /src/opa rev-parse "refs/tags/${OPA_TAG}^{commit}")" = "${OPA_COMMIT}" \
    && git -C /src/opa checkout --detach "${OPA_COMMIT}" \
    && git -C /src/opa apply --check /tmp/opa-no-oci.patch \
    && git -C /src/opa apply /tmp/opa-no-oci.patch
WORKDIR /src/opa
RUN go mod edit \
        -require=golang.org/x/crypto@v0.52.0 \
        -require=golang.org/x/net@v0.55.0 \
        -require=golang.org/x/sys@v0.45.0 \
    && go mod tidy \
    && go mod verify \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/crypto)" = "v0.52.0" \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/net)" = "v0.55.0" \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/sys)" = "v0.45.0" \
    && CGO_ENABLED=0 go build -tags=opa_no_oci -mod=readonly -trimpath -buildvcs=false \
        -ldflags="-s -w -X github.com/open-policy-agent/opa/v1/version.Vcs=${OPA_COMMIT} -X github.com/open-policy-agent/opa/v1/version.Timestamp=${OPA_SOURCE_TIMESTAMP} -X github.com/open-policy-agent/opa/v1/version.Hostname=reproducible" \
        -o /out/opa . \
    && test "$(go version /out/opa)" = "/out/opa: go1.26.5" \
    && ! go version -m /out/opa | grep -F "oras.land/oras-go" \
    && /out/opa version | grep -F "Version: 1.18.2" \
    && /out/opa version | grep -F "Build Commit: ${OPA_COMMIT}" \
    && /out/opa version | grep -F "Go Version: go1.26.5"

FROM python:3.12.13-alpine3.24@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SOURCE_DATE_EPOCH=1767225600
ENV PYTHONHASHSEED=0

WORKDIR /workspace
COPY requirements/python/runtime-linux-py312.lock /workspace/requirements/python/runtime-linux-py312.lock
COPY requirements/python/build-tools-linux-py312.lock /workspace/requirements/python/build-tools-linux-py312.lock
RUN test "$(python --version)" = "Python 3.12.13" \
    && python -m pip download --require-hashes --only-binary=:all: --no-deps \
      --dest /wheelhouse/build-tools \
      -r /workspace/requirements/python/build-tools-linux-py312.lock \
    && python -m pip install --no-cache-dir --no-index --no-deps --require-hashes \
      --find-links=/wheelhouse/build-tools \
      -r /workspace/requirements/python/build-tools-linux-py312.lock \
    && python -m pip download --require-hashes --only-binary=:all: --no-deps \
      --dest /wheelhouse/runtime \
      -r /workspace/requirements/python/runtime-linux-py312.lock
COPY apps/api/pyproject.toml /workspace/apps/api/pyproject.toml
COPY apps/api/src /workspace/apps/api/src
COPY scripts/ci/build_reproducible_wheel.py /workspace/scripts/ci/build_reproducible_wheel.py
RUN python /workspace/scripts/ci/build_reproducible_wheel.py \
      --output-dir /wheelhouse/application

FROM python:3.12.13-alpine3.24@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements/python/runtime-linux-py312.lock /tmp/runtime-linux-py312.lock
COPY --from=python-builder /wheelhouse/runtime /tmp/wheelhouse/runtime
COPY --from=python-builder /wheelhouse/application /tmp/wheelhouse/application
COPY scripts/dev/apply_postgres_migrations.py /app/scripts/dev/apply_postgres_migrations.py
COPY scripts/dev/bootstrap_opensearch_template.py /app/scripts/dev/bootstrap_opensearch_template.py
COPY scripts/dev/bootstrap_kind_vault.py /app/scripts/dev/bootstrap_kind_vault.py
COPY infra/rag/pgvector /app/infra/rag/pgvector
COPY infra/rag/opensearch /app/infra/rag/opensearch
COPY infra/opa/policies /app/infra/opa/policies
COPY --from=opa-builder /out/opa /usr/local/bin/opa
RUN chmod 0555 /usr/local/bin/opa \
    && /usr/local/bin/opa version \
    && /usr/local/bin/opa check --strict /app/infra/opa/policies
RUN test "$(python --version)" = "Python 3.12.13" \
    && python -m pip install --no-cache-dir --no-index --no-deps --require-hashes \
      --find-links=/tmp/wheelhouse/runtime -r /tmp/runtime-linux-py312.lock \
    && python -m pip install --no-cache-dir --no-index --no-deps \
      /tmp/wheelhouse/application/hallu_defense_api-0.1.0-py3-none-any.whl \
    && python -m pip check \
    && python -c "import hallu_defense; print(hallu_defense.__version__)" \
    && rm -rf /tmp/wheelhouse /tmp/runtime-linux-py312.lock
RUN adduser -D -u 10001 -s /sbin/nologin appuser \
    && mkdir -p /run/hallu-defense/kubernetes \
    && find /app -type d -exec chmod 0555 {} + \
    && find /app -type f -exec chmod 0444 {} + \
    && chmod 0555 /usr/local/bin/opa

EXPOSE 8000
USER appuser
CMD ["uvicorn", "hallu_defense.main:app", "--host", "0.0.0.0", "--port", "8000"]
