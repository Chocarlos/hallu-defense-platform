# syntax=docker/dockerfile:1.7

FROM golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113 AS builder

ARG SOURCE_TAG=v0.156.0
ARG SOURCE_COMMIT=aa158b23c8f89d795b21a05a49b3978565dfebd4
ARG OBI_SHA256=151ef5d04bff9660743148ff20d5c833222b0b45ab15245a2968a3f7f4366dec
ENV GOTOOLCHAIN=local
ENV GOPROXY=https://proxy.golang.org
ENV GOSUMDB=sum.golang.org

WORKDIR /src
RUN git init . \
    && git remote add origin https://github.com/open-telemetry/opentelemetry-collector-releases.git \
    && git fetch --depth=1 origin "refs/tags/${SOURCE_TAG}:refs/tags/${SOURCE_TAG}" \
    && test "$(git rev-parse "refs/tags/${SOURCE_TAG}^{commit}")" = "${SOURCE_COMMIT}" \
    && git checkout --detach "${SOURCE_COMMIT}"
RUN mkdir -p .local \
    && curl --fail --show-error --location --retry 3 \
      --output .local/obi-v0.10.0-source-generated.tar.gz \
      https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/download/v0.10.0/obi-v0.10.0-source-generated.tar.gz \
    && echo "${OBI_SHA256}  .local/obi-v0.10.0-source-generated.tar.gz" | sha256sum --check --strict
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    make build DISTRIBUTIONS=otelcol-contrib \
    && test -x distributions/otelcol-contrib/_build/otelcol-contrib \
    && test "$(go version | awk '{print $3}')" = "go1.26.5" \
    && echo "303a747584810d6259a8e3a4547275761136fafbd31e4413f62cf9189e9d8b3d  distributions/otelcol-contrib/_build/otelcol-contrib" \
      | sha256sum --check --strict \
    && cp distributions/otelcol-contrib/_build/otelcol-contrib /out-otelcol-contrib

FROM otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108 AS official

FROM scratch
USER 10001:10001
COPY --from=official /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=official /etc/otelcol-contrib/config.yaml /etc/otelcol-contrib/config.yaml
COPY --from=builder --chmod=0555 /out-otelcol-contrib /otelcol-contrib
ENTRYPOINT ["/otelcol-contrib"]
CMD ["--config", "/etc/otelcol-contrib/config.yaml"]
EXPOSE 4317 4318 55679
LABEL org.opencontainers.image.source="https://github.com/open-telemetry/opentelemetry-collector-releases" \
      org.opencontainers.image.revision="aa158b23c8f89d795b21a05a49b3978565dfebd4" \
      org.opencontainers.image.version="0.156.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.hallu-defense.rebuilt-go-version="1.26.5" \
      io.hallu-defense.upstream-image="otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108"
