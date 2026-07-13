# syntax=docker/dockerfile:1.7

FROM golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113 AS builder

ARG OCB_VERSION=0.156.0
ENV GOTOOLCHAIN=local
ENV GOPROXY=https://proxy.golang.org
ENV GOSUMDB=sum.golang.org

WORKDIR /src
COPY infra/docker/otel-collector-builder.yaml /src/builder.yaml
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" \
      "go.opentelemetry.io/collector/cmd/builder@v${OCB_VERSION}" \
    && test "$(go version | awk '{print $3}')" = "go1.26.5" \
    && /go/bin/builder --config /src/builder.yaml \
    && test -x /src/_build/otelcol-contrib \
    && echo "f2de43b6617e9c5c88da5265733bd14a937545f766d8a1ab00ddec156390765e  /src/_build/otelcol-contrib" \
      | sha256sum --check --strict \
    && cp /src/_build/otelcol-contrib /out-otelcol-contrib

FROM otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108 AS official

FROM scratch
USER 10001:10001
COPY --from=official /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=official /etc/otelcol-contrib/config.yaml /etc/otelcol-contrib/config.yaml
COPY --from=builder --chmod=0555 /out-otelcol-contrib /otelcol-contrib
ENTRYPOINT ["/otelcol-contrib"]
CMD ["--config", "/etc/otelcol-contrib/config.yaml"]
EXPOSE 4317 4318 55679
LABEL org.opencontainers.image.source="https://github.com/open-telemetry/opentelemetry-collector" \
      org.opencontainers.image.revision="v0.156.0-modules" \
      org.opencontainers.image.version="0.156.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.hallu-defense.rebuilt-go-version="1.26.5" \
      io.hallu-defense.upstream-image="otel/opentelemetry-collector-contrib:0.156.0@sha256:125bdbeb7590cc1952c5b3430ecf14063568980c2c93d5b38676cc0446ed8108"
