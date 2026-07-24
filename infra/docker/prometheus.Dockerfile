FROM golang:1.26.5-trixie@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS prometheus-builder

ARG PROMETHEUS_REPOSITORY=https://github.com/prometheus/prometheus.git
ARG PROMETHEUS_TAG=v3.13.1
ARG PROMETHEUS_COMMIT=73ff57ce2b8161059ac7fe5188f03f1c3d22b29a
ARG PROMETHEUS_VERSION=3.13.1
ARG PROMETHEUS_BUILD_DATE=20260710-08:03:47
ARG GRPC_GO_VERSION=v1.82.1
ENV GOPROXY=https://proxy.golang.org
ENV GOSUMDB=sum.golang.org

RUN git init /src/prometheus \
    && git -C /src/prometheus remote add origin "${PROMETHEUS_REPOSITORY}" \
    && git -C /src/prometheus fetch --depth=1 origin "refs/tags/${PROMETHEUS_TAG}:refs/tags/${PROMETHEUS_TAG}" \
    && test "$(git -C /src/prometheus rev-parse "refs/tags/${PROMETHEUS_TAG}^{commit}")" = "${PROMETHEUS_COMMIT}" \
    && git -C /src/prometheus checkout --detach "${PROMETHEUS_COMMIT}"

WORKDIR /src/prometheus
RUN go mod edit -require=google.golang.org/grpc@${GRPC_GO_VERSION} \
    && go mod tidy \
    && go mod verify \
    && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "${GRPC_GO_VERSION}" \
    && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false \
       -ldflags="-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}" \
       -o /out/prometheus ./cmd/prometheus \
    && CGO_ENABLED=0 go build -tags=netgo,builtinassets -mod=readonly -trimpath -buildvcs=false \
       -ldflags="-s -w -X github.com/prometheus/common/version.Version=${PROMETHEUS_VERSION} -X github.com/prometheus/common/version.Revision=${PROMETHEUS_COMMIT} -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=HalluDefense@reproducible -X github.com/prometheus/common/version.BuildDate=${PROMETHEUS_BUILD_DATE}" \
       -o /out/promtool ./cmd/promtool \
    && test "$(go version /out/prometheus)" = "/out/prometheus: go1.26.5" \
    && test "$(go version /out/promtool)" = "/out/promtool: go1.26.5" \
    && test "$(go version -m /out/prometheus | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "${GRPC_GO_VERSION}" \
    && test "$(go version -m /out/promtool | awk '$1 == "dep" && $2 == "google.golang.org/grpc" { print $3 }')" = "${GRPC_GO_VERSION}" \
    && ! go version -m /out/prometheus | grep -F "google.golang.org/grpc v1.81.1" \
    && ! go version -m /out/promtool | grep -F "google.golang.org/grpc v1.81.1" \
    && /out/prometheus --version 2>&1 | grep -F "prometheus, version 3.13.1" \
    && /out/prometheus --version 2>&1 | grep -F "revision: ${PROMETHEUS_COMMIT}" \
    && /out/promtool --version 2>&1 | grep -F "promtool, version 3.13.1"

FROM prom/prometheus:v3.13.1-distroless@sha256:214f8427c8fba80c327bb94a75feb802ae12f2d6ca30812aa6e7d22f09bbea80

LABEL org.opencontainers.image.source="https://github.com/Chocarlos/hallu-defense-platform" \
      org.opencontainers.image.description="Prometheus 3.13.1 rebuilt with grpc-go 1.82.1" \
      hallu-defense.prometheus.source-commit="73ff57ce2b8161059ac7fe5188f03f1c3d22b29a" \
      hallu-defense.prometheus.grpc-go="v1.82.1"

COPY --from=prometheus-builder --chmod=0555 /out/prometheus /bin/prometheus
COPY --from=prometheus-builder --chmod=0555 /out/promtool /bin/promtool

USER 65532:65532
