ARG GO_BUILDER_IMAGE=golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
ARG RUNTIME_IMAGE=alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM ${GO_BUILDER_IMAGE} AS seaweedfs-builder

ARG SEAWEEDFS_VERSION=4.29
ARG SEAWEEDFS_COMMIT=1355c7a102194d6c461baf090eff50367b575afb
ARG SEAWEEDFS_SOURCE_SHA256=d4ec97a7eda952296913fbfdcb3aefc62546fb80da7ad06f8e0c85f59474c6ed

ENV CGO_ENABLED=0 \
    GOFLAGS=-buildvcs=false \
    SOURCE_DATE_EPOCH=1779753600

WORKDIR /src

RUN wget -q -O /tmp/seaweedfs.tar.gz \
      "https://codeload.github.com/seaweedfs/seaweedfs/tar.gz/${SEAWEEDFS_COMMIT}" \
    && echo "${SEAWEEDFS_SOURCE_SHA256}  /tmp/seaweedfs.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/seaweedfs.tar.gz --strip-components=1 \
    && rm /tmp/seaweedfs.tar.gz \
    && test -f weed/weed.go \
    && test "$(go list -m)" = "github.com/seaweedfs/seaweedfs"

# Upstream mini propagates -ip.bind to Master/Filer/Volume/S3/WebDAV but its
# Admin HTTP and worker-gRPC listeners still use ":port". Harden the derivative
# to loopback those two otherwise-unauthenticated control-plane listeners.
RUN test "$(grep -F -c 'addr := fmt.Sprintf(":%d", *options.port)' weed/command/admin.go)" = "1" \
    && sed -i 's/addr := fmt.Sprintf(":%d", \*options.port)/addr := fmt.Sprintf("127.0.0.1:%d", *options.port)/' weed/command/admin.go \
    && test "$(grep -F -c 'listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))' weed/admin/dash/worker_grpc_server.go)" = "1" \
    && sed -i 's/net.Listen("tcp", fmt.Sprintf(":%d", port))/net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))/' weed/admin/dash/worker_grpc_server.go \
    && grep -Fq 'addr := fmt.Sprintf("127.0.0.1:%d", *options.port)' weed/command/admin.go \
    && grep -Fq 'net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))' weed/admin/dash/worker_grpc_server.go \
    && ! grep -Fq 'addr := fmt.Sprintf(":%d", *options.port)' weed/command/admin.go \
    && ! grep -Fq 'net.Listen("tcp", fmt.Sprintf(":%d", port))' weed/admin/dash/worker_grpc_server.go

# SeaweedFS 4.29 shipped with vulnerable Go 1.25.10, x/net 0.54.0,
# x/image 0.39.0, and a replacement that forced Thrift 0.22.0. Build the
# immutable upstream commit with fixed, exact dependency versions and verify
# the resulting module graph before compilation.
RUN go mod edit -dropreplace=github.com/apache/thrift \
    && go mod edit -require=github.com/apache/thrift@v0.23.0 \
    && go mod edit -require=golang.org/x/net@v0.55.0 \
    && go mod edit -require=golang.org/x/image@v0.43.0 \
    && go mod download all \
    && go mod verify \
    && test "$(go list -m -f '{{.Version}}' github.com/apache/thrift)" = "v0.23.0" \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/net)" = "v0.55.0" \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/image)" = "v0.43.0"

RUN mkdir -p /out \
    && go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o /out/weed.first ./weed \
    && go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o /out/weed.second ./weed \
    && cmp /out/weed.first /out/weed.second \
    && mv /out/weed.first /out/weed \
    && rm /out/weed.second \
    && go version -m /out/weed | awk '$1 == "dep" && $2 == "github.com/apache/thrift" && $3 == "v0.23.0" { found=1 } END { exit !found }' \
    && go version -m /out/weed | awk '$1 == "dep" && $2 == "golang.org/x/net" && $3 == "v0.55.0" { found=1 } END { exit !found }' \
    && go version -m /out/weed | awk '$1 == "dep" && $2 == "golang.org/x/image" && $3 == "v0.43.0" { found=1 } END { exit !found }'

COPY infra/docker/seaweedfs_launcher.go /launcher/seaweedfs_launcher.go

RUN go build -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o /out/seaweedfs-launcher.first /launcher/seaweedfs_launcher.go \
    && go build -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o /out/seaweedfs-launcher.second /launcher/seaweedfs_launcher.go \
    && cmp /out/seaweedfs-launcher.first /out/seaweedfs-launcher.second \
    && mv /out/seaweedfs-launcher.first /out/seaweedfs-launcher \
    && rm /out/seaweedfs-launcher.second

FROM ${RUNTIME_IMAGE}

ARG SEAWEEDFS_VERSION=4.29
ARG SEAWEEDFS_COMMIT=1355c7a102194d6c461baf090eff50367b575afb

LABEL org.opencontainers.image.title="Hallu Defense SeaweedFS" \
      org.opencontainers.image.description="Reproducible non-root SeaweedFS S3-compatible runtime" \
      org.opencontainers.image.source="https://github.com/seaweedfs/seaweedfs" \
      org.opencontainers.image.version="${SEAWEEDFS_VERSION}" \
      org.opencontainers.image.revision="${SEAWEEDFS_COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV GODEBUG=fips140=on

RUN addgroup -S -g 10001 seaweedfs \
    && adduser -S -D -H -u 10001 -G seaweedfs seaweedfs \
    && install -d -m 0700 -o 10001 -g 10001 /data

COPY --from=seaweedfs-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=seaweedfs-builder --chmod=0555 /out/weed /usr/local/bin/weed
COPY --from=seaweedfs-builder --chmod=0555 /out/seaweedfs-launcher /usr/local/bin/seaweedfs-launcher

USER 10001:10001
VOLUME ["/data"]
EXPOSE 9000

ENTRYPOINT ["/usr/local/bin/seaweedfs-launcher"]
CMD ["mini", "-dir=/data", "-s3.port=9000", "-bucket=hallu-backups,hallu-primary,hallu-backup-replica"]
