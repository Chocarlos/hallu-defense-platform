# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc
ARG NODE_IMAGE=node:20-alpine3.23@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
ARG VAULT_IMAGE=hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54
ARG VAULT_COMMIT=7193f9a48ff6093ca61b3b627a8671e770428ba6
ARG VAULT_SOURCE_SHA256=7a12e6300ea17de23b1d533ff6452ed18802b9efa5b075dd1135ea1ded7b307b

FROM ${GO_IMAGE} AS source
ARG VAULT_COMMIT
ARG VAULT_SOURCE_SHA256
ADD --checksum=sha256:${VAULT_SOURCE_SHA256} \
    https://github.com/hashicorp/vault/archive/${VAULT_COMMIT}.tar.gz \
    /tmp/vault.tar.gz
RUN mkdir -p /src/vault \
    && tar -xzf /tmp/vault.tar.gz -C /src/vault --strip-components=1 \
    && rm /tmp/vault.tar.gz \
    && grep -qx 'module github.com/hashicorp/vault' /src/vault/go.mod \
    && test "$(cat /src/vault/.go-version)" = "1.26.4"

FROM ${NODE_IMAGE} AS ui
WORKDIR /src/vault
COPY --from=source /src/vault/ ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store,sharing=locked \
    corepack enable \
    && cd ui \
    && pnpm install --frozen-lockfile \
    && npm rebuild node-sass \
    && pnpm run build \
    && test -s ../http/web_ui/index.html

FROM source AS builder
ARG VAULT_COMMIT
WORKDIR /src/vault
COPY --from=ui /src/vault/http/web_ui ./http/web_ui
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    test "$(go env GOVERSION)" = "go1.26.5" \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false -tags=ui \
        -ldflags="-X github.com/hashicorp/vault/version.GitCommit=${VAULT_COMMIT} -X github.com/hashicorp/vault/version.BuildDate=2026-06-17T12:39:45Z -X github.com/hashicorp/vault/version.Version=2.0.3 -X github.com/hashicorp/vault/version.VersionMetadata=" \
        -o /out/vault . \
    && test "$(go version /out/vault)" = "/out/vault: go1.26.5" \
    && /out/vault version | grep -F 'Vault v2.0.3' \
    && test "$(wc -c < http/web_ui/index.html)" -gt 1000000

FROM ${VAULT_IMAGE} AS patched
COPY --from=builder --chmod=0555 /out/vault /bin/vault
RUN /bin/vault version | grep -F 'Vault v2.0.3' \
    && test "$(find /vault -maxdepth 2 -type f | wc -l)" -ge 1

FROM scratch
COPY --from=patched / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV NAME=vault
USER vault
WORKDIR /
EXPOSE 8200
VOLUME ["/vault/file", "/vault/logs"]
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-dev"]
LABEL name="Vault" \
      version="2.0.3" \
      release="7193f9a48ff6093ca61b3b627a8671e770428ba6" \
      revision="7193f9a48ff6093ca61b3b627a8671e770428ba6" \
      vendor="HashiCorp" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      summary="Vault is a tool for securely accessing secrets." \
      description="Vault is a tool for securely accessing secrets with tightly controlled access and an audit log." \
      io.hallu-defense.rebuilt-go-version="1.26.5" \
      io.hallu-defense.upstream-image="hashicorp/vault:2.0.3@sha256:a296a888b118615dc01d5f1a6846e6d4a7277946caaed5b447008fff5fe06b54"
