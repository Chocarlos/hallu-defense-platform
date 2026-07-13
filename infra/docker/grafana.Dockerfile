FROM golang:1.26.5-trixie@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS backend-builder

ARG GRAFANA_COMMIT=b309c9bb3b81a748c3a75289236a27309ed2566a
ARG GRAFANA_SOURCE_DATE_EPOCH=1782199002
ARG TEMPO_COMMIT=4aeafc237b8d9a8d62e45735131e8a89eb741a00

RUN git init /src/grafana \
    && git -C /src/grafana remote add origin https://github.com/grafana/grafana.git \
    && git -C /src/grafana fetch --depth=1 origin "${GRAFANA_COMMIT}" \
    && git -C /src/grafana checkout --detach FETCH_HEAD \
    && test "$(git -C /src/grafana rev-parse HEAD)" = "${GRAFANA_COMMIT}" \
    && git init /src/tempo-v2.10.3-src \
    && git -C /src/tempo-v2.10.3-src remote add origin https://github.com/grafana/tempo.git \
    && git -C /src/tempo-v2.10.3-src fetch --depth=1 origin "${TEMPO_COMMIT}" \
    && git -C /src/tempo-v2.10.3-src checkout --detach FETCH_HEAD \
    && test "$(git -C /src/tempo-v2.10.3-src rev-parse HEAD)" = "${TEMPO_COMMIT}"

COPY infra/docker/grafana-tempo-2.10.3.patch /tmp/grafana-tempo-2.10.3.patch

RUN git -C /src/grafana apply --check /tmp/grafana-tempo-2.10.3.patch \
    && git -C /src/grafana apply /tmp/grafana-tempo-2.10.3.patch \
    && test "$(git -C /src/grafana diff --numstat | awk '{added += $1; removed += $2} END {print added ":" removed}')" = "3:1"

WORKDIR /src/grafana

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    SOURCE_DATE_EPOCH="${GRAFANA_SOURCE_DATE_EPOCH}" \
    COMMIT_SHA="${GRAFANA_COMMIT}" \
    BUILD_BRANCH=v13.1.0 \
    make build-go OS=linux ARCH=amd64 CGO_ENABLED=0 \
    && echo "9e7b41aa84cfc2e735f7482d51103e5ffcc6989525b6be7dad7b43c7b724c2f9  bin/linux/amd64/grafana" | sha256sum --check --strict \
    && go version -m bin/linux/amd64/grafana | grep -F 'github.com/grafana/tempo' | grep -F 'v2.10.3+incompatible' \
    && go version -m bin/linux/amd64/grafana | grep -F 'golang.org/x/net' | grep -F 'v0.55.0' \
    && go version -m bin/linux/amd64/grafana | grep -F 'google.golang.org/grpc' | grep -F 'v1.81.1'

FROM grafana/grafana:13.1.0@sha256:121a7a9ece6dc10b969f1f96eed64b4f07dfac0d0b8abc070f7cb83bbde86f63 AS upstream-assets

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ENV GF_PATHS_CONFIG=/etc/grafana/grafana.ini \
    GF_PATHS_DATA=/var/lib/grafana \
    GF_PATHS_HOME=/usr/share/grafana \
    GF_PATHS_LOGS=/var/log/grafana \
    GF_PATHS_PLUGINS=/var/lib/grafana/plugins \
    GF_PATHS_PROVISIONING=/etc/grafana/provisioning

RUN addgroup -S -g 472 grafana \
    && adduser -S -D -H -u 472 -G grafana grafana \
    && mkdir -p \
        /etc/grafana \
        /usr/share/grafana/bin \
        /usr/share/grafana/data \
        /var/lib/grafana/plugins \
        /var/log/grafana \
    && chown -R 472:472 /var/lib/grafana /var/log/grafana \
    && chmod -R 0770 /var/lib/grafana /var/log/grafana

COPY --from=upstream-assets /etc/grafana /etc/grafana
COPY --from=upstream-assets /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=upstream-assets /usr/share/grafana/conf /usr/share/grafana/conf
COPY --from=upstream-assets /usr/share/grafana/public /usr/share/grafana/public
COPY --from=upstream-assets /usr/share/grafana/LICENSE /usr/share/grafana/LICENSE
COPY --from=backend-builder /src/grafana/bin/linux/amd64/grafana /usr/share/grafana/bin/grafana

RUN chown -R root:root /etc/grafana /usr/share/grafana \
    && chmod -R a-w /etc/grafana /usr/share/grafana \
    && chmod -R a+rX /etc/grafana /usr/share/grafana \
    && test "$(stat -c '%u:%g:%a' /usr/share/grafana/bin/grafana)" = "0:0:555" \
    && test "$(stat -c '%u:%g:%a' /usr/share/grafana/public)" = "0:0:555" \
    && test "$(stat -c '%u:%g:%a' /usr/share/grafana/conf/defaults.ini)" = "0:0:444"

WORKDIR /usr/share/grafana
USER 472:472
EXPOSE 3000
ENTRYPOINT ["/usr/share/grafana/bin/grafana"]
CMD ["server", "--homepath=/usr/share/grafana", "--config=/etc/grafana/grafana.ini"]
