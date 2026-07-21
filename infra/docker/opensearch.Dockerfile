FROM opensearchproject/opensearch:3.7.0@sha256:123e6591a47b1d54686890551bdb35739c85193ecded381219fc9e059e18128f

ARG AMAZON_LINUX_RELEASEVER=2023.12.20260720

USER 0

# This local/Kind image intentionally exposes only the OpenSearch core used by
# the BM25 evidence index.  Optional plugins are neither configured nor needed
# by this product and materially expand the Java dependency/CVE surface.
RUN dnf --assumeyes --refresh --releasever="${AMAZON_LINUX_RELEASEVER}" upgrade \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' openssl-libs)" = "3.5.5-1.amzn2023.0.5" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' openssl-fips-provider-latest)" = "3.5.5-1.amzn2023.0.5" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' expat)" = "2.6.3-1.amzn2023.0.6" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' glib2)" = "2.82.2-770.amzn2023" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' libacl)" = "2.4.0-1.amzn2023.0.1" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' libsolv)" = "0.7.22-1.amzn2023.0.4" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' python3)" = "3.9.25-1.amzn2023.0.8" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' sqlite-libs)" = "3.40.0-1.amzn2023.0.8" \
    && test "$(rpm -q --qf '%{VERSION}-%{RELEASE}' system-release)" = "2023.12.20260720-0.amzn2023" \
    && dnf clean all \
    && rm -rf \
        /var/cache/dnf/* \
        /usr/share/opensearch/plugins/* \
        /usr/share/opensearch/config/opensearch-* \
        /usr/share/opensearch/modules/ingest-geoip \
    && test -z "$(ls -A /usr/share/opensearch/plugins)" \
    && test ! -e /usr/share/opensearch/modules/ingest-geoip \
    && mkdir -p /opt/hallu-defense \
    && cp -a /usr/share/opensearch/config /opt/hallu-defense/opensearch-config \
    && chown -R root:root /usr/share/opensearch \
    && chown -R root:root /opt/hallu-defense \
    && chmod -R a-w /usr/share/opensearch \
    && chmod -R a-w /opt/hallu-defense \
    && chmod -R a+rX /usr/share/opensearch \
    && chmod -R a+rX /opt/hallu-defense \
    && chown -R 1000:1000 /usr/share/opensearch/data /usr/share/opensearch/logs \
    && chmod 0700 /usr/share/opensearch/data /usr/share/opensearch/logs \
    && test "$(stat -c '%u:%g:%a' /usr/share/opensearch/bin/opensearch)" = "0:0:555" \
    && test "$(stat -c '%u:%g:%a' /usr/share/opensearch/config/opensearch.yml)" = "0:0:444" \
    && test "$(stat -c '%u:%g:%a' /usr/share/opensearch/data)" = "1000:1000:700" \
    && test "$(stat -c '%u:%g:%a' /usr/share/opensearch/logs)" = "1000:1000:700"

COPY --chown=0:0 --chmod=0555 infra/docker/opensearch_entrypoint.sh /usr/local/bin/hallu-opensearch-entrypoint

USER 1000
ENTRYPOINT ["/usr/local/bin/hallu-opensearch-entrypoint"]
