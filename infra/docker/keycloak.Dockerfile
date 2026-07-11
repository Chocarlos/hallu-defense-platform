FROM eclipse-temurin:21.0.11_10-jre-alpine-3.23@sha256:3f08b13888f595cc49edabea7250ba69499ba25602b267da591720769400e08c AS keycloak-builder

ADD --checksum=sha256:f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a https://github.com/keycloak/keycloak/releases/download/26.7.0/keycloak-26.7.0.tar.gz /tmp/keycloak.tar.gz
ADD --checksum=sha256:3888e9e69ab66fbacaacc9aea0e9ffbf15368288e4aca468b024dba11c09fbf9 https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.21.4/jackson-databind-2.21.4.jar /tmp/jackson-databind-2.21.4.jar

RUN mkdir -p /opt/keycloak \
    && tar -xzf /tmp/keycloak.tar.gz --strip-components=1 -C /opt/keycloak \
    && /opt/keycloak/bin/kc.sh --version | grep -F '26.7.0'

RUN set -eux; \
    library=/opt/keycloak/lib/lib/main; \
    legacy="$library/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar"; \
    corrected="$library/com.fasterxml.jackson.core.jackson-databind-2.21.4.jar"; \
    test -f "$legacy"; \
    install -m 0444 /tmp/jackson-databind-2.21.4.jar "$corrected"; \
    rm "$legacy"; \
    ln -s "$(basename "$corrected")" "$legacy"; \
    test -L "$legacy"; \
    test "$(readlink "$legacy")" = "$(basename "$corrected")"; \
    unzip -p "$corrected" \
      META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties \
      | grep -Fx 'version=2.21.4'

ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true

RUN /opt/keycloak/bin/kc.sh build \
    && config="$(/opt/keycloak/bin/kc.sh show-config)" \
    && printf '%s\n' "$config" | grep -F 'kc.db =  postgres' \
    && printf '%s\n' "$config" | grep -F 'kc.health-enabled =  true' \
    && printf '%s\n' "$config" | grep -F 'kc.metrics-enabled =  true'

RUN set -eux; \
    for artifact in \
      lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-13.2.1.jre11.jar \
      lib/lib/main/com.mysql.mysql-connector-j-9.6.0.jar \
      lib/lib/main/io.quarkus.quarkus-jdbc-mysql-3.33.2.1.jar \
      lib/lib/main/io.quarkus.quarkus-jdbc-oracle-3.33.2.1.jar \
      lib/lib/main/com.h2database.h2-2.4.240.jar \
      lib/lib/main/io.quarkus.quarkus-jdbc-mariadb-3.33.2.1.jar \
      lib/lib/main/io.quarkus.quarkus-jdbc-mssql-3.33.2.1.jar \
      lib/lib/main/org.mariadb.jdbc.mariadb-java-client-3.5.7.jar \
      lib/lib/deployment/io.quarkus.quarkus-jdbc-mssql-deployment-3.33.2.1.jar \
      lib/lib/deployment/io.quarkus.quarkus-jdbc-oracle-deployment-3.33.2.1.jar \
      lib/lib/deployment/io.quarkus.quarkus-jdbc-mysql-deployment-3.33.2.1.jar \
      lib/lib/deployment/io.quarkus.quarkus-jdbc-mariadb-deployment-3.33.2.1.jar; \
    do \
      test -f "/opt/keycloak/$artifact"; \
      rm "/opt/keycloak/$artifact"; \
    done; \
    test -f /opt/keycloak/lib/lib/main/org.postgresql.postgresql-42.7.11.jar; \
    test -f /opt/keycloak/lib/lib/main/io.quarkus.quarkus-jdbc-postgresql-3.33.2.1.jar; \
    test -f /opt/keycloak/lib/lib/deployment/io.quarkus.quarkus-jdbc-postgresql-deployment-3.33.2.1.jar; \
    test -L /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar; \
    test -f /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.4.jar; \
    test -f /opt/keycloak/bin/client/keycloak-admin-cli-26.7.0.jar; \
    rm -rf /opt/keycloak/bin/client; \
    test ! -e /opt/keycloak/bin/client

FROM python:3.12.13-alpine3.24@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df AS metadata-patcher

COPY --from=keycloak-builder /opt/keycloak /opt/keycloak
COPY scripts/ci/patch_keycloak_metadata.py /tmp/patch_keycloak_metadata.py
RUN python /tmp/patch_keycloak_metadata.py \
    && test ! -e /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar \
    && test -f /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.4.jar

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ENV JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/java/openjdk/bin:/opt/keycloak/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_RUN_IN_CONTAINER=true

COPY --from=keycloak-builder /opt/java/openjdk /opt/java/openjdk
COPY --from=metadata-patcher /opt/keycloak /opt/keycloak

RUN addgroup -S -g 10001 keycloak \
    && adduser -S -D -H -u 10001 -G keycloak -s /sbin/nologin keycloak \
    && rm -rf /opt/keycloak/data \
    && mkdir -p /opt/keycloak/data \
    && find /opt/keycloak -type d -exec chmod 0555 {} + \
    && find /opt/keycloak -type f -exec chmod 0444 {} + \
    && find /opt/keycloak/bin -type f -name '*.sh' -exec chmod 0555 {} + \
    && test "$(java -version 2>&1 | sed -n '1s/.*version "\([^"]*\)".*/\1/p')" = "21.0.11" \
    && /opt/keycloak/bin/kc.sh --version | grep -F '26.7.0' \
    && test ! -e /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar \
    && test -f /opt/keycloak/lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.4.jar \
    && test ! -e /opt/keycloak/bin/client \
    && test ! -e /opt/keycloak/lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-13.2.1.jre11.jar

EXPOSE 8080 9000
USER 10001:10001
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
