FROM postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777 AS pgvector-builder

ARG PGVECTOR_TAG=v0.8.5
ARG PGVECTOR_COMMIT=159b79aaad5983fb7459c1e3df2897fbb2d11788

USER root
RUN apk add --no-cache \
      build-base=0.5-r4 \
      clang21=21.1.8-r3 \
      git=2.54.0-r0 \
      llvm21=21.1.8-r1 \
    && test "$(git --version)" = "git version 2.54.0" \
    && test "$(clang-21 --version | head -n 1)" = "Alpine clang version 21.1.8"
RUN git init /src/pgvector \
    && git -C /src/pgvector remote add origin https://github.com/pgvector/pgvector.git \
    && git -C /src/pgvector fetch --depth=1 origin \
      "refs/tags/${PGVECTOR_TAG}:refs/tags/${PGVECTOR_TAG}" \
    && test "$(git -C /src/pgvector rev-parse "refs/tags/${PGVECTOR_TAG}^{commit}")" \
      = "${PGVECTOR_COMMIT}" \
    && git -C /src/pgvector checkout --detach "${PGVECTOR_COMMIT}"
WORKDIR /src/pgvector
RUN make clean \
    && make OPTFLAGS="" \
    && make install DESTDIR=/opt/pgvector \
    && test -f /opt/pgvector/usr/local/lib/postgresql/vector.so \
    && test -f /opt/pgvector/usr/local/share/postgresql/extension/vector.control \
    && test -f /opt/pgvector/usr/local/share/postgresql/extension/vector--0.8.5.sql

FROM postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777

USER root
COPY --from=pgvector-builder /opt/pgvector/usr/local/lib/postgresql/vector.so /usr/local/lib/postgresql/vector.so
COPY --from=pgvector-builder /opt/pgvector/usr/local/share/postgresql/extension/ /usr/local/share/postgresql/extension/
RUN rm -f /usr/local/bin/gosu \
    && test ! -e /usr/local/bin/gosu \
    && test "$(postgres --version)" = "postgres (PostgreSQL) 16.14" \
    && test -f /usr/local/lib/postgresql/vector.so \
    && find /usr/local/lib/postgresql/vector.so \
      /usr/local/share/postgresql/extension/vector* -type f -exec chmod 0444 {} +

# The upstream entrypoint invokes gosu only from UID 0. Starting as the native
# Alpine postgres account keeps that branch unreachable and removes the
# vulnerable helper binary from the runtime image.
USER postgres
