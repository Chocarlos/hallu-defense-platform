FROM node:24.18.0-alpine3.24@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS node-lts

# npm is part of the executable sandbox surface. Fetch its official archive by
# the SHA-256 recorded alongside the registry SHA-512 integrity lock.
COPY infra/docker/sandbox-npm.lock.json /tmp/sandbox-npm.lock.json
COPY scripts/ci/verify_sandbox_npm_archive.mjs /tmp/verify-sandbox-npm-archive.mjs
ADD --checksum=sha256:e810af397525cfe6fdc0b299bd748694744e6a21fb476895a7ec8309a39efced https://registry.npmjs.org/npm/-/npm-12.0.0.tgz /tmp/npm-12.0.0.tgz
RUN test "$(node --version)" = "v24.18.0" \
    && node /tmp/verify-sandbox-npm-archive.mjs \
      /tmp/sandbox-npm.lock.json /tmp/npm-12.0.0.tgz \
    && rm -rf /usr/local/lib/node_modules/npm \
    && mkdir -p /usr/local/lib/node_modules/npm \
    && tar -xzf /tmp/npm-12.0.0.tgz --strip-components=1 \
      -C /usr/local/lib/node_modules/npm \
    && rm /tmp/npm-12.0.0.tgz /tmp/sandbox-npm.lock.json \
      /tmp/verify-sandbox-npm-archive.mjs \
    && node /usr/local/lib/node_modules/npm/bin/npm-cli.js --version \
      | grep -Fx "12.0.0"

FROM python:3.12.13-alpine3.24@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df AS sandbox-wheelhouse

COPY requirements/python/sandbox-linux-py312.lock /tmp/sandbox-linux-py312.lock
RUN test "$(python --version)" = "Python 3.12.13" \
    && python -m pip download --require-hashes --only-binary=:all: --no-deps \
      --dest /wheelhouse -r /tmp/sandbox-linux-py312.lock

FROM python:3.12.13-alpine3.24@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apk add --no-cache git=2.54.0-r0 \
    && test "$(git --version)" = "git version 2.54.0"

COPY --from=node-lts /usr/local/bin/node /usr/local/bin/node
COPY --from=node-lts /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=node-lts /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
COPY --from=node-lts /usr/lib/libstdc++.so.6.0.34 /usr/lib/libstdc++.so.6.0.34
COPY --from=sandbox-wheelhouse /wheelhouse /tmp/wheelhouse
COPY requirements/python/sandbox-linux-py312.lock /tmp/sandbox-linux-py312.lock
COPY infra/docker/sandbox-npm.lock.json /usr/local/share/hallu-defense/sandbox-npm.lock.json
COPY infra/docker/sandbox_runner.py /opt/hallu-defense/sandbox_runner.py
COPY infra/docker/sandbox_batch_runner.py /opt/hallu-defense/sandbox_batch_runner.py
COPY infra/docker/sandbox_workspace.py /opt/hallu-defense/sandbox_workspace.py
COPY infra/docker/sandbox_stream_exporter.py /opt/hallu-defense/sandbox_stream_exporter.py
COPY infra/docker/sandbox_git_inspector.py /opt/hallu-defense/sandbox_git_inspector.py

RUN ln -s libstdc++.so.6.0.34 /usr/lib/libstdc++.so.6 \
    && ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && test "$(python --version)" = "Python 3.12.13" \
    && test "$(node --version)" = "v24.18.0" \
    && test "$(npm --version)" = "12.0.0" \
    && python -m pip install --no-cache-dir --no-index --no-deps --require-hashes \
      --find-links=/tmp/wheelhouse -r /tmp/sandbox-linux-py312.lock \
    && python -m pip check \
    && rm -rf /tmp/wheelhouse /tmp/sandbox-linux-py312.lock \
    && adduser -D -u 10001 -s /sbin/nologin sandbox \
    && mkdir -p /workspace /opt/hallu-defense \
    && chown 10001:10001 /workspace \
    && python -m py_compile /opt/hallu-defense/sandbox_runner.py \
      /opt/hallu-defense/sandbox_batch_runner.py \
      /opt/hallu-defense/sandbox_workspace.py \
      /opt/hallu-defense/sandbox_stream_exporter.py \
      /opt/hallu-defense/sandbox_git_inspector.py \
    && rm -rf /opt/hallu-defense/__pycache__ \
    && find /opt/hallu-defense -type d -exec chmod 0555 {} + \
    && find /opt/hallu-defense -type f -exec chmod 0444 {} +

WORKDIR /workspace
USER 10001

CMD ["python", "--version"]
