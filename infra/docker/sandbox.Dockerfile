FROM node:22.17.1-bookworm-slim AS node-lts

FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=node-lts /usr/local/bin/node /usr/local/bin/node
COPY --from=node-lts /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && python -m pip install --no-cache-dir pytest==9.0.3 \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /workspace \
    && chown -R 10001:10001 /workspace

WORKDIR /workspace
USER 10001

CMD ["python", "--version"]
