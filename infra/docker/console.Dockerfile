FROM node:24.18.0-alpine3.24@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS builder

WORKDIR /app
COPY .npmrc /app/.npmrc
COPY package.json package-lock.json* tsconfig.base.json /app/
COPY packages /app/packages
COPY apps/console /app/apps/console
RUN test "$(node --version)" = "v24.18.0" \
    && test "$(npm --version)" = "11.16.0" \
    && npm ci
RUN npm --workspace @hallu-defense/contracts run build
RUN npm --workspace @hallu-defense/sdk run build
RUN npm --workspace @hallu-defense/console run build

FROM node:24.18.0-alpine3.24@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS runtime

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app

# The standalone server does not need npm, npx, compilers, source files, or
# development dependencies. Removing the bundled npm dependency tree also
# keeps runtime-only vulnerabilities out of the production image.
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx

COPY --from=builder /app/apps/console/.next/standalone ./
COPY --from=builder /app/apps/console/.next/static ./apps/console/.next/static
RUN find /app -type d -exec chmod 0555 {} + \
    && find /app -type f -exec chmod 0444 {} +

EXPOSE 3000
USER node
CMD ["node", "apps/console/server.js"]
