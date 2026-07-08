FROM node:24-alpine

WORKDIR /app
COPY package.json package-lock.json* tsconfig.base.json /app/
COPY packages /app/packages
COPY apps/console /app/apps/console
RUN npm ci
RUN npm --workspace @hallu-defense/contracts run build
RUN npm --workspace @hallu-defense/sdk run build
RUN npm --workspace @hallu-defense/console run build
RUN chown -R node:node /app

EXPOSE 3000
USER node
CMD ["npm", "--workspace", "@hallu-defense/console", "run", "start"]
