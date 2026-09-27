# Build context is the repo root (see docker-compose.yml):
#   docker build -f packages/server/Dockerfile .

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
# npm validates every workspace listed in the lockfile, so copy all manifests.
COPY packages/crypto/package.json packages/crypto/
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
COPY packages/extension/package.json packages/extension/
RUN npm ci --workspace=@password-manager/server --include-workspace-root
COPY packages/server/ packages/server/
RUN npm run build --workspace=@password-manager/server

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/server/package.json packages/server/
COPY packages/web/package.json packages/web/
COPY packages/extension/package.json packages/extension/
RUN npm ci --omit=dev --workspace=@password-manager/server && npm cache clean --force
COPY --from=build /app/packages/server/dist packages/server/dist
COPY packages/server/migrations packages/server/migrations
WORKDIR /app/packages/server
USER node
EXPOSE 3001
CMD ["node", "dist/index.js"]
