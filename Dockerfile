# syntax = docker/dockerfile:1
FROM node:20-slim AS base
LABEL fly_launch_runtime="Node.js"

WORKDIR /app
ENV NODE_ENV=production

FROM base AS build
COPY package*.json ./
RUN npm ci --omit=dev

FROM base
COPY --from=build /app/node_modules /app/node_modules
COPY . .
EXPOSE 8080
CMD ["node", "server.js"]
