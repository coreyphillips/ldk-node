FROM node:22-alpine@sha256:ce8d97f7cfc7c5386421eb932df20a29df99b1a7f469f6157d5c9956702ffadc
RUN apk add --no-cache iptables ip6tables su-exec libstdc++ ca-certificates
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev && npm cache clean --force
COPY worker.cjs entrypoint.sh ./
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
