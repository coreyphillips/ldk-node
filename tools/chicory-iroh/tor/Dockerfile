FROM node:22-alpine@sha256:ce8d97f7cfc7c5386421eb932df20a29df99b1a7f469f6157d5c9956702ffadc
RUN apk add --no-cache tor=0.4.9.14-r0
USER node
ENTRYPOINT ["tor"]
