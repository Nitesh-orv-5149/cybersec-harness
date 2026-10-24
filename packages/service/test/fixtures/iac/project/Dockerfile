# Deliberately misconfigured fixture: runs as root, no HEALTHCHECK, unpinned base image.
FROM node:latest
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "server.js"]
