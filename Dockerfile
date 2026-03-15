# Copyright © 2026 Sthenos Security. All rights reserved.
# Intentionally Vulnerable Dockerfile — CONFIG issues for REACHABLE testing

# CONFIG-001: Using latest tag (unpinned version)
FROM node:latest

WORKDIR /app

COPY package*.json ./

# CONFIG-002: Running npm as root
RUN npm install

COPY . .

# CONFIG-003: Exposing debug port
EXPOSE 3000
EXPOSE 9229

# CONFIG-004: Running as root (no USER directive)
CMD ["node", "app.js"]
