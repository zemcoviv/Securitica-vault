# Multi-stage: build the Mini App bundle, then serve it + /api from FastAPI.
# The static bundle is OUR supply-chain surface (BRIEF §9): build it ourselves,
# pin deps via the committed lockfile, and serve with strict headers.

FROM node:22-slim AS miniapp-build
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY tsconfig.json vite.config.ts ./
COPY miniapp ./miniapp
# Hosts are public origins, injected at build time (no secrets).
ARG VITE_SERVER_URL=""
ARG VITE_VAULTWARDEN_URL="/vault"
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server ./server
COPY --from=miniapp-build /build/dist /srv/miniapp
ENV MINIAPP_DIST=/srv/miniapp

RUN useradd --create-home --uid 10002 appuser
USER appuser

EXPOSE 8000
# X-Forwarded-For trust (so request.client reflects the real caller, not
# Caddy's container IP) is applied in-process via ProxyHeadersMiddleware in
# server/main.py, not via a CLI flag here — that keeps it in effect under
# any ASGI runner and lets it be covered by tests. Do not also pass
# --proxy-headers: uvicorn would wrap the app in a second copy of the same
# middleware, double-parsing the forwarded-for chain.
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
