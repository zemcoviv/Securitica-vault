"""Thin backend for the Mini App (BRIEF §6.4).

Responsibilities ONLY:
  - serve the static Mini App bundle with strict security headers,
  - verify Telegram initData (identity) and rate-limit unlock attempts.

It MUST NOT proxy or store any secret. Sync goes directly client -> Vaultwarden.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .initdata import verify_init_data

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
STATIC_DIR = os.environ.get("MINIAPP_DIST", "/srv/miniapp")
INITDATA_TTL = int(os.environ.get("INITDATA_TTL_SECONDS", "86400"))

# In-memory sliding-window rate limiter. For a single-node deploy this is enough;
# swap for Redis if you scale horizontally. Anti-brute on master phrase is also
# enforced by the memory-hard KDF and by Vaultwarden itself (BRIEF §9).
_RATE_WINDOW_SECONDS = 60
_RATE_MAX_HITS = 20
_hits: dict[str, deque[float]] = defaultdict(deque)


def _rate_limited(key: str) -> bool:
    now = time.time()
    bucket = _hits[key]
    while bucket and now - bucket[0] > _RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX_HITS:
        return True
    bucket.append(now)
    return False


app = FastAPI(title="Securitica Mini App backend", docs_url=None, redoc_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Defence-in-depth; Caddy sets the authoritative CSP/HSTS at the edge.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self' https://telegram.org; "
        "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors https://*.telegram.org; object-src 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/session")
async def session(request: Request) -> JSONResponse:
    """Verify identity from Telegram initData. Returns nothing secret."""
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(f"session:{client_ip}"):
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)

    init_data = payload.get("initData", "")
    result = verify_init_data(init_data, BOT_TOKEN, max_age_seconds=INITDATA_TTL)
    if not result.ok:
        return JSONResponse(
            {"ok": False, "error": result.reason}, status_code=401
        )
    return JSONResponse({"ok": True, "userId": result.user_id})


# Static Mini App bundle, mounted last so /api routes win. Only enabled when the
# build output exists (the container mounts the Vite dist here).
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="miniapp")
