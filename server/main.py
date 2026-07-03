"""Thin backend for the Mini App (BRIEF §6.4).

Responsibilities ONLY:
  - serve the static Mini App bundle with strict security headers,
  - verify Telegram initData (identity) and rate-limit unlock attempts.

It MUST NOT proxy or store any secret. Sync goes directly client -> Vaultwarden.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .geoip import lookup_geo
from .initdata import verify_init_data
from .notifications import VALID_EVENT_KINDS, AccountEvent, send_account_event
from .provisioning import is_provisioned, mark_provisioned, synthetic_email
from .vaultwarden_admin import VaultwardenAdminError, invite_user

logger = logging.getLogger("securitica.server")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
STATIC_DIR = os.environ.get("MINIAPP_DIST", "/srv/miniapp")
INITDATA_TTL = int(os.environ.get("INITDATA_TTL_SECONDS", "86400"))
# Reaches Vaultwarden directly over the internal docker network — never
# through Caddy — since this is a server-to-server admin call, not client sync.
VAULTWARDEN_INTERNAL_URL = os.environ.get("VAULTWARDEN_INTERNAL_URL", "http://vaultwarden:80")
VAULTWARDEN_ADMIN_TOKEN = os.environ.get("VAULTWARDEN_ADMIN_TOKEN", "")
# Cap on the client-supplied device string — never trust arbitrary length/content
# beyond "short label", and it is never logged or forwarded anywhere but Telegram.
_MAX_DEVICE_LEN = 120

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


@app.post("/api/events")
async def report_event(request: Request) -> JSONResponse:
    """
    Metadata-only account-event alert (BRIEF §6.2, §10 M4): login, export, or
    master password change. The request body carries `initData` (verified
    below) and `kind` — a closed enum — plus an optional short `device`
    string. Nothing else is accepted or forwarded; there is no field here a
    cipher or key could travel through.
    """
    # See the matching comment in session() above re: ProxyHeadersMiddleware.
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(f"events:{client_ip}"):
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)

    kind = payload.get("kind")
    if kind not in VALID_EVENT_KINDS:
        return JSONResponse({"ok": False, "error": "invalid_kind"}, status_code=400)

    init_data = payload.get("initData", "")
    result = verify_init_data(init_data, BOT_TOKEN, max_age_seconds=INITDATA_TTL)
    if not result.ok or result.user_id is None:
        return JSONResponse({"ok": False, "error": result.reason}, status_code=401)

    device = payload.get("device")
    device = device[:_MAX_DEVICE_LEN] if isinstance(device, str) else None

    event = AccountEvent(
        kind=kind,
        when=datetime.now(timezone.utc),
        ip=client_ip,
        geo=lookup_geo(client_ip),
        device=device,
    )
    try:
        await send_account_event(BOT_TOKEN, result.user_id, event)
    except Exception:
        # Best-effort: a Telegram/network hiccup must not fail the caller's
        # own flow (the login/export/password-change already succeeded).
        logger.warning("failed to deliver account-event notification", exc_info=True)
        return JSONResponse({"ok": True, "notified": False})
    return JSONResponse({"ok": True, "notified": True})


@app.post("/api/provision")
async def provision(request: Request) -> JSONResponse:
    """
    Resolve a Telegram identity to a Vaultwarden account (BRIEF §1: the user
    never sees Vaultwarden, an email field, or a KDF setting). Invites a new
    account if one doesn't exist yet for this Telegram user, so the client
    can register() straight away — SIGNUPS_ALLOWED stays false; this uses
    the admin-invite mechanism, gated by initData-verified Telegram identity,
    never open self-registration from the raw internet.
    """
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(f"provision:{client_ip}"):
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)

    init_data = payload.get("initData", "")
    result = verify_init_data(init_data, BOT_TOKEN, max_age_seconds=INITDATA_TTL)
    if not result.ok or result.user_id is None:
        return JSONResponse({"ok": False, "error": result.reason}, status_code=401)

    email = synthetic_email(result.user_id)
    if is_provisioned(result.user_id):
        return JSONResponse({"ok": True, "email": email, "status": "existing"})

    if not VAULTWARDEN_ADMIN_TOKEN:
        logger.error("VAULTWARDEN_ADMIN_TOKEN is not set — cannot provision new accounts")
        return JSONResponse({"ok": False, "error": "server_misconfigured"}, status_code=500)

    try:
        await invite_user(VAULTWARDEN_INTERNAL_URL, VAULTWARDEN_ADMIN_TOKEN, email)
    except VaultwardenAdminError:
        logger.exception("failed to provision vaultwarden invite for %s", email)
        return JSONResponse({"ok": False, "error": "provision_failed"}, status_code=502)

    return JSONResponse({"ok": True, "email": email, "status": "new"})


@app.post("/api/provision/complete")
async def provision_complete(request: Request) -> JSONResponse:
    """
    Called by the client right after a successful registration against
    Vaultwarden, so future /api/provision calls report "existing" instead of
    inviting again. Purely a UX-routing signal (BRIEF: which first-run screen
    to show) — never a security gate; getting this wrong just shows the
    wrong screen once, it can't grant or withhold vault access.
    """
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)

    init_data = payload.get("initData", "")
    result = verify_init_data(init_data, BOT_TOKEN, max_age_seconds=INITDATA_TTL)
    if not result.ok or result.user_id is None:
        return JSONResponse({"ok": False, "error": result.reason}, status_code=401)

    mark_provisioned(result.user_id)
    return JSONResponse({"ok": True})


# Static Mini App bundle, mounted last so /api routes win. Only enabled when the
# build output exists (the container mounts the Vite dist here).
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="miniapp")

# Trust X-Forwarded-For/X-Forwarded-Proto from whoever connects to this
# process. Safe to trust unconditionally here because this service publishes
# no port in docker-compose.yml (networks: [internal, egress] only) — the
# only thing able to reach it at all is another container on the compose
# network, and only Caddy actually reverse-proxies real traffic to it. This
# MUST be the outermost wrap (applied last) so it rewrites request.client
# before any route or the security_headers middleware above sees it.
app = ProxyHeadersMiddleware(app, trusted_hosts="*")
