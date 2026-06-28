"""Telegram initData verification (BRIEF §9).

INVARIANT (BRIEF §2): initData authenticates *identity* only. It is verified
server-side and is NEVER key material — a stolen Telegram account must not yield
vault decryption. This module is pure (no I/O) so it is trivially testable; the
FastAPI wiring lives in ``server/main.py``.

Scheme:
    secret_key = HMAC_SHA256(key="WebAppData", msg=BOT_TOKEN)
    check_string = "\\n".join(f"{k}={v}" for k, v in sorted(fields) if k != "hash")
    expected = HMAC_SHA256(key=secret_key, msg=check_string)
    valid <=> constant_time_eq(expected_hex, provided_hash) AND auth_date fresh
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl


@dataclass(frozen=True)
class InitDataResult:
    ok: bool
    user_id: int | None = None
    reason: str | None = None


def _build_check_string(pairs: list[tuple[str, str]]) -> str:
    # All fields except ``hash``, sorted by key, joined by newlines.
    filtered = sorted((k, v) for k, v in pairs if k != "hash")
    return "\n".join(f"{k}={v}" for k, v in filtered)


def verify_init_data(
    init_data: str,
    bot_token: str,
    *,
    max_age_seconds: int = 86_400,
    now: float | None = None,
) -> InitDataResult:
    """Verify a raw Telegram ``initData`` query string.

    Rejects on: missing/invalid hash, HMAC mismatch, or stale/missing
    ``auth_date`` (TTL). Uses constant-time comparison for the hash.
    """
    if not bot_token:
        return InitDataResult(False, reason="server_misconfigured")

    pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=False)
    fields = dict(pairs)

    provided_hash = fields.get("hash")
    if not provided_hash:
        return InitDataResult(False, reason="missing_hash")

    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    check_string = _build_check_string(pairs)
    expected = hmac.new(
        secret_key, check_string.encode(), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, provided_hash):
        return InitDataResult(False, reason="bad_hash")

    # auth_date freshness (anti-replay TTL).
    auth_date_raw = fields.get("auth_date")
    if not auth_date_raw or not auth_date_raw.isdigit():
        return InitDataResult(False, reason="missing_auth_date")
    auth_date = int(auth_date_raw)
    current = time.time() if now is None else now
    if current - auth_date > max_age_seconds:
        return InitDataResult(False, reason="expired")
    if auth_date - current > 300:  # clock-skew guard against future timestamps
        return InitDataResult(False, reason="future_auth_date")

    user_id = _extract_user_id(fields.get("user"))
    return InitDataResult(True, user_id=user_id)


def _extract_user_id(user_field: str | None) -> int | None:
    if not user_field:
        return None
    try:
        import json

        return int(json.loads(user_field).get("id"))
    except (ValueError, TypeError, KeyError):
        return None
