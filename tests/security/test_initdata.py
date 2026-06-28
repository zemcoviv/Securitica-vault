"""BRIEF §11.3 — initData-tamper.

A forged ``hash`` or an expired ``auth_date`` MUST be rejected server-side.
These tests exercise the pure verifier in ``server/initdata.py`` so no running
server is required.

Run with:  pytest tests/security/test_initdata.py
"""

from __future__ import annotations

import hashlib
import hmac
import time
from urllib.parse import urlencode

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from server.initdata import verify_init_data  # noqa: E402

BOT_TOKEN = "123456:TEST_BOT_TOKEN_do_not_use_in_prod"


def _sign(fields: dict[str, str], token: str = BOT_TOKEN) -> str:
    """Produce a valid signed initData query string for the given fields."""
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    signed = {**fields, "hash": digest}
    return urlencode(signed)


def _base_fields(auth_date: int | None = None) -> dict[str, str]:
    return {
        "auth_date": str(auth_date if auth_date is not None else int(time.time())),
        "query_id": "AAEdef",
        "user": '{"id":42,"first_name":"Test"}',
    }


def test_valid_initdata_accepted():
    init_data = _sign(_base_fields())
    result = verify_init_data(init_data, BOT_TOKEN)
    assert result.ok is True
    assert result.user_id == 42


def test_forged_hash_rejected():
    init_data = _sign(_base_fields())
    # Corrupt the hash value while keeping the field present.
    tampered = "&".join(
        ("hash=deadbeefdeadbeef" if p.startswith("hash=") else p)
        for p in init_data.split("&")
    )
    result = verify_init_data(tampered, BOT_TOKEN)
    assert result.ok is False
    assert result.reason == "bad_hash"


def test_tampered_field_invalidates_hash():
    # Flip a signed field after signing — the hash no longer matches.
    init_data = _sign(_base_fields())
    tampered = init_data.replace("id%22%3A42", "id%22%3A99")
    result = verify_init_data(tampered, BOT_TOKEN)
    assert result.ok is False
    assert result.reason == "bad_hash"


def test_expired_auth_date_rejected():
    old = int(time.time()) - 10_000
    init_data = _sign(_base_fields(auth_date=old))
    result = verify_init_data(init_data, BOT_TOKEN, max_age_seconds=3600)
    assert result.ok is False
    assert result.reason == "expired"


def test_missing_hash_rejected():
    fields = _base_fields()
    result = verify_init_data(urlencode(fields), BOT_TOKEN)
    assert result.ok is False
    assert result.reason == "missing_hash"


def test_wrong_bot_token_rejected():
    init_data = _sign(_base_fields(), token="999:OTHER")
    result = verify_init_data(init_data, BOT_TOKEN)
    assert result.ok is False
    assert result.reason == "bad_hash"


def test_future_auth_date_rejected():
    future = int(time.time()) + 10_000
    init_data = _sign(_base_fields(auth_date=future))
    result = verify_init_data(init_data, BOT_TOKEN)
    assert result.ok is False
    assert result.reason == "future_auth_date"
