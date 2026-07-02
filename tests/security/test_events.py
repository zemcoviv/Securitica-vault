"""BRIEF §6.2 / §10 M4 — account-event notifications carry metadata only.

Exercises POST /api/events on the thin backend: a valid, freshly-signed
initData is required (tamper/expiry already covered by test_initdata.py);
the Telegram call itself is mocked so no network is used, and we assert the
captured payload never contains anything that isn't kind/time/ip/geo/device —
in particular a `CANARY_PLAINTEXT_...` marker smuggled into the request body
under an unexpected field name must never reach the "Telegram message".
"""

from __future__ import annotations

import hashlib
import hmac
import sys
import time
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

import server.main as server_main  # noqa: E402

BOT_TOKEN = "123456:TEST_BOT_TOKEN_do_not_use_in_prod"
CANARY = "CANARY_PLAINTEXT_events_9f8a7b"


def _sign(fields: dict[str, str], token: str = BOT_TOKEN) -> str:
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


def _valid_init_data(user_id: int = 42) -> str:
    return _sign(
        {
            "auth_date": str(int(time.time())),
            "user": f'{{"id":{user_id},"first_name":"Test"}}',
        }
    )


def _client() -> TestClient:
    server_main.BOT_TOKEN = BOT_TOKEN
    server_main._hits.clear()
    return TestClient(server_main.app)


def test_valid_login_event_is_accepted_and_notifies():
    with patch.object(server_main, "send_account_event", new=AsyncMock()) as mock_send:
        resp = _client().post(
            "/api/events",
            json={"initData": _valid_init_data(), "kind": "login", "device": "iPhone"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "notified": True}
    mock_send.assert_awaited_once()
    _, chat_id, event = mock_send.await_args.args
    assert chat_id == 42
    assert event.kind == "login"
    assert event.device == "iPhone"


def test_canary_smuggled_into_the_body_never_reaches_the_notification():
    with patch.object(server_main, "send_account_event", new=AsyncMock()) as mock_send:
        resp = _client().post(
            "/api/events",
            json={
                "initData": _valid_init_data(),
                "kind": "export",
                "device": "desktop",
                # Extra, unexpected fields an attacker (or a buggy client)
                # might smuggle a secret into — must be silently ignored.
                "password": f"{CANARY}-password",
                "notes": f"{CANARY}-notes",
                "vaultKey": f"{CANARY}-key",
            },
        )
    assert resp.status_code == 200
    mock_send.assert_awaited_once()
    _, _chat_id, event = mock_send.await_args.args
    # AccountEvent only ever has kind/when/ip/geo/device — assert that
    # structurally, not just by absence of the canary string.
    assert set(vars(event).keys()) == {"kind", "when", "ip", "geo", "device"}
    for value in vars(event).values():
        assert CANARY not in str(value)


def test_invalid_kind_rejected():
    resp = _client().post(
        "/api/events",
        json={"initData": _valid_init_data(), "kind": "delete_everything"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_kind"


def test_tampered_init_data_rejected_even_with_valid_kind():
    tampered = _valid_init_data().replace("id%22%3A42", "id%22%3A99")
    with patch.object(server_main, "send_account_event", new=AsyncMock()) as mock_send:
        resp = _client().post(
            "/api/events", json={"initData": tampered, "kind": "login"}
        )
    assert resp.status_code == 401
    mock_send.assert_not_awaited()


def test_device_field_is_capped_in_length():
    huge_device = "A" * 10_000
    with patch.object(server_main, "send_account_event", new=AsyncMock()) as mock_send:
        resp = _client().post(
            "/api/events",
            json={"initData": _valid_init_data(), "kind": "login", "device": huge_device},
        )
    assert resp.status_code == 200
    _, _chat_id, event = mock_send.await_args.args
    assert len(event.device) <= server_main._MAX_DEVICE_LEN


def test_telegram_delivery_failure_does_not_fail_the_caller():
    with patch.object(
        server_main, "send_account_event", new=AsyncMock(side_effect=RuntimeError("boom"))
    ):
        resp = _client().post(
            "/api/events", json={"initData": _valid_init_data(), "kind": "login"}
        )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "notified": False}
