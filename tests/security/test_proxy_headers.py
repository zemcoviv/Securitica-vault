"""Regression test (security review finding): the thin backend sits behind
Caddy (docker-compose.yml: only Caddy has a published port, miniapp-server is
internal-only) and MUST read the real client IP from X-Forwarded-For, not the
proxy's own container IP — otherwise the per-IP rate limiter becomes one
shared bucket for every user, and the IP in account-event alerts is always
wrong. server/main.py wraps the app in uvicorn's ProxyHeadersMiddleware to
fix this; this test proves request.client.host (and therefore the rate-limit
key and the notified IP) reflects X-Forwarded-For, not the TCP peer address
TestClient uses by default.
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


def _valid_init_data(user_id: int = 42) -> str:
    fields = {
        "auth_date": str(int(time.time())),
        "user": f'{{"id":{user_id},"first_name":"Test"}}',
    }
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


def _client() -> TestClient:
    server_main.BOT_TOKEN = BOT_TOKEN
    server_main._hits.clear()
    return TestClient(server_main.app)


def test_client_ip_reflects_x_forwarded_for_not_the_tcp_peer():
    with patch.object(server_main, "send_account_event", new=AsyncMock()) as mock_send:
        resp = _client().post(
            "/api/events",
            json={"initData": _valid_init_data(), "kind": "login"},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
    assert resp.status_code == 200
    _, _chat_id, event = mock_send.await_args.args
    # Must be the forwarded client IP, NOT TestClient's default peer
    # (testclient / 127.0.0.1), proving ProxyHeadersMiddleware is active.
    assert event.ip == "203.0.113.7"


def test_rate_limit_is_keyed_per_forwarded_client_not_one_shared_bucket():
    # Two distinct "users" arriving through the same proxy (same TCP peer as
    # far as TestClient is concerned) must get independent rate-limit budgets.
    client = _client()
    with patch.object(server_main, "send_account_event", new=AsyncMock()):
        for _ in range(server_main._RATE_MAX_HITS):
            resp = client.post(
                "/api/events",
                json={"initData": _valid_init_data(), "kind": "login"},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
            assert resp.status_code == 200
        # This user is now rate-limited...
        limited = client.post(
            "/api/events",
            json={"initData": _valid_init_data(), "kind": "login"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )
        assert limited.status_code == 429

        # ...but a different forwarded IP must be unaffected.
        other_user = client.post(
            "/api/events",
            json={"initData": _valid_init_data(), "kind": "login"},
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        assert other_user.status_code == 200
