"""server/vaultwarden_admin.py: the admin login -> invite two-step flow,
with httpx itself mocked so no real network is ever touched. Confirms the
exact request shapes (form field name, cookie handoff) match what Vaultwarden
1.32.7's admin.rs actually expects.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import pytest  # noqa: E402

from server.vaultwarden_admin import VaultwardenAdminError, invite_user  # noqa: E402

# Captured before any monkeypatching so our fake client factory never calls
# itself recursively via the (later-patched) `httpx.AsyncClient` name.
_RealAsyncClient = httpx.AsyncClient


class _FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, admin_token: str, invite_status: int = 200):
        self.admin_token = admin_token
        self.invite_status = invite_status
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/admin/" and request.method == "POST":
            body = (await request.aread()).decode()
            if f"token={self.admin_token}" not in body:
                return httpx.Response(401, text="bad token")
            return httpx.Response(
                200,
                headers={"set-cookie": "VW_ADMIN=fake-jwt-value; Path=/admin; HttpOnly"},
            )
        if request.url.path == "/admin/invite" and request.method == "POST":
            if request.headers.get("cookie", "").find("VW_ADMIN=fake-jwt-value") == -1:
                return httpx.Response(401, text="missing admin cookie")
            return httpx.Response(self.invite_status, json={"ok": True})
        return httpx.Response(404)


def _patch_client(monkeypatch, transport: _FakeTransport) -> None:
    def fake_async_client(*args, **kwargs):
        kwargs["transport"] = transport
        return _RealAsyncClient(*args, **kwargs)

    monkeypatch.setattr("server.vaultwarden_admin.httpx.AsyncClient", fake_async_client)


@pytest.mark.asyncio
async def test_invite_user_logs_in_then_invites_with_the_session_cookie(monkeypatch):
    transport = _FakeTransport(admin_token="correct-token")
    _patch_client(monkeypatch, transport)

    await invite_user("http://vaultwarden:80", "correct-token", "tg42@securitica.local")

    assert len(transport.requests) == 2
    login_req, invite_req = transport.requests
    assert login_req.url.path == "/admin/"
    assert invite_req.url.path == "/admin/invite"
    invite_body = (await invite_req.aread()).decode()
    assert '"email":"tg42@securitica.local"' in invite_body


@pytest.mark.asyncio
async def test_wrong_admin_token_raises(monkeypatch):
    transport = _FakeTransport(admin_token="correct-token")
    _patch_client(monkeypatch, transport)

    with pytest.raises(VaultwardenAdminError):
        await invite_user("http://vaultwarden:80", "wrong-token", "tg42@securitica.local")


@pytest.mark.asyncio
async def test_conflict_from_invite_is_not_an_error(monkeypatch):
    # Vaultwarden returning 4xx for "email already known" is the success case
    # for our purposes (see docstring in vaultwarden_admin.py).
    transport = _FakeTransport(admin_token="correct-token", invite_status=400)
    _patch_client(monkeypatch, transport)

    await invite_user("http://vaultwarden:80", "correct-token", "tg42@securitica.local")


@pytest.mark.asyncio
async def test_server_error_from_invite_raises(monkeypatch):
    transport = _FakeTransport(admin_token="correct-token", invite_status=500)
    _patch_client(monkeypatch, transport)

    with pytest.raises(VaultwardenAdminError):
        await invite_user("http://vaultwarden:80", "correct-token", "tg42@securitica.local")
