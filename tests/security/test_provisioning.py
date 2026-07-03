"""BRIEF §1 onboarding — /api/provision resolves a Telegram identity to a
Vaultwarden account without ever exposing Vaultwarden, an email field, or a
KDF setting to the user. Exercises: new-user invite, idempotency for
already-provisioned users, initData gating, and that ADMIN_TOKEN /
Vaultwarden-admin calls are properly mocked out (never touch a real network).
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

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import server.main as server_main  # noqa: E402
import server.provisioning as provisioning  # noqa: E402
from server.vaultwarden_admin import VaultwardenAdminError  # noqa: E402

BOT_TOKEN = "123456:TEST_BOT_TOKEN_do_not_use_in_prod"


def _valid_init_data(user_id: int) -> str:
    fields = {
        "auth_date": str(int(time.time())),
        "user": f'{{"id":{user_id},"first_name":"Test"}}',
    }
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    digest = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": digest})


@pytest.fixture(autouse=True)
def _isolated_provisioning_db(tmp_path, monkeypatch):
    monkeypatch.setattr(provisioning, "_DB_PATH", tmp_path / "provisioning.sqlite3")
    server_main.BOT_TOKEN = BOT_TOKEN
    server_main.VAULTWARDEN_ADMIN_TOKEN = "test-admin-token"
    server_main._hits.clear()
    yield


def _client() -> TestClient:
    return TestClient(server_main.app)


def test_new_user_gets_invited_and_reports_status_new():
    with patch.object(server_main, "invite_user", new=AsyncMock()) as mock_invite:
        resp = _client().post(
            "/api/provision", json={"initData": _valid_init_data(111)}
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"ok": True, "email": "tg111@securitica.local", "status": "new"}
    mock_invite.assert_awaited_once()
    args = mock_invite.await_args.args
    assert args[0] == server_main.VAULTWARDEN_INTERNAL_URL
    assert args[1] == "test-admin-token"
    assert args[2] == "tg111@securitica.local"


def test_already_provisioned_user_skips_invite_and_reports_existing():
    provisioning.mark_provisioned(222)
    with patch.object(server_main, "invite_user", new=AsyncMock()) as mock_invite:
        resp = _client().post(
            "/api/provision", json={"initData": _valid_init_data(222)}
        )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "email": "tg222@securitica.local", "status": "existing"}
    mock_invite.assert_not_awaited()


def test_provision_complete_marks_provisioned_for_subsequent_calls():
    client = _client()
    with patch.object(server_main, "invite_user", new=AsyncMock()) as mock_invite:
        first = client.post("/api/provision", json={"initData": _valid_init_data(333)})
        assert first.json()["status"] == "new"
        mock_invite.assert_awaited_once()

        complete = client.post(
            "/api/provision/complete", json={"initData": _valid_init_data(333)}
        )
        assert complete.status_code == 200
        assert complete.json() == {"ok": True}

        second = client.post("/api/provision", json={"initData": _valid_init_data(333)})
        assert second.json()["status"] == "existing"
        # Still only ever invited once.
        mock_invite.assert_awaited_once()


def test_tampered_init_data_is_rejected_before_any_invite_call():
    tampered = _valid_init_data(444).replace("id%22%3A444", "id%22%3A999")
    with patch.object(server_main, "invite_user", new=AsyncMock()) as mock_invite:
        resp = _client().post("/api/provision", json={"initData": tampered})
    assert resp.status_code == 401
    mock_invite.assert_not_awaited()


def test_missing_admin_token_fails_closed_for_new_users():
    server_main.VAULTWARDEN_ADMIN_TOKEN = ""
    resp = _client().post("/api/provision", json={"initData": _valid_init_data(555)})
    assert resp.status_code == 500
    assert resp.json()["error"] == "server_misconfigured"


def test_vaultwarden_admin_error_surfaces_as_502():
    with patch.object(
        server_main,
        "invite_user",
        new=AsyncMock(side_effect=VaultwardenAdminError("boom")),
    ):
        resp = _client().post("/api/provision", json={"initData": _valid_init_data(666)})
    assert resp.status_code == 502
    assert resp.json()["error"] == "provision_failed"


def test_provision_complete_rejects_tampered_init_data():
    tampered = _valid_init_data(777).replace("id%22%3A777", "id%22%3A888")
    resp = _client().post("/api/provision/complete", json={"initData": tampered})
    assert resp.status_code == 401
    assert provisioning.is_provisioned(777) is False
    assert provisioning.is_provisioned(888) is False


def test_synthetic_email_never_needs_a_real_email_address():
    # The whole point: no email field anywhere in this flow.
    assert provisioning.synthetic_email(42) == "tg42@securitica.local"
