"""Programmatic Vaultwarden admin actions (invite-only account provisioning,
BRIEF §1: the Mini App drives onboarding directly, no admin panel clicking).

This is the ONLY place ADMIN_TOKEN is used, and it is used exactly the way a
human operator would through the admin panel — log in, get the session
cookie, invite an email — just automated and gated by initData-verified
Telegram identity instead of a person. ADMIN_TOKEN never appears in any
request to or from the Mini App client; it only ever travels
server-to-server, directly to Vaultwarden over the internal docker network.

Vaultwarden's admin auth (confirmed against 1.32.7 source) has no bearer-token
shortcut: POST /admin/ with the raw token as a form field sets a VW_ADMIN JWT
cookie, which POST /admin/invite then requires. SIGNUPS_ALLOWED stays false;
this relies on the Invitation-record path Vaultwarden's own registration
handler checks first, deliberately independent of that setting.
"""

from __future__ import annotations

import httpx


class VaultwardenAdminError(Exception):
    pass


async def invite_user(vaultwarden_url: str, admin_token: str, email: str) -> None:
    """Ensure a pending Invitation record exists for `email`. Idempotent:
    Vaultwarden rejects inviting an email that already has a user/invitation
    row, and we treat that as success — the precondition we actually care
    about (registration is now possible for this email) already holds.
    """
    base = vaultwarden_url.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        login_resp = await client.post(f"{base}/admin/", data={"token": admin_token})
        if login_resp.status_code >= 400:
            raise VaultwardenAdminError(
                f"admin login failed: {login_resp.status_code}"
            )
        if not client.cookies.get("VW_ADMIN"):
            raise VaultwardenAdminError("admin login did not return a VW_ADMIN cookie")

        # The client's own cookie jar already carries VW_ADMIN from the
        # login response above — no need to attach it manually.
        invite_resp = await client.post(f"{base}/admin/invite", json={"email": email})
        # Any 4xx here means Vaultwarden considers the email already
        # known (user or pending invitation) — exactly the state we want,
        # so it is not an error for our purposes. Only a server-side (5xx)
        # failure or an auth problem is worth surfacing.
        if invite_resp.status_code >= 500:
            raise VaultwardenAdminError(
                f"invite failed: {invite_resp.status_code}: {invite_resp.text[:200]}"
            )
