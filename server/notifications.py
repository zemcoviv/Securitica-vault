"""Metadata-only account event notifications (BRIEF §6.2, §8, M4).

INVARIANT: this module only ever handles `kind` (a closed enum), a timestamp,
an IP, an optional device string, and an optional geo string. It has no path
to any cipher, key, or master phrase — the caller (server/main.py) receives
those fields from the client's /api/events request body and nothing else.

The thin backend sends the Telegram message directly (it already holds
BOT_TOKEN for initData HMAC verification) rather than relaying through the
aiogram bot process, keeping the notification path a single hop.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

TELEGRAM_API_BASE = "https://api.telegram.org"

VALID_EVENT_KINDS = frozenset({"login", "export", "master_password_changed"})

_LABELS = {
    "login": "🔓 New sign-in to your vault",
    "export": "📤 Vault export performed",
    "master_password_changed": "🔑 Master password changed",
}


@dataclass(frozen=True)
class AccountEvent:
    kind: str
    when: datetime
    ip: str | None = None
    geo: str | None = None
    device: str | None = None


def format_event(event: AccountEvent) -> str:
    """Render a metadata-only alert. No vault content can appear here."""
    label = _LABELS.get(event.kind, f"ℹ️ Account event: {event.kind}")
    when = event.when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [label, f"Time: {when}"]
    if event.device:
        lines.append(f"Device: {event.device}")
    if event.ip:
        loc = f" ({event.geo})" if event.geo else ""
        lines.append(f"IP: {event.ip}{loc}")
    lines.append("\nIf this wasn't you, lock the vault and rotate the master password.")
    return "\n".join(lines)


async def send_account_event(bot_token: str, chat_id: int, event: AccountEvent) -> None:
    """POST directly to the Telegram Bot API. Raises on failure (best-effort
    handling — not failing the caller's own flow — is the caller's job)."""
    text = format_event(event)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{TELEGRAM_API_BASE}/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
        )
        resp.raise_for_status()
