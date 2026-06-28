"""Account-event notifications (BRIEF §6.2, role 2).

INVARIANT (BRIEF §2, §8): notifications carry **metadata only** — time, IP/geo,
device. Never a byte of vault content, never a secret, never anything routed
through Bot API that could be a record field. This module deliberately has no
access to ciphers or keys; it only formats event metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AccountEvent:
    kind: str  # "login" | "export" | "master_password_changed"
    when: datetime
    ip: str | None = None
    geo: str | None = None
    device: str | None = None


_LABELS = {
    "login": "🔓 New sign-in to your vault",
    "export": "📤 Vault export performed",
    "master_password_changed": "🔑 Master password changed",
}


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


async def notify_account_event(bot, chat_id: int, event: AccountEvent) -> None:
    """Send a metadata-only alert to an allowlisted chat."""
    await bot.send_message(chat_id, format_event(event))
