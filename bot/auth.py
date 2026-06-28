"""Authorization for the bot (BRIEF §6.2).

The bot is a control plane + notification channel ONLY. It has no access to vault
contents in principle. Management commands are gated behind an allowlist of
Telegram ``chat_id``s; DMs from anyone not on the allowlist are rejected.
"""

from __future__ import annotations

import os


def _parse_allowlist(raw: str) -> frozenset[int]:
    ids: set[int] = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            continue
    return frozenset(ids)


# Comma-separated chat_ids, e.g. ALLOWLIST_CHAT_IDS="111,222".
ALLOWLIST: frozenset[int] = _parse_allowlist(os.environ.get("ALLOWLIST_CHAT_IDS", ""))


def is_allowed(chat_id: int) -> bool:
    """True if the chat may use launcher + management commands."""
    return chat_id in ALLOWLIST


def is_management_allowed(chat_id: int) -> bool:
    """Management commands use the same allowlist for now (BRIEF §6.2).

    Kept separate so a stricter admin subset can be split out later without
    touching call sites.
    """
    return is_allowed(chat_id)
