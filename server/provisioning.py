"""Per-Telegram-user account provisioning state (BRIEF §1 onboarding).

Tracks, per Telegram numeric user id, whether that user has completed
Vaultwarden account registration — purely a UX-routing signal ("show the
'set a password' screen" vs "show the 'enter your password' screen"), not a
security boundary. Getting this wrong in either direction just means the
wrong first-run screen shows once; it never grants or withholds vault access
(that's entirely Vaultwarden's own login, gated by the master password).

Each Telegram user maps to a deterministic synthetic email
(`tg<id>@securitica.local`) so the Mini App never has to ask for — or the
user ever has to think about — a real email address. This is not a
per-account secret; it's derived, and re-derivable at any time.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

_DB_PATH = Path(os.environ.get("PROVISIONING_DB_PATH", "/data/provisioning.sqlite3"))


def synthetic_email(telegram_user_id: int) -> str:
    return f"tg{telegram_user_id}@securitica.local"


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS provisioned (
            telegram_user_id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    return conn


def is_provisioned(telegram_user_id: int) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM provisioned WHERE telegram_user_id = ?",
            (telegram_user_id,),
        ).fetchone()
        return row is not None


def mark_provisioned(telegram_user_id: int) -> None:
    email = synthetic_email(telegram_user_id)
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO provisioned (telegram_user_id, email) VALUES (?, ?)",
            (telegram_user_id, email),
        )
        conn.commit()
