"""Securitica bot — aiogram v3 (BRIEF §6.2).

Role 1 (control plane): a button that launches the Mini App (WebView) and a few
allowlisted management commands. Role 2 (notifications) lives in notify.py.

INVARIANTS (BRIEF §2):
  - No secret is ever routed through the Bot API — not in messages, not in
    callback_data, not in inline mode. The bot cannot read vault contents.
  - BOT_TOKEN is the bot's identity; its leak = spoofing. Keep it in secrets.
  - DMs from non-allowlisted chats are rejected.
"""

from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    WebAppInfo,
)

from auth import is_allowed, is_management_allowed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securitica.bot")

BOT_TOKEN = os.environ["BOT_TOKEN"]
MINIAPP_URL = os.environ.get("MINIAPP_URL", "https://vault.example.com/")

dp = Dispatcher()


def _launch_keyboard() -> InlineKeyboardMarkup:
    # Launches the Mini App WebView. No secret is ever encoded in this URL.
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔐 Open vault",
                    web_app=WebAppInfo(url=MINIAPP_URL),
                )
            ]
        ]
    )


@dp.message(Command("start"))
async def cmd_start(message: Message) -> None:
    chat_id = message.chat.id
    if not is_allowed(chat_id):
        logger.warning("rejected /start from non-allowlisted chat_id=%s", chat_id)
        await message.answer("Access denied.")
        return
    await message.answer(
        "Securitica Vault — zero-knowledge password manager.\n"
        "Tap below to open the vault. Your master password never leaves your device.",
        reply_markup=_launch_keyboard(),
    )


@dp.message(Command("status"))
async def cmd_status(message: Message) -> None:
    if not is_management_allowed(message.chat.id):
        await message.answer("Access denied.")
        return
    await message.answer("Securitica bot is up. Vault backend is reachable via the Mini App.")


@dp.message(F.text)
async def fallback(message: Message) -> None:
    # Reject everything else from non-allowlisted chats; never echo content.
    if not is_allowed(message.chat.id):
        await message.answer("Access denied.")
        return
    await message.answer("Use /start to open the vault.", reply_markup=_launch_keyboard())


async def main() -> None:
    if not os.environ.get("ALLOWLIST_CHAT_IDS"):
        logger.warning("ALLOWLIST_CHAT_IDS is empty — bot will reject everyone.")
    bot = Bot(token=BOT_TOKEN)
    logger.info("Securitica bot starting (allowlist enforced).")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
