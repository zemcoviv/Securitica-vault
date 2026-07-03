"""Regression test: the bot must configure both the "/" command list and the
persistent Menu button (☰ next to the message box) on startup — without
these, opening the bot shows no way to launch the Mini App beyond typing
/start by hand and hoping the chat_id is allowlisted.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bot"))

os.environ.setdefault("BOT_TOKEN", "123456:TEST_BOT_TOKEN_do_not_use_in_prod")

import pytest  # noqa: E402

import main as bot_main  # noqa: E402
from aiogram.types import BotCommand, MenuButtonWebApp  # noqa: E402


@pytest.mark.asyncio
async def test_configure_bot_ui_sets_commands_and_menu_button():
    bot = AsyncMock()
    await bot_main._configure_bot_ui(bot)

    bot.set_my_commands.assert_awaited_once()
    (commands,), _ = bot.set_my_commands.await_args
    assert all(isinstance(c, BotCommand) for c in commands)
    assert {c.command for c in commands} == {"start", "status"}

    bot.set_chat_menu_button.assert_awaited_once()
    _, kwargs = bot.set_chat_menu_button.await_args
    menu_button = kwargs["menu_button"]
    assert isinstance(menu_button, MenuButtonWebApp)
    assert menu_button.web_app.url == bot_main.MINIAPP_URL
