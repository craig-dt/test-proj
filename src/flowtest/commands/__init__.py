"""Command registry. Each command module exposes register(subparsers); add one line here per command."""

from __future__ import annotations

from flowtest.commands import top_talkers

COMMANDS = (top_talkers,)
