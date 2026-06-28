"""Shared helpers for the PreToolUse hooks — stdlib only, no dependencies.

Claude Code runs each hook as a plain command, feeds the event as JSON on stdin,
and reads the decision back. A hook either stays silent (exit 0, no output ->
defer to the normal permission flow) or denies the tool call by emitting a
PreToolUse decision (verified against the hooks schema):

    {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "<why>"
      }
    }
"""

from __future__ import annotations

import json
import sys
from typing import Any


def read_event() -> dict[str, Any]:
    """Parse the hook event from stdin (returns {} on bad/empty input)."""
    try:
        return json.loads(sys.stdin.read() or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}


def deny(reason: str) -> None:
    """Block the tool call and tell Claude why, then exit."""
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def allow() -> None:
    """Stay out of the way — defer to the normal permission flow."""
    sys.exit(0)
