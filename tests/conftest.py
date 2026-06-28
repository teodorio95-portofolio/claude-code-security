"""Test harness: run a hook script exactly as Claude Code would (JSON on stdin)."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

_HOOKS = Path(__file__).resolve().parents[1] / "hooks"


@dataclass
class HookResult:
    code: int
    decision: dict | None

    @property
    def denied(self) -> bool:
        out = (self.decision or {}).get("hookSpecificOutput", {})
        return out.get("permissionDecision") == "deny"

    @property
    def reason(self) -> str:
        return (self.decision or {}).get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


@pytest.fixture
def run_hook():
    def _run(script: str, event: dict) -> HookResult:
        proc = subprocess.run(
            [sys.executable, str(_HOOKS / script)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
        )
        decision = json.loads(proc.stdout) if proc.stdout.strip() else None
        return HookResult(proc.returncode, decision)

    return _run


def bash(command: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


def write(path: str, content: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": path, "content": content},
    }
