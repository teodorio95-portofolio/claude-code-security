#!/usr/bin/env python3
"""PreToolUse(Bash): block irreversibly destructive shell commands.

Catches the classic foot-guns an agent should never run unprompted — recursive
deletes of important paths, disk-wiping, fork bombs, and `curl … | sh` pipes
that execute remote code. Heuristic by design: it errs toward blocking the
obviously dangerous, and stays silent otherwise (you can always run these
yourself outside the agent).
"""

from __future__ import annotations

import re

from _hooklib import allow, deny, read_event

# `rm` is special-cased: dangerous only when it is BOTH recursive/forced AND
# aimed at a root / home / wildcard / current-dir target.
_RM_RECURSIVE_FORCE = re.compile(r"\brm\b[^|;&\n]*\s-[a-zA-Z]*[rf]")
_RM_ROOT_TARGET = re.compile(
    r"""(?x)
    \s(?:/|~|\$HOME|\*|\.\.?)(?:\s|/?$)                    # bare /  ~  $HOME  *  .  ..
    | \s(?:~/|/(?:etc|usr|var|bin|sbin|lib|lib64|boot|sys|dev|proc|root|opt|home))\b
    """
)

# (compiled pattern, human reason) for the remaining one-shot dangers.
_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/(sd|nvme|disk|vd)"), "raw write to a disk device (dd of=/dev/…)"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "filesystem format (mkfs)"),
    (re.compile(r">\s*/dev/(sd|nvme|disk|vd)\w*"), "redirect over a disk device"),
    (re.compile(r"\bchmod\s+(-[a-zA-Z]*\s+)*(-R|--recursive)\s+0*777\s+/"), "chmod -R 777 on a root path"),
    (
        re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b"),
        "piping a downloaded script straight into a shell (curl … | sh)",
    ),
    (
        re.compile(r"\bgit\b.*\bpush\b.*--force\b.*\b(origin|upstream)\s+(main|master)\b"),
        "force-push to a protected branch",
    ),
]


def _dangerous_rm(command: str) -> bool:
    return bool(_RM_RECURSIVE_FORCE.search(command) and _RM_ROOT_TARGET.search(command))


def main() -> None:
    command = (read_event().get("tool_input") or {}).get("command", "")
    if not command:
        allow()
    if _dangerous_rm(command):
        deny(
            "Blocked destructive command: recursive force-delete of a root/home/wildcard path. "
            "Run it yourself if you really mean to."
        )
    for pattern, reason in _RULES:
        if pattern.search(command):
            deny(f"Blocked destructive command: {reason}. Run it yourself if you really mean to.")
    allow()


if __name__ == "__main__":
    main()
