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
import shlex

from _hooklib import allow, deny, read_event

# `rm` is special-cased: recursion and a dangerous target must belong to
# the same command. Force alone is safe; home subdirectories are not roots.
_RM_ROOT_TARGET = re.compile(
    r"(?:/|~/?|\$HOME/?|\*|\.{1,2}/?|(?:~|\$HOME)?/\*|"
    r"/(?:etc|usr|var|bin|sbin|lib|lib64|boot|sys|dev|proc|root|opt|home)/?)"
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
    lexer = shlex.shlex(command, posix=True, punctuation_chars="|;&()\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return False  # An incomplete shell command cannot execute as written.
    recursive = False
    targets = []
    in_rm = False
    options = True
    for token in tokens + [";"]:
        if token and all(ch in "|;&()\n" for ch in token):
            if recursive and any(_RM_ROOT_TARGET.fullmatch(t) for t in targets):
                return True
            recursive, in_rm, options = False, False, True
            targets = []
        elif not in_rm:
            if token in ("rm", "/bin/rm", "/usr/bin/rm"):
                in_rm = True
        elif options and token == "--":
            options = False
        elif options and token.startswith("-"):
            recursive |= token == "--recursive" or bool(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*", token))
        else:
            targets.append(token)
    return False


def main() -> None:
    command = (read_event().get("tool_input") or {}).get("command", "")
    if not command:
        allow()
    if _dangerous_rm(command):
        deny(
            "Blocked destructive command: recursive delete of a root/home/wildcard path. "
            "Run it yourself if you really mean to."
        )
    for pattern, reason in _RULES:
        if pattern.search(command):
            deny(f"Blocked destructive command: {reason}. Run it yourself if you really mean to.")
    allow()


if __name__ == "__main__":
    main()
