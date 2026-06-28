#!/usr/bin/env python3
"""PreToolUse(Write|Edit|MultiEdit): block writing secrets to disk.

Scans the content the agent is about to write/edit and denies the call if it
contains a credential. Stops the agent from committing an API key, private key
or token into a file (where it would then be hard to scrub from git history).
Pattern-based and deterministic — names the rule that fired, never echoes the
secret.
"""

from __future__ import annotations

import re

from _hooklib import allow, deny, read_event

# (rule name, pattern). High-signal credential shapes.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI/Anthropic-style key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    # Generic assignment: password/secret/token/api_key = "longish value",
    # excluding obvious placeholders.
    (
        "hard-coded credential assignment",
        re.compile(
            r"""(?ix)
            \b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b
            \s*[:=]\s*
            ['"](?!.*(?:changeme|example|placeholder|your[_-]?|xxxx|<|\$\{|\$\(|env\.))
            [^'"\s]{8,}['"]
            """
        ),
    ),
]


def _content(event: dict) -> str:
    """The text being written, across Write / Edit / MultiEdit shapes."""
    ti = event.get("tool_input") or {}
    parts = [ti.get("content", ""), ti.get("new_string", "")]
    for edit in ti.get("edits") or []:
        if isinstance(edit, dict):
            parts.append(edit.get("new_string", ""))
    return "\n".join(p for p in parts if p)


def main() -> None:
    text = _content(read_event())
    if not text:
        allow()
    for name, pattern in _RULES:
        if pattern.search(text):
            deny(
                f"Refused to write a secret to disk: looks like a {name}. "
                f"Use an env var or a secrets manager, not a file."
            )
    allow()


if __name__ == "__main__":
    main()
