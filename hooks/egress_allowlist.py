#!/usr/bin/env python3
"""PreToolUse(Bash): allow network egress only to allowlisted hosts.

A prompt-injected or confused agent that can reach the network can exfiltrate
data or pull in malicious code. This hook extracts the http(s) hosts a Bash
command would contact and denies the call if any host is not on the allowlist
(`config/egress-allowlist.txt`). Default-deny for the network, allowlist for the
hosts you trust.

The allowlist is found via $CLAUDE_PLUGIN_ROOT (set when running as a plugin),
or relative to this file, or $CCSEC_ALLOWLIST for tests.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hooklib import allow, deny, read_event

# Hosts in URLs the command would contact.
_URL_HOST = re.compile(r"https?://(?:[^/@\s'\"]*@)?([^/:\s'\"]+)", re.IGNORECASE)


def _allowlist_path() -> Path:
    if override := os.environ.get("CCSEC_ALLOWLIST"):
        return Path(override)
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    base = Path(root) if root else Path(__file__).resolve().parent.parent
    return base / "config" / "egress-allowlist.txt"


def _load_allowlist() -> set[str]:
    path = _allowlist_path()
    if not path.exists():
        return set()
    hosts: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            hosts.add(line)
    return hosts


def _is_allowed(host: str, allowlist: set[str]) -> bool:
    host = host.lower().strip(".")
    # exact match, or a subdomain of an allowlisted domain
    return any(host == a or host.endswith("." + a) for a in allowlist)


def main() -> None:
    event = read_event()
    command = (event.get("tool_input") or {}).get("command", "")
    hosts = {h for h in _URL_HOST.findall(command)}
    if not hosts:
        allow()  # no network egress in this command
    allowlist = _load_allowlist()
    blocked = sorted(h for h in hosts if not _is_allowed(h, allowlist))
    if blocked:
        deny(
            f"Network egress to non-allowlisted host(s): {', '.join(blocked)}. "
            f"Add them to config/egress-allowlist.txt if this is intended."
        )
    allow()


if __name__ == "__main__":
    main()
