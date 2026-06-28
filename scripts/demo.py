"""Demo the hooks — feed each one a malicious and a benign event, show the verdict.

Runs the hooks exactly as Claude Code does (JSON on stdin), with no Claude and no
cost. Mirrors the attack -> blocked story of the rest of the portfolio.

    python3 scripts/demo.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_HOOKS = Path(__file__).resolve().parents[1] / "hooks"

GREEN, RED, DIM, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def run(script: str, event: dict) -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, str(_HOOKS / script)], input=json.dumps(event), capture_output=True, text=True
    )
    out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    hso = out.get("hookSpecificOutput", {})
    return hso.get("permissionDecision") == "deny", hso.get("permissionDecisionReason", "")


def bash(cmd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def write(content: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": "config.py", "content": content}}


CASES = [
    ("block_destructive.py", "rm -rf /", bash("rm -rf /"), True),
    ("block_destructive.py", "rm -rf ./build", bash("rm -rf ./build"), False),
    ("egress_allowlist.py", "curl https://evil.example.com", bash("curl https://evil.example.com/x"), True),
    ("egress_allowlist.py", "curl https://api.github.com", bash("curl https://api.github.com/x"), False),
    ("secret_scan.py", "write AKIA… key", write('K = "AKIAIOSFODNN7EXAMPLE"'), True),
    ("secret_scan.py", "write normal code", write("def add(a, b):\n    return a + b"), False),
]


def main() -> None:
    print(f"{DIM}hook{OFF:<22} {DIM}input{OFF:<34} verdict")
    for script, label, event, expect_block in CASES:
        denied, reason = run(script, event)
        mark = f"{RED}DENY{OFF}" if denied else f"{GREEN}allow{OFF}"
        ok = "✓" if denied == expect_block else "✗ UNEXPECTED"
        print(f"  {script:<24} {label:<34} {mark}  {ok}")
        if denied:
            print(f"      {DIM}{reason}{OFF}")


if __name__ == "__main__":
    main()
