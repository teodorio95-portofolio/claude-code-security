"""secret_scan.py — refuses to write credentials to disk."""

from __future__ import annotations

import pytest
from conftest import write

HOOK = "secret_scan.py"

GHP = "ghp_" + "a" * 36
GLPAT = "glpat-" + "x" * 20
SK = "sk-" + "b" * 40

BLOCKED_CONTENT = [
    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEexample\n-----END RSA PRIVATE KEY-----",
    f'token = "{GHP}"',
    f'gitlab = "{GLPAT}"',
    f'openai = "{SK}"',
    'password = "S3cr3tP@ssw0rd!"',
]

ALLOWED_CONTENT = [
    "def add(a, b):\n    return a + b",
    'API_KEY = "your-key-here"',  # placeholder, excluded
    'password = "${DB_PASSWORD}"',  # env interpolation, excluded
    'token = os.environ["TOKEN"]',  # not a quoted literal
    "# how to store a secret: use an env var, never a file",
]


@pytest.mark.parametrize("content", BLOCKED_CONTENT)
def test_blocks_secret_writes(run_hook, content):
    assert run_hook(HOOK, write("config.py", content)).denied, content


@pytest.mark.parametrize("content", ALLOWED_CONTENT)
def test_allows_clean_writes(run_hook, content):
    assert not run_hook(HOOK, write("config.py", content)).denied, content


def test_scans_edit_new_string(run_hook):
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "x.py", "old_string": "k = 1", "new_string": f'k = "{SK}"'},
    }
    assert run_hook(HOOK, event).denied


def test_scans_multiedit(run_hook):
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "x.py",
            "edits": [
                {"old_string": "a", "new_string": "b"},
                {"old_string": "c", "new_string": f'token="{GHP}"'},
            ],
        },
    }
    assert run_hook(HOOK, event).denied
