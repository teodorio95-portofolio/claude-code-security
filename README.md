# claude-code-security

> Project **#10** of the DevSecOps portfolio: a **Claude Code plugin** that puts
> security guardrails around the agent that writes your code. Install it **once**
> and every project gets the same protections — `PreToolUse` hooks that block
> destructive commands, enforce a network egress allowlist and stop secrets being
> written to disk, plus a read-only **security-reviewer** subagent and
> `/security-review` + `/threat-model` commands.

This is project **#7 (runtime security of AI agents) applied to your dev tool**:
the agent that edits your repo is itself an agent that can be prompt-injected or
make mistakes — so it deserves the same guardrails. Packaged as a plugin, it's
the "install once, secure everywhere" answer instead of copying files per repo.

| # | Project | Role |
|---|---------|------|
| 6 | mcp-security-toolkit | Security scanners exposed as MCP tools |
| 7 | ai-security-lab | Runtime security of AI/LLM agents (OWASP LLM Top 10) |
| 9 | mcp-gateway | Security proxy in front of an MCP server |
| **10** | **claude-code-security** *(this repo)* | **Security guardrails for Claude Code itself (hooks, subagent, commands)** |

## What it gives you

| Component | Type | What it does |
|-----------|------|--------------|
| **block_destructive** | `PreToolUse(Bash)` hook | Blocks `rm -rf /`/`~`/system dirs, fork bombs, `dd of=/dev/…`, `mkfs`, `curl … \| sh`, force-push to main |
| **egress_allowlist** | `PreToolUse(Bash)` hook | Default-deny network: blocks `curl`/`wget` to hosts not in `config/egress-allowlist.txt` |
| **secret_scan** | `PreToolUse(Write\|Edit)` hook | Blocks writing AWS/GitHub/GitLab/Slack/Google/OpenAI keys, private keys, or hard-coded credentials to disk |
| **security-reviewer** | subagent | Read-only (Read/Grep/Glob) security review — policy-as-code: it *can't* edit or run anything |
| **/security-review** | command | Reviews the branch diff (delegates to the subagent), findings by severity |
| **/threat-model** | command | A lightweight STRIDE threat model for a feature or change |

Hooks **deny** with a clear reason the agent sees (verified against the Claude
Code hooks schema: `permissionDecision: "deny"`). They are **stdlib-only Python**,
so they run as plain `python3` commands with no venv.

## Install (once, works in every project)

```bash
# add this repo as a plugin marketplace, then install the plugin:
claude plugin marketplace add teodorio95-portofolio/claude-code-security
# in Claude Code:
/plugin install claude-code-security@teodorio-security
```

Or try it without installing:

```bash
claude --plugin-dir /path/to/claude-code-security
```

Commands are namespaced by the plugin: `/claude-code-security:security-review`,
`/claude-code-security:threat-model`. Tune the egress allowlist in
[config/egress-allowlist.txt](config/egress-allowlist.txt).

## See it work — no Claude, free

```bash
make demo     # feeds each hook a malicious + a benign event, shows the verdict
make test     # 42 tests: every hook, blocked and allowed cases (uv run pytest)
```

`make demo` output (abridged):

```
block_destructive.py   rm -rf /                        DENY   ✓
block_destructive.py   rm -rf ./build                  allow  ✓
egress_allowlist.py    curl https://evil.example.com   DENY   ✓
egress_allowlist.py    curl https://api.github.com     allow  ✓
secret_scan.py         write AKIA… key                 DENY   ✓
secret_scan.py         write normal code               allow  ✓
```

## How a hook works

Claude Code runs each hook as a command, passing the event as JSON on stdin
*before* the tool runs. The hook inspects `tool_input` and either stays silent
(allow) or prints a deny decision:

```python
# hooks/secret_scan.py (abridged)
event = read_event()                     # {"tool_name":"Write","tool_input":{"content":...}}
if SECRET_PATTERN.search(content):
    deny("Refused to write a secret to disk: looks like a GitHub token.")
allow()
```

Wiring lives in [hooks/hooks.json](hooks/hooks.json) (the same format as
`settings.json`), with paths via `${CLAUDE_PLUGIN_ROOT}`. Full design in
[docs/architecture.md](docs/architecture.md).

## Repository layout

```
claude-code-security/
├── .claude-plugin/
│   ├── plugin.json              # plugin manifest (name, version, …)
│   └── marketplace.json         # so the repo is installable via /plugin
├── hooks/
│   ├── hooks.json               # PreToolUse wiring (Bash → 2 hooks, Write/Edit → secret scan)
│   ├── _hooklib.py              # read stdin event, emit allow/deny (stdlib)
│   ├── block_destructive.py
│   ├── egress_allowlist.py
│   └── secret_scan.py
├── agents/security-reviewer.md  # read-only review subagent (policy-as-code)
├── commands/
│   ├── security-review.md       # /security-review
│   └── threat-model.md          # /threat-model
├── config/egress-allowlist.txt  # trusted hosts (editable, default-deny)
├── tests/                       # pytest: each hook, blocked + allowed
├── scripts/demo.py              # offline before/after demo
├── Makefile                     # test / demo / validate / install / help
└── docs/architecture.md
```

## ⚠️ Note

The hooks are **defense-in-depth heuristics, not a sandbox** — they raise the bar
against an agent doing something destructive or leaky, but a determined bypass is
possible (obfuscated commands, paths they don't model). Keep using real
permissions and review. The egress allowlist and secret patterns are starting
points: tune them to your projects.
