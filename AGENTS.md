# claude-code-security — agent context

Claude Code plugin (DevSecOps portfolio project #10) that adds security
guardrails around the coding agent: PreToolUse hooks, a read-only
security-reviewer subagent, and `/security-review` + `/threat-model` commands.
Runs on: local Claude Code, installed from this repo as a plugin marketplace.

## Commands
- `make test` — `uv run pytest -q`; every hook, blocked and allowed cases (safe).
- `make demo` — `python3 scripts/demo.py`: feeds each hook a malicious and a
  benign event and prints the verdict; no Claude, offline (safe).
- `make validate` — `claude plugin validate .`, or a JSON parse fallback when
  `claude` is missing.
- `make install` — only prints the install commands
  (`claude plugin marketplace add ...`, `/plugin install claude-code-security@teodorio-security`).
- Try without installing: `claude --plugin-dir .`.

## Layout
- `.claude-plugin/plugin.json` — plugin manifest (name, version); `marketplace.json`
  — marketplace `teodorio-security`, plugin source `./`.
- `hooks/hooks.json` — wiring: `Bash` -> `block_destructive.py` + `egress_allowlist.py`;
  `Write|Edit|MultiEdit` -> `secret_scan.py`; paths via `${CLAUDE_PLUGIN_ROOT}`.
- `hooks/_hooklib.py` — read the stdin event, emit allow (silent exit 0) or deny.
- `config/egress-allowlist.txt` — default-deny host list; an entry also matches subdomains.
- `agents/security-reviewer.md` — subagent limited to Read/Grep/Glob.
- `commands/security-review.md`, `commands/threat-model.md`.
- `docs/architecture.md` — full design; `tests/` — pytest per hook.

## How it works
- Claude Code runs each hook as a command with the event JSON on stdin before
  the tool runs; a deny prints `hookSpecificOutput.permissionDecision: "deny"`
  with a reason the agent sees.
- Hooks are stdlib-only Python run as plain `python3` (no venv);
  `pyproject.toml` (`package = false`) exists only for the test suite.
- `egress_allowlist` blocks `curl`/`wget` to hosts not in the allowlist;
  `secret_scan` blocks cloud/forge/chat keys, private keys and hard-coded credentials.
- `mirror-to-gitlab.yml` mirrors every branch and tag to GitLab on each push or
  delete (needs repo secret `GITLAB_TOKEN`); there is no test CI workflow.

## Gotchas
- `block_destructive` blocks only recursive `rm` of bare root/home/wildcard/`.`
  targets and top-level system dirs; `rm -f` of one file under home and quoted
  text that merely mentions `rm` must stay allowed (ee43c0d).
- Bump `version` in `.claude-plugin/plugin.json` on behaviour changes, or
  installed copies keep the old hooks (ee43c0d bumped it to 0.1.1).
  `pyproject.toml` has its own, unrelated version.
- Hosts added to an installed copy's allowlist are lost on plugin update;
  persist them in `config/egress-allowlist.txt` here (0e7a583).
- The hooks are heuristics, not a sandbox: obfuscated commands can bypass them.

## Related repos
- Portfolio siblings: `mcp-security-toolkit` (#6), `ai-security-lab` (#7),
  `mcp-gateway` (#9).
- GitLab mirror of this repo, kept in sync by `mirror-to-gitlab.yml`.

## Do not
- Do not add third-party dependencies to the hooks; they must run under bare `python3`.
- Do not widen the allowlist or relax a hook without a test for the new case.
- Do not put real secrets in tests or the demo; use fake key shapes, and only in
  paths `.gitleaks.toml` allowlists (`hooks/secret_scan.py`, `tests/`, `docs/`, `README.md`).
