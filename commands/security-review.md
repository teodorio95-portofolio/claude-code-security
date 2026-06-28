---
description: Security-review the current branch diff (or given files) and report findings by severity.
argument-hint: "[path or file globs — optional; defaults to the branch diff]"
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git merge-base:*), Read, Grep, Glob, Agent
---

Run a security review and report findings grouped by severity.

## Scope

Target: **$ARGUMENTS**

If no target was given, review the current branch's diff against its base:

- Base: !`git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || echo HEAD~1`
- Changed files: !`git diff --name-only "$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || echo HEAD~1)" 2>/dev/null`
- Diff: !`git diff "$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || echo HEAD~1)" 2>/dev/null | head -800`

## What to do

Delegate the analysis to the **security-reviewer** subagent (read-only), pointing
it at the changed files / diff above. Then present its findings:

1. Group by **Critical / High / Medium / Low**.
2. For each: what & where (`file:line`), why it's exploitable, and the fix.
3. Focus on the usual sinks — shell, SQL, filesystem paths, deserialization,
   network/SSRF, secrets, auth — and on untrusted input reaching them.

End with a clear verdict: **safe to merge** or **needs changes**. Don't invent
issues; if the diff is clean, say so.
