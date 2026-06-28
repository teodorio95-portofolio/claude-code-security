---
description: Produce a lightweight STRIDE threat model for a feature, component, or the current change.
argument-hint: "[feature/component to model — e.g. 'the file upload endpoint']"
allowed-tools: Read, Grep, Glob, Bash(git diff:*), Bash(git log:*)
---

Build a concise, practical threat model for: **$ARGUMENTS**

If no target was given, model the component touched by the current change
(inspect the diff: !`git diff --stat HEAD~1 2>/dev/null | head -40`).

## Method

1. **Map it** — what are the components, the trust boundaries, and the data
   flows? Where does data cross from less-trusted to more-trusted (or out)?
   Read the relevant code to ground this in reality, not guesses.
2. **Enumerate threats with STRIDE**, per element / data flow:
   - **S**poofing — can identity be faked?
   - **T**ampering — can data/code be modified in transit or at rest?
   - **R**epudiation — can an action be denied / is it audited?
   - **I**nformation disclosure — can secrets/PII leak?
   - **D**enial of service — can it be exhausted/crashed?
   - **E**levation of privilege — can someone do more than allowed?
3. For each credible threat: **likelihood × impact**, and the **mitigation**
   (validation, authZ, encryption, rate-limit, audit, least-privilege).

## Output

A short table: *Element → Threat (STRIDE) → Risk → Mitigation*, then the **top 3
things to fix first** and any explicit **assumptions / out-of-scope** items.
Keep it actionable — a model someone can act on, not a checklist dump.
