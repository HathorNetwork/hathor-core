# Shared conventions for review prompts

All prompts in this directory follow the conventions below. Each prompt links
back here instead of restating them.

## Inputs & how to locate them

Unless the user supplies explicit paths, locate inputs as follows:

- **RFC**: under [`docs/rfcs/`](../rfcs/). The PR description or branch name
  usually names it. If multiple RFCs are in flight, ask the user which one
  applies.
- **Feature spec**: lives next to the feature it describes
  (e.g. [`docs/p2p/peer-whitelist.md`](../p2p/peer-whitelist.md)). The RFC's
  "Spec impact" section cites the spec path.
- **Base branch**: `master` unless the user says otherwise.
- **Diff**: `git diff <base>...HEAD` for the current branch. Do not review
  uncommitted working-tree changes unless the user asks.
- **Full codebase for a feature**: start from the spec's "Reference" section
  (modules, classes, entry points). Expand outward only when following a
  call path; stop at shared infrastructure that is not feature-specific.

If a required input is missing (no spec, no RFC, no base branch), stop and
report what's missing — do not guess.

## Traceability header

Every review output MUST begin with a traceability header so stacked reviews
remain auditable long after the PR lands:

```markdown
**Inputs**
- RFC: `docs/rfcs/NNNN-slug.md` @ commit `<short-sha>`
- Spec: `docs/<path>.md` @ commit `<short-sha>`
- Code: branch `<branch>` @ commit `<short-sha>` (base `<base-sha>`)
- Reviewed on: `<YYYY-MM-DD>`
```

Omit lines that do not apply to a given prompt (e.g. an RFC↔Spec review has
no code commit).

## Severity ladder

Use one ladder across all prompts:

| Severity | Meaning | Gate |
|---|---|---|
| **Blocking** | Correctness, security, peer admission, data integrity, or a stated invariant (RULE-XX / DEC-XX) is violated. | FAIL |
| **Important** | Operational concern (error handling, logging, performance, observability) that should be fixed but does not break the contract. | PASS WITH NOTES |
| **Minor** | Implementation detail with no external effect (naming, log format, internal refactor). | PASS WITH NOTES |
| **Informational** | Observation the author may want to know, not a defect. | PASS |

Verdict mapping: any Blocking ⇒ **FAIL**. Otherwise, any Important or Minor ⇒
**PASS WITH NOTES**. No findings ⇒ **PASS**.

## Scope discipline

- Stay inside the prompt's stated edge. Do not re-review code quality in an
  RFC review, or RFC hygiene in a code review. A dedicated prompt exists for
  each concern.
- Quote the source on every finding: the RFC passage, the spec rule, or the
  file:line. A finding without a citation is not actionable.
- When a finding straddles artifacts (the spec and the code disagree), do
  not decide which is correct. State the conflict and flag it for the author.
