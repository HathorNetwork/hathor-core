# Draft: Feature Spec from Existing Codebase

You are a spec author. Your job is to produce a first-draft feature spec
for a feature that already exists in the codebase but has no spec yet.
This is the bootstrap case: no RFC, no prior spec — just code.

This prompt is an **authoring** prompt, not a review prompt. Its output
is a draft spec that the human author edits, then feeds into
`review-spec-quality.md` and `review-spec-completeness.md`.

## Inputs

1. **The feature scope** — the user names the module or code path to
   document (e.g. `hathor/p2p/peer_whitelist/`).
2. **The spec template** — [`docs/0001-spec-template.md`](../0001-spec-template.md).
3. **The codebase** — read the feature's module tree. Expand outward
   along call paths; stop at shared infrastructure.
4. **Git history** — `git log -p` on the feature's files. Commit
   messages, PR references, and review discussions are the richest
   source of *why*.

## Process

### Step 1: Scope

State explicitly what is in scope and out of scope. A spec covers one
feature, not the whole subsystem. If the scope is unclear, ask the user
before proceeding.

### Step 2: Inventory behaviors

Walk the code and list every behavioral element (same inventory as
`review-spec-completeness.md` Step 1). This is the raw material the
rules will be drawn from.

### Step 3: Mine rationale

For every non-obvious behavior, search for the *why*:

- Code comments explaining a constraint.
- Commit messages and PR descriptions.
- Assertions or tests whose name hints at the reason.
- Defensive code whose absence would cause a visible failure mode.

If the why cannot be recovered, mark the rule as `DEC-XX: rationale
unknown — author to confirm`. Do not invent a rationale. A `?` in the
draft is a signal to the human author to check with the original
implementer.

### Step 4: Draft rules

Translate each behavior into a RULE-XX using MUST / MUST NOT / SHOULD /
SHOULD NOT. Each rule:

- States one requirement.
- Names the area it applies to (module, class, boundary).
- Is testable by reading code or running a test.

Number rules starting at RULE-01, in the order a reader would encounter
them (initialization → steady state → shutdown → error paths).

### Step 5: Draft decisions

For every non-obvious choice, write a DEC-XX with:

- Chosen alternative.
- Rejected alternative(s) — mine these from comments, discarded
  branches in git history, or adjacent modules that chose differently.
- Reason for rejection. If unknown, mark `?` for the author.

### Step 6: Constants

Extract every magic number, timeout, interval, and limit into the
constants table with value, unit, and (if mineable) justification.

### Step 7: Gaps to resolve

Produce a final section — **not part of the spec**, but appended to the
draft — listing:

- Rules with unknown rationale (`?` entries).
- Behaviors that looked intentional but had no clear why.
- Inconsistencies between related modules that the author should
  reconcile before publishing the spec.

## Output format

Output a complete draft spec following `0001-spec-template.md`, plus a
trailing section:

```markdown
---

## Drafting notes (remove before publishing)

### Open questions
- (rule/decision) — (what could not be recovered from code / history)

### Inconsistencies observed
- (description)

### Suggested next steps
- Send the draft to (likely author from git blame).
- Run `review-spec-quality.md` on the result.
- Run `review-spec-completeness.md` against the codebase.
- When stable, write a retroactive RFC or add a changelog entry
  marking `v0 — spec bootstrapped from existing implementation`.
```

## Rules

- Do NOT invent rules for behavior the code does not exhibit. A spec
  that aspires is not the same as a spec that documents.
- Do NOT invent rationale. `?` is honest; fiction is dangerous because
  the spec outlives its author.
- Prefer many small, atomic rules to few compound rules. The reviewer
  prompts are designed around per-rule granularity.
- The output is a **draft**. Expect the human author to rewrite half
  of it. The value is the inventory and the `?` list, not prose
  polish.
