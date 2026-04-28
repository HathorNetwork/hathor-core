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

**Output of this step is an inventory, not rules.** Do NOT promote
entries directly to `RULE-XX` — they must pass the Step 4 filter first.

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

### Step 4: Filter and draft rules

**Filter first.** For every inventoried behavior, ask:

> If someone rewrote this module from scratch — different file layout,
> different function names, different library primitives — while
> preserving the feature's externally observable contract, would this
> rule still be true?

- **Yes** → it's a spec rule. Promote it.
- **No** → it's implementation detail. It belongs in the RFC that
  proposes *this* implementation, not in the forever-spec. Drop it
  from the draft.
- **Sometimes** → split it. Keep the behavioral half; drop the
  structural half.

**Then draft.** Translate each surviving behavior into a RULE-XX using
MUST / MUST NOT / SHOULD / SHOULD NOT. Each rule:

- States one requirement.
- Names the **observable surface** it applies to — the place a test or
  an integrator would see it: CLI input, wire/file format, peer
  admission outcome, HTTP endpoint, operator-visible state, log
  message the operator relies on.
- Is testable from outside the module (by a test, an integrator, or an
  operator) without peeking at private fields.

Number rules starting at RULE-01, in the order a reader would encounter
them (initialization → steady state → shutdown → error paths).

#### Rule smells — reject or rewrite

The following patterns almost always indicate implementation bleed:

- **Names a private field** (`_current`, `_has_successful_fetch`,
  `_consecutive_failures`). Rewrite as observable state ("the active
  whitelist", "the grace-period flag", "the failure count that drives
  backoff").
- **Names a function, method, or class** (`create_peers_whitelist`,
  `URLPeersWhitelist._unsafe_update`, `_apply_whitelist_update`). The
  rule should describe *what* happens on an event, not which callable
  does it.
- **Names a file path** (`hathor_cli/builder.py`,
  `hathor/p2p/whitelist/factory.py`). Paths move in refactors; the
  rule shouldn't.
- **Names a library primitive** (`LoopingCall`, `Deferred`,
  `deferToThread`, `Agent`). Describe the behavior (periodic
  refresh, async, non-blocking I/O, HTTP GET) — not the library.
- **Asserts a specific exception class or message**
  (`ValueError('invalid header')`). Unless the exact class or text is
  part of a public API other code depends on, say "MUST be rejected"
  and let the RFC/implementation choose the mechanism.
- **Numbered steps that mirror source-file order.** If the rule is a
  1-to-1 transcription of a function body, it's a procedure, not a
  contract. Either collapse to the invariant ("state is updated
  before callbacks fire, so re-entrant checks observe the new state")
  or move the step-by-step to the RFC.

If a rule needs an *architectural* decision to remain true (e.g. "file
I/O must not block the reactor"), keep it — but write it as the
architectural invariant, not as "uses `deferToThread`". The
architecture belongs in the spec; the primitive that realizes it
belongs in the RFC.

### Step 5: Draft decisions

For every non-obvious choice, write a DEC-XX with:

- Chosen alternative.
- Rejected alternative(s) — mine these from comments, discarded
  branches in git history, or adjacent modules that chose differently.
- Reason for rejection. If unknown, mark `?` for the author.

### Step 6: Constants

Extract every magic number, timeout, interval, and limit into the
constants table with:

- **Name** — the operator- or reader-facing name of the constant.
- **Value** and **unit**.
- **Purpose** — the *intent*, not the object that owns it. Write
  "Refresh period for the whitelist", not "Period of the refresh
  `LoopingCall`". If the purpose isn't clear from the constant's
  name and value, that's a hint the constant itself is under-named.
- **Justification** — only if mineable. Why *this* value? `?` if
  unknown.

Do NOT include a "Defined in" / "Module" / "Class" column. Where the
constant lives is an implementation detail.

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
- **Do NOT write implementation-bleed rules.** Rules describe the
  feature's external contract, not the current code's shape. If a
  rule stops being true after a behavior-preserving refactor, it is
  over-specified — demote it to the RFC that proposed the current
  implementation, or rewrite it in terms of the observable
  invariant. See Step 4's rule-smell list.
- Prefer many small, atomic rules to few compound rules. The reviewer
  prompts are designed around per-rule granularity.
- The output is a **draft**. Expect the human author to rewrite half
  of it. The value is the inventory and the `?` list, not prose
  polish.

## What belongs in the spec vs. in the RFC

The spec is the forever-contract: behaviors the feature guarantees no
matter who implements it or how. The RFC is the change narrative for a
specific implementation or modification.

| Belongs in the **spec** (RULE-XX / DEC-XX) | Belongs in the **RFC** |
|---|---|
| CLI flag names and accepted values | Which module parses them |
| Wire / file formats (headers, ordering, encoding) | Which function does the parsing |
| State machine: states, transitions, triggers | Private field names that encode the state |
| Constants: value, unit, intent | File the constant lives in |
| Error outcomes visible to peers / operators / callers | Exact exception class or message text (unless part of a public contract) |
| Architectural invariants ("file I/O MUST NOT block the reactor") | Mechanism that realizes them (`deferToThread`, thread pool size) |
| Observable ordering guarantees ("state updated before disconnect callbacks") | Which lines of which function enforce the ordering |
| HTTP endpoint paths, field names, and shapes | Resource class that serves them |

When in doubt: if the sentence only makes sense to someone reading
*this specific codebase today*, it's an RFC-level detail. If it makes
sense to someone integrating against the feature from outside, it's a
spec rule.
