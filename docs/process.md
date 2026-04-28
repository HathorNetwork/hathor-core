# RFC / Spec / Code — the consistency triangle

Changes to Hathor core are described across three artifacts — RFC, feature
spec, and code — with a set of review prompts that enforce consistency
between them and sanity-check each artifact in isolation.

```
                RFC  (the change narrative)
                 /\
                /  \
               /    \
              /      \
             /        \
            /          \
           /            \
         Code ────────── Spec
    (the implementation)  (the testable truth)
```

## The problem this model solves

### Institutional memory decays faster than the codebase

A mature codebase accumulates decisions. Many of them are *negative* decisions
— the code doesn't do X, doesn't clear Y on failure, doesn't retry Z more
than N times — chosen deliberately to prevent a specific failure mode the
original author understood at the time.

Those decisions are invisible in the code. You cannot see a decision that was
made to *not* do something. At best, a code comment flags the constraint;
more often, the constraint lives only in the author's head, in a design doc
that rotted, in a Slack thread nobody can find, or in a post-incident review
on a wiki that was archived two re-orgs ago.

Six months later, someone refactors the module and the constraint is gone.
The tests still pass (there was no test — the constraint was about a
situation the author thought was obvious). The PR reviewer nods. The
regression ships. The incident recurs, and a new round of institutional
learning begins.

This is the "Chesterton's fence" problem at codebase scale: every refactor is
a fence-removal decision, and the team has no durable way to record why the
fence is there.

### Git history and RFCs don't solve it

The usual answers fail under load:

- **Code comments** get deleted in the same refactor that violates the
  constraint. A comment saying "don't clear this on failure — it would lock
  out all peers during transient outages" is easy to delete if the person
  deleting it doesn't see how it applies to the change they're making.
- **Git history** records *what* changed and *when*, but a commit message
  like "refactor error handling" leaves no way to discover that an unrelated
  change from eighteen months prior established a constraint. You would have
  to know to look.
- **RFCs / design docs** describe a change at the moment it happens. Once the
  change lands, the RFC is frozen. Future contributors have no index into it
  — nothing connects the new diff to the RFC that established the invariant
  it's about to violate.
- **Tests** catch the subset of constraints someone thought to test. They do
  not catch "obvious" constraints the original author considered too
  self-evident to codify.
- **Tribal knowledge** works until the person holding it leaves, goes on
  vacation, or reviews too many PRs in a row to remember this one.

### LLM reviewers have no context at all

This problem gets sharper when the reviewer is an LLM. A human senior
engineer who has worked on the module for three years has *some* chance of
remembering the constraint, or at least being suspicious enough to ask. An
LLM reviewing a diff sees only what's in its context window: the diff, maybe
the surrounding file, maybe the PR description. It has no memory of the
conversation eighteen months ago that established the invariant. It has no
way to know which fences were deliberate.

If the project's institutional memory lives in private chat logs, stale wiki
pages, and the heads of senior engineers, an LLM reviewer will miss almost
every category of "silent regression of an old decision." It will catch
typos, style issues, and local logic bugs — but not the class of bug this
process is designed to prevent.

### What the model does

The feature spec is a single, stable, authoritative document per feature.
Every non-obvious constraint is written as a numbered `RULE-XX` (the
behavioral contract) or `DEC-XX` (the rationale and rejected alternatives).
The number is a forever-citation: `RULE-18` means the same thing in 2029
that it meant the day it was written, unless an RFC explicitly modifies it.

This gives every future reviewer — human or LLM — a durable index into the
invariants. A review prompt can mechanically check "does this diff still
satisfy every `RULE-XX`?" without any of the reviewer's prior knowledge.
The spec carries the context the reviewer lacks.

## The three artifacts

### RFC — the change narrative

Lives under [`docs/rfcs/`](rfcs/). Template: [`0000-template.md`](0000-template.md).

An RFC describes a *change*: why we're doing it, what it adds, modifies, or
removes, what tradeoffs were considered, what could go wrong. It is a
point-in-time document — once the change lands, the RFC is history. It cites
the spec rules it adds/modifies/removes (`RULE-XX`) so the delta is auditable.

An RFC is NOT the authoritative description of how the system behaves. That
lives in the spec.

### Spec — the testable truth

Lives next to the feature it describes (e.g. [`docs/p2p/peer-whitelist.md`](p2p/peer-whitelist.md)).
Template: [`0001-spec-template.md`](0001-spec-template.md).

A feature spec is the authoritative behavioral contract. Every rule is a
precise, testable statement (`RULE-XX`, using RFC 2119 MUST/SHOULD). It
describes steady-state behavior — state machines, data formats, constants,
error handling, integration contracts. Edge cases and non-obvious choices are
captured as numbered decisions (`DEC-XX`) so future readers don't have to
reconstruct the reasoning from git history.

The spec outlives any single RFC. Multiple RFCs may modify the same spec over
time; the spec's changelog tracks the revisions.

### Code — the implementation

The spec is what the code MUST do. If the spec and code disagree, one of them
is wrong — the review process decides which.

## The review prompts

Prompts live under [`docs/prompts/`](prompts/). Each defines a reviewer role
with inputs, process, output format, and blocking rules. Shared conventions
(input locators, traceability header, severity ladder) live in
[`conventions.md`](prompts/conventions.md) and are referenced by every
prompt.

The prompts split into three groups: **triangle edges** (pairwise
consistency), **per-artifact hygiene** (is each artifact well-formed?), and
**scenario-specific** (run only when a condition applies). A final triage
prompt aggregates the outputs.

### Triangle edges

| Prompt | Edge | Reviewer job |
|---|---|---|
| [`review-code-vs-rfc.md`](prompts/review-code-vs-rfc.md) | Code ↔ RFC | Did the PR implement what the RFC promised? Flags missing, contradicted, and undocumented changes. |
| [`review-code-vs-spec.md`](prompts/review-code-vs-spec.md) | Code ↔ Spec | Does every `RULE-XX` have compliant code? Does every `DEC-XX` keep its rejected alternative absent? **Load-bearing** — catches silent regressions of prior decisions. |
| [`review-rfc-vs-spec.md`](prompts/review-rfc-vs-spec.md) | RFC ↔ Spec | Are the RFC's claimed spec impacts (adds/modifies/removes `RULE-XX`) actually reflected in the spec, with a changelog entry? |
| [`review-spec-completeness.md`](prompts/review-spec-completeness.md) | Code → Spec | Finds undocumented behaviors in code and flags stale spec rules for deleted code paths. |
| [`review-tests-vs-spec.md`](prompts/review-tests-vs-spec.md) | Tests ↔ Spec | Does every `RULE-XX` have a test? Does every `DEC-XX` have a test that would fail if the rejected alternative were re-introduced? |

### Per-artifact hygiene

| Prompt | Artifact | Reviewer job |
|---|---|---|
| [`review-rfc-quality.md`](prompts/review-rfc-quality.md) | RFC | Is the RFC well-formed: template compliance, motivation, rejected alternatives, risks, explicit spec impact? |
| [`review-spec-quality.md`](prompts/review-spec-quality.md) | Spec | Are rules testable and atomic, keywords correct (MUST/SHOULD), decisions justified, numbers stable, constants and changelog complete? |

### Scenario-specific

| Prompt | When to run | Reviewer job |
|---|---|---|
| [`review-rule-modification.md`](prompts/review-rule-modification.md) | Any RFC that modifies/removes an existing `RULE-XX` or `DEC-XX`. | Ensures the reversal of a prior decision is deliberate, justified, and cannot be silently re-weakened. |

### Aggregation

| Prompt | When to run | Job |
|---|---|---|
| [`triage-reviews.md`](prompts/triage-reviews.md) | After other prompts. | Deduplicates findings, flags missing required reviews, and produces a single land/no-land verdict. |

### Authoring (non-review)

| Prompt | When to run | Job |
|---|---|---|
| [`draft-spec-from-codebase.md`](prompts/draft-spec-from-codebase.md) | Bootstrap case — a feature exists in code but has no spec yet. | Produces a first-draft spec by inventorying behaviors and mining rationale from git history, flagging unknowns for the human author. |

### Why each prompt exists

Each prompt defends against a specific failure mode. Reading from the
outside in:

- **`review-rfc-quality.md`** — the RFC is the change narrative. If it is
  vague or missing its rejected-alternatives section, every downstream
  reviewer loses context. Catches: "motivation unclear," "no spec impact
  listed," "silently reverses a prior DEC without saying so."
- **`review-spec-quality.md`** — the spec is the forever-citation. A rule
  that is not testable, not atomic, or uses the wrong RFC 2119 keyword
  silently weakens every future `review-code-vs-spec` run. Catches:
  "rule reads like a suggestion," "number reused," "decision missing
  rejected alternative."
- **`review-rfc-vs-spec.md`** — the RFC claims to change rules; the spec
  must reflect those changes or future reviewers are working from a stale
  contract. Catches: "RFC says it modifies RULE-18 but RULE-18 is
  unchanged," "new behavior mentioned in RFC but no new rule added,"
  "changelog missing."
- **`review-code-vs-rfc.md`** — cheapest consistency check: did the PR do
  what it said? Catches: "RFC promised X, diff doesn't do X," "diff does
  Y that the RFC never mentioned."
- **`review-code-vs-spec.md`** — *the* load-bearing review. The only one
  that catches "silent violation of an invariant established by a prior
  RFC." This is the Chesterton-fence scenario from the worked example
  below. Catches: "code no longer satisfies RULE-18," "DEC-02's rejected
  alternative has re-appeared on a different branch."
- **`review-spec-completeness.md`** — the dual of `review-code-vs-spec`:
  if code exists that no rule describes, either the spec needs a rule
  or the code is unintentional. Catches: "undocumented behavior with
  operational consequences," "stale rule describing deleted code."
- **`review-tests-vs-spec.md`** — a `RULE-XX` with no test is decorative.
  A `DEC-XX` with no test defending the rejected alternative will lose
  the decision at the next refactor. Catches: "no test exercises
  RULE-18," "nothing would fail if DEC-02 were reversed."
- **`review-rule-modification.md`** — reversing a prior decision is
  allowed, but must be loud. Catches: "MUST silently weakened to
  SHOULD," "old DEC dropped instead of superseded," "test that guarded
  the old decision was deleted in the same diff."
- **`triage-reviews.md`** — with many prompts, findings duplicate and
  some reviews get skipped. This is the single gate the author and
  merger look at.
- **`draft-spec-from-codebase.md`** — the bootstrap case. Without this,
  features that predate the spec process never acquire a spec, and the
  consistency triangle has no starting point for them.

## Typical workflow

0. **(Bootstrap only — feature has no spec yet.)** Run
   [`draft-spec-from-codebase.md`](prompts/draft-spec-from-codebase.md).
   Resolve the draft's open questions with the original implementer. Then
   run `review-spec-quality.md` and `review-spec-completeness.md` on the
   result. The published spec is the starting point for step 1.
1. **Draft the spec change.** If the feature is new, write a spec from
   [`0001-spec-template.md`](0001-spec-template.md). If it's a modification,
   edit the existing spec and add a changelog entry.
2. **Write the RFC.** Describe the change from
   [`0000-template.md`](0000-template.md). Cite the `RULE-XX` the change
   adds, modifies, or removes.
3. **Implement.** Write the code to match the updated spec, and add tests
   for every new rule and a defending test for every new decision.
4. **Run the reviews.** The order below matches the dependency chain:
   hygiene before consistency, consistency before aggregation.

   | Step | Prompt | When to run |
   |---|---|---|
   | 4a | [`review-rfc-quality.md`](prompts/review-rfc-quality.md) | Always. |
   | 4b | [`review-spec-quality.md`](prompts/review-spec-quality.md) | Always if the spec changed. |
   | 4c | [`review-rule-modification.md`](prompts/review-rule-modification.md) | Only if the RFC modifies or removes an existing `RULE-XX` / `DEC-XX`. |
   | 4d | [`review-rfc-vs-spec.md`](prompts/review-rfc-vs-spec.md) | Always. |
   | 4e | [`review-code-vs-rfc.md`](prompts/review-code-vs-rfc.md) | Always if code changed. |
   | 4f | [`review-code-vs-spec.md`](prompts/review-code-vs-spec.md) | Always. Run against the **full feature codebase**, not just the diff — this is how silent regressions are caught. |
   | 4g | [`review-spec-completeness.md`](prompts/review-spec-completeness.md) | Always if code or spec changed. |
   | 4h | [`review-tests-vs-spec.md`](prompts/review-tests-vs-spec.md) | Always if the spec or tests changed. |
   | 4i | [`triage-reviews.md`](prompts/triage-reviews.md) | After all applicable reviews above. Produces the single land/no-land verdict. |

   Each prompt emits a `Verdict` (PASS / FAIL / PASS WITH NOTES) following
   the severity ladder in
   [`conventions.md`](prompts/conventions.md). `triage-reviews` is the
   gate.

## End-to-end flow by scenario

The workflow table above lists every prompt in order. In practice, the set
of prompts that apply depends on the change. The three scenarios below
cover almost every PR.

### Scenario A — new feature (no existing spec for the area)

```
author:  draft-spec-from-codebase.md   (only if prior code exists to document)
         → resolve ? entries with original implementer
         → publish spec v1
         → write RFC citing new RULE-XX / DEC-XX
         → implement + tests

reviews: review-rfc-quality
         review-spec-quality
         review-rfc-vs-spec
         review-code-vs-rfc
         review-code-vs-spec          ← full feature codebase
         review-spec-completeness
         review-tests-vs-spec
         triage-reviews                ← single gate
```

### Scenario B — additive change to an existing feature

New behavior, new RULE-XX / DEC-XX, no prior rule touched.

```
author:  edit spec (add rules, add changelog entry)
         → write RFC citing added RULE-XX
         → implement + tests

reviews: review-rfc-quality
         review-spec-quality
         review-rfc-vs-spec
         review-code-vs-rfc
         review-code-vs-spec
         review-spec-completeness
         review-tests-vs-spec
         triage-reviews
```

### Scenario C — modification or removal of an existing rule

Any change that weakens, replaces, or deletes a prior `RULE-XX` or
`DEC-XX`. This is the highest-risk scenario — it is the deliberate
reversal of a decision that a previous RFC established.

```
author:  edit spec (supersede old rule, add new RULE-XX, changelog entry)
         → write RFC that explicitly names the modified rules and explains
           why the prior decision should be reversed
         → update or replace tests that defended the old decision
         → implement

reviews: review-rfc-quality
         review-spec-quality
         review-rule-modification      ← required for this scenario
         review-rfc-vs-spec
         review-code-vs-rfc
         review-code-vs-spec
         review-spec-completeness
         review-tests-vs-spec
         triage-reviews
```

### The triage gate

`triage-reviews.md` is the single gate a maintainer looks at before
merging. Its job is to:

1. Confirm every required review for the scenario was actually run
   (missing reviews are Blocking — a skipped `review-code-vs-spec` is
   exactly how silent regressions land).
2. Deduplicate findings across prompts.
3. Produce one verdict: **FAIL** (do not land), **PASS WITH NOTES**
   (land + tracked follow-ups), or **PASS**.

## Worked example: a future change silently reverting an old decision

This is the scenario the model is built to catch.

In April 2026 we land the peer-whitelist subsystem. The spec records:

> **RULE-18**: On fetch failure (network error, non-2xx HTTP status, parse
> error), the existing `_current` and `_policy` MUST be preserved.

With the rationale captured as **DEC-02**: transient failures must not flip
the node into either "lock out everyone" (empty list) or "allow everyone"
(no list). Last-known-good is the only safe default.

Fast-forward eighteen months. A new contributor is refactoring error
handling across the P2P layer and notices `_current` isn't cleared on
failure — it looks inconsistent with other error paths. They open a PR that
clears the set on any fetch error "for consistency." The RFC describes it as
a cleanup; it doesn't mention whitelists specifically, because the author
didn't realize the non-clearing was load-bearing.

**What each reviewer catches:**

| Reviewer | Verdict | Why |
|---|---|---|
| Code ↔ RFC review | PASS | The code matches the RFC — it's a cleanup PR. |
| Human reviewer without spec | Likely PASS | The diff looks reasonable. Tests pass (no test covers "fetch fails with existing whitelist loaded" — the original author considered it obvious). |
| LLM reviewer without spec | PASS | It has no memory of the April 2026 conversation. The rationale from DEC-02 lives nowhere reachable from the diff. |
| **Code ↔ Spec review** | **FAIL** | `RULE-18` is violated. The reviewer quotes the rule and the offending lines side by side. |

The Code ↔ Spec review is the only one that catches it, and only because
`RULE-18` exists as a stable, machine-checkable statement the reviewer can
mechanically verify without prior context.

The resolution forces a deliberate conversation: either the PR restores the
behavior, or the author writes a follow-up RFC that explicitly modifies
`RULE-18` and documents why the prior decision should be reversed. Either
way, the invariant isn't silently lost.

## Summary

- **Problem**: institutional memory decays. Old decisions live in tribal
  knowledge that future contributors (and LLM reviewers) can't access.
- **Cause**: code, tests, git history, and RFCs each fail to carry constraint
  context across time — they describe *what* but not *what must not happen*.
- **Solution**: the feature spec is a stable, numbered, authoritative
  contract. Every non-obvious constraint is written as `RULE-XX` or `DEC-XX`
  so any future reviewer can mechanically verify compliance.
- **Enforcement**: a set of review prompts checks every edge of the
  triangle, sanity-checks each artifact, and applies extra scrutiny when
  a prior decision is being reversed. `review-code-vs-spec` is the
  load-bearing one — the one that catches silent regressions of
  decisions made months or years ago. `triage-reviews` is the single
  gate a maintainer reads before merging.
