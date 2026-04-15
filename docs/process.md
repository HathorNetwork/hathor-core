# RFC / Spec / Code — the consistency triangle

Changes to Hathor core are described across three artifacts. Each plays a
distinct role, and reviewers enforce consistency between them pairwise.

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

## The four review prompts

Prompts live under [`docs/prompts/`](prompts/). Each defines a reviewer role
with inputs, process, output format, and blocking rules. Together they enforce
consistency across every edge of the triangle.

| Prompt | Edge | Reviewer job |
|---|---|---|
| [`review-code-vs-rfc.md`](prompts/review-code-vs-rfc.md) | Code ↔ RFC | Did the PR implement what the RFC promised? Flags missing, contradicted, and undocumented changes. |
| [`review-code-vs-spec.md`](prompts/review-code-vs-spec.md) | Code ↔ Spec | Does every `RULE-XX` have compliant code? Produces per-rule Compliant / Violation / Partial / Unverifiable. |
| [`review-rfc-vs-spec.md`](prompts/review-rfc-vs-spec.md) | RFC ↔ Spec | Are the RFC's claimed spec impacts (adds/modifies/removes `RULE-XX`) actually reflected in the spec? |
| [`review-spec-completeness.md`](prompts/review-spec-completeness.md) | Code → Spec | Finds undocumented behaviors in code and flags stale spec rules for deleted code paths. |

The first three are pairwise checks on each edge. The fourth closes a gap the
pairwise checks miss: behavior that exists in code but was never written down.

## Typical workflow

1. **Draft the spec change.** If the feature is new, write a spec from
   [`0001-spec-template.md`](0001-spec-template.md). If it's a modification,
   edit the existing spec and add a changelog entry.
2. **Write the RFC.** Describe the change from
   [`0000-template.md`](0000-template.md). Cite the `RULE-XX` the change adds,
   modifies, or removes.
3. **Implement.** Write the code to match the updated spec.
4. **Run the reviews.** Use the four prompts to check every edge of the
   triangle. Each prompt's `Verdict` (PASS / FAIL / PASS WITH NOTES) gates
   landing the change.

## Why this shape

Three artifacts with pairwise review is more overhead than a single design
doc, but each artifact answers a question the others can't:

- **"What changed and why?"** → RFC. Git history alone doesn't capture
  rejected alternatives or the motivation behind a decision.
- **"What does the system do today?"** → Spec. The RFC goes stale the moment
  it lands; the spec stays current.
- **"Does the code actually do it?"** → Code ↔ Spec review. Without this,
  specs drift into fiction.

The prompts exist because each edge is a different reviewer role with a
different focus — conflating them produces shallow reviews that miss
category-specific issues (RFC reviewers miss spec gaps; spec reviewers miss
RFC/code mismatches).
