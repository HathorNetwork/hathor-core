- Feature Name: (fill me in with a unique ident, e.g. my_awesome_feature)
- Status: (Draft | Accepted | Implemented | Deprecated)
- Start Date: (fill me in with today's date, YYYY-MM-DD)
- Authors: (fill this with Your Name <your@email>, Other Author <other@email>)
- Hathor Issue: (leave this empty)
- Implementation PR(s): (leave this empty)

# Overview

One paragraph. What this feature is, at the highest level.

# Specification

The authoritative behavioral description of the feature. Everything in this
section is a statement that can be verified against the implementation. Organize
by subsystem or concern using sub-headings.

Write rules as precise, testable statements — not tutorial prose. Prefer tables
for enumerations, state transitions, and configuration mappings. Use "MUST",
"MUST NOT", "SHOULD", and "MAY" (RFC 2119) when precision matters.

## Sub-section guidelines

Break the specification into logical sub-sections. Common patterns:

- **Configuration / CLI** — all knobs, their values, defaults, and validation
  rules.
- **Data format** — wire formats, file formats, schemas. Be exact: specify
  headers, field ordering, escaping rules.
- **Lifecycle** — startup, steady-state, shutdown. State machines and transition
  tables belong here.
- **Behavior** — what happens on success, on failure, on each edge. Use numbered
  rules when a sequence matters.
- **Integration points** — how this feature interacts with other subsystems.
  Specify the contract at each boundary (function signature, callback shape,
  sysctl key, API field).
- **Constants** — all magic numbers, intervals, limits, with rationale inline.

Example of a verifiable rule:

> **RULE-07**: When a fetch fails, the retry interval MUST follow exponential
> backoff: `min(BASE * 2^failures, MAX)` where BASE = 30 s and MAX = 300 s.
> The backoff counter resets to 0 on the next successful fetch.

Example of a state transition table:

> | Current state | Event            | Next state | Side effects          |
> |---------------|------------------|------------|-----------------------|
> | GRACE_PERIOD  | fetch succeeds   | ENFORCING  | apply whitelist       |
> | ENFORCING     | fetch fails      | ENFORCING  | keep previous list    |
> | ENFORCING     | sysctl "off"     | SUSPENDED  | store whitelist, stop |

## (Your sub-sections here)

(Replace this with the actual specification content.)

# Edge Cases & Decisions

Numbered list of non-obvious decisions, trade-offs, and edge-case behaviors.
Each entry states what was decided, why, and what alternative was rejected.

Keep these concise. The goal is to preserve context so a future reader
understands *why* a rule in the Specification section exists, without having to
reconstruct the discussion from git history.

Format:

> **DEC-01: (short title)**
> Decision: (what we chose)
> Rationale: (why)
> Alternative rejected: (what else was considered and why it lost)

# Open Questions

Bullet list of things not yet decided or explicitly deferred. Remove items as
they are resolved (move them to Edge Cases & Decisions or into the
Specification).

# Changelog

Track significant revisions to this spec so readers know when rules changed.

| Date | Author | Description |
|------|--------|-------------|
| YYYY-MM-DD | Author Name | Initial draft |
