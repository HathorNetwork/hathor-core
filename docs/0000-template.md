- Feature Name: (fill me in with a unique ident, my_awesome_feature)
- Start Date: (fill me in with today's date, YYYY-MM-DD)
- RFC PR: (leave this empty)
- Hathor Issue: (leave this empty)
- Feature Spec: (path to the feature spec this RFC relates to, if any)
- Author: (fill this with Your Name <your@email>, Other Author <other@email>)

# Summary
[summary]: #summary

One paragraph explanation of the feature.

# Motivation
[motivation]: #motivation

Why are we doing this? What use cases does it support? What is the expected
outcome?

# Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

Explain the proposal as if it was already included in the network and you were
teaching it to another Hathor programmer. That generally means:

- Introducing new named concepts.
- Explaining the feature largely in terms of examples.
- Explaining how Hathor programmers should *think* about the feature, and how it
  should impact the way they use Hathor. It should explain the impact as
  concretely as possible.
- If applicable, provide sample error messages, deprecation warnings, or
  migration guidance.
- If applicable, describe the differences between teaching this to existing
  Hathor programmers and new Hathor programmers.

For implementation-oriented RFCs (e.g. for compiler internals), this section
should focus on how compiler contributors should think about the change, and
give examples of its concrete impact. For policy RFCs, this section should
provide an example-driven introduction to the policy, and explain its impact in
concrete terms.

# Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

This is the technical portion of the RFC. Explain the design in sufficient
detail that:

- Its interaction with other features is clear.
- It is reasonably clear how the feature would be implemented.
- Corner cases are dissected by example.

The section should return to the examples given in the previous section, and
explain more fully how the detailed proposal makes those examples work.

When a Feature Spec exists, cross-reference the spec rules this RFC adds,
modifies, or removes. Use the format `RULE-XX` to cite specific rules. For
each change, state the spec impact:

- Adds RULE-XX: (brief description)
- Modifies RULE-XX: (what changed and why)
- Removes RULE-XX: (why it's no longer needed)

# Drawbacks
[drawbacks]: #drawbacks

Why should we *not* do this?

# Decisions
[decisions]: #decisions

Non-obvious choices made in this RFC. Each entry should state what was decided,
what alternatives existed, and why this choice was made. Use numbered entries
for easy cross-referencing with the Feature Spec's Edge Cases & Decisions
section.

> **D-01: (short title)**
> Decision: (what was chosen)
> Rationale: (why)
> Alternative rejected: (what else was considered and why it lost)

# Risks & Rollback
[risks-and-rollback]: #risks-and-rollback

What could go wrong? How would you roll this back if needed? Does this change
require coordination (e.g., deploy ordering, feature flags, data migrations)?

# Prior art
[prior-art]: #prior-art

Discuss prior art, both the good and the bad, in relation to this proposal.
A few examples of what this can include are:

- For protocol, network, algorithms and other changes that directly affect the
  code: Does this feature exist in other blockchains and what experience have
  their community had?
- For community proposals: Is this done by some other community and what were
  their experiences with it?
- For other teams: What lessons can we learn from what other communities have
  done here?
- Papers: Are there any published papers or great posts that discuss this? If
  you have some relevant papers to refer to, this can serve as a more detailed
  theoretical background.

This section is intended to encourage you as an author to think about the
lessons from other blockchains, provide readers of your RFC with a fuller
picture. If there is no prior art, that is fine - your ideas are interesting to
us whether they are brand new or if it is an adaptation from other blockchains.

Note that while precedent set by other blockchains is some motivation, it does
not on its own motivate an RFC. Please also take into consideration that Hathor
sometimes intentionally diverges from common blockchain features.

# Testing
[testing]: #testing

How was this change tested? What test cases were added or modified? Are there
behaviors that are hard to test automatically and require manual verification?

# Unresolved questions
[unresolved-questions]: #unresolved-questions

- What parts of the design do you expect to resolve through the RFC process
  before this gets merged?
- What parts of the design do you expect to resolve through the implementation
  of this feature before stabilization?
- What related issues do you consider out of scope for this RFC that could be
  addressed in the future independently of the solution that comes out of this
  RFC?

# Future possibilities
[future-possibilities]: #future-possibilities

Think about what the natural extension and evolution of your proposal would be
and how it would affect the network and project as a whole in a holistic way.
Try to use this section as a tool to more fully consider all possible
interactions with the project and network in your proposal. Also consider how
this all fits into the roadmap for the project and of the relevant sub-team.

This is also a good place to "dump ideas", if they are out of scope for the
RFC you are writing but otherwise related.

If you have tried and cannot think of any future possibilities,
you may simply state that you cannot think of anything.

Note that having something written down in the future-possibilities section
is not a reason to accept the current or a future RFC; such notes should be
in the section on motivation or rationale in this or subsequent RFCs.
The section merely provides additional information.
