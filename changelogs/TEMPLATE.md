<!--
CHANGELOG FRAGMENT TEMPLATE
============================

HOW TO USE:
1. Copy this file to: changelogs/unreleased/<PR_NUMBER>.<type>.md
   Example: changelogs/unreleased/1234.added.md

2. Choose <type> based on your change:
   - added      New user-facing features or capabilities
   - changed    Changes to existing functionality
   - removed    Features or functionality that were removed
   - fixed      Bug fixes
   - packaging  Build system, CI, dependency, or tooling changes

   Note: Breaking changes should be noted in the fragment description, not as a separate type.

3. Replace this entire comment block with your changelog entry.
   Write a concise, user-facing description of the change.

EXAMPLES:

  New feature (added):
    Add rate limiting support for API endpoints

  Behavior change (changed):
    Increase default WebSocket timeout from 30s to 60s

  Removal (removed):
    Remove deprecated `get_tx()` method from storage API

  Bug fix (fixed):
    Fix WebSocket reconnection failing after timeout

  Packaging (packaging):
    Add towncrier for changelog generation

  Breaking change (changed with migration note):
    Rename `get_tx()` to `get_vertex()` in storage API

    **BREAKING:** Replace all calls to `storage.get_tx(hash)`
    with `storage.get_vertex(hash)`

GUIDELINES:
- Write for end users, not developers
- Focus on impact, not implementation details
- For breaking changes, always include migration steps
- Keep it concise: 1-2 sentences for simple changes
-->

Your changelog entry here
