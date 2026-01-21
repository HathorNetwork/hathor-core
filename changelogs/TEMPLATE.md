<!--
CHANGELOG FRAGMENT TEMPLATE
============================

HOW TO USE:
1. Copy this file to: changelogs/unreleased/<PR_NUMBER>.<type>.md
   Example: changelogs/unreleased/1234.feat.md

2. Choose <type> based on your change (matches semantic commit prefixes):
   - feature  → New user-facing features
   - fix      → Bug fixes for users
   - docs     → Documentation changes
   - style    → Formatting, no code change (hidden from public changelog)
   - refactor → Refactoring production code
   - test     → Test changes, no production code (hidden from public changelog)
   - chore    → Admin/build/config changes (hidden from public changelog)

   Note: Breaking changes should be noted in the fragment description, not as a separate type.

3. Replace this entire comment block with your changelog entry.
   Write a concise, user-facing description of the change.

EXAMPLES:

  Simple feature (feature):
    Add rate limiting support for API endpoints

  Bug fix (fix):
    Fix WebSocket reconnection failing after timeout

  Refactoring (refactor):
    Simplify transaction validation logic

  Breaking change (feature with migration note):
    Rename `get_tx()` to `get_vertex()` in storage API

    **BREAKING:** Replace all calls to `storage.get_tx(hash)`
    with `storage.get_vertex(hash)`

  With code examples (feature with breaking change):
    Change configuration format from YAML to TOML

    **BREAKING:**
    ```yaml
    # Before (config.yml)
    server:
      port: 8080
    ```
    ```toml
    # After (config.toml)
    [server]
    port = 8080
    ```

GUIDELINES:
- Write for end users, not developers
- Focus on impact, not implementation details
- For breaking changes, always include migration steps
- Keep it concise: 1-2 sentences for simple changes
-->

Your changelog entry here
