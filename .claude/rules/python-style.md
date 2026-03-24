---
globs: ["hathor/**/*.py", "hathor_cli/**/*.py", "hathor_tests/**/*.py"]
---

# Python Style Guide

## Formatting
- Line length: 119 characters
- isort config: `combine_as_imports=true`, `trailing_comma=true`, `multi_line_output=3`
- No trailing whitespace, single newline at EOF

## Imports
- Always include `from __future__ import annotations` as first import
- Use `TYPE_CHECKING` blocks for imports only needed by type checkers:
  ```python
  from __future__ import annotations

  from typing import TYPE_CHECKING

  if TYPE_CHECKING:
      from hathor.transaction import BaseTransaction
  ```
- No wildcard imports (`from x import *`)
- Group: stdlib → third-party → first-party (`hathor`, `hathor_tests`)

## Type Annotations
- Strict mypy enforced for: `hathor.consensus`, `hathor.verification`, `hathor.event`, `hathor.feature_activation` and their test counterparts
- In strict modules: no `Any` without justification, `disallow_untyped_defs`, `disallow_any_generics`
- Use `X | None` instead of `Optional[X]`

## Naming
- `PascalCase` for classes and type aliases
- `snake_case` for functions, methods, variables
- `UPPER_SNAKE_CASE` for module-level constants
- `_` prefix for private methods/attributes
- `__slots__` on all classes (not just performance-critical ones)

## Logging
- Use structlog: `from structlog import get_logger; logger = get_logger()` at module level
- Instance logger: `self.log = logger.new()` in `__init__`
- Structured kwargs, never f-strings: `self.log.debug('found output', tx=tx.hash_hex, index=index)`

## License Header
All new Python files must start with the Apache 2.0 Hathor Labs license header (see CLAUDE.md).
