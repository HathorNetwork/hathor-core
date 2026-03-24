---
description: Review code against hathor-core conventions
---

Review the current changes (staged + unstaged) against hathor-core project conventions. Check for:

1. **License headers**: All new `.py` files must have the Apache 2.0 Hathor Labs header
2. **Imports**: `from __future__ import annotations` present, TYPE_CHECKING blocks used for type-only imports, no wildcards
3. **Pydantic**: Uses `hathor.utils.pydantic.BaseModel` (not raw pydantic), `Hex[T]` for bytes in API models
4. **Type safety**: No untyped defs in strict mypy modules (consensus, verification, event, feature_activation), no bare `Any`
5. **Logging**: structlog with structured kwargs, no f-strings in log messages
6. **Test quality**: Correct base class, uses `self.rng`/`self.clock` for determinism, `@inlineCallbacks` for async
7. **API resources**: `@register_resource`, `isLeaf = True`, `@api_endpoint(...)` decorator (not manual `set_cors()`/`json_dumpb()`/`.openapi` dicts)
8. **Security**: No manual crypto implementations, proper input validation at boundaries
9. **Style**: Line length ≤119, snake_case functions, PascalCase classes

Run `git diff` and `git diff --cached` to see changes, then report findings grouped by severity:
- **Blocking**: Must fix before merge (type errors, missing license, security issues)
- **Warning**: Should fix (style violations, missing TYPE_CHECKING blocks)
- **Suggestion**: Nice to have (better naming, additional tests)
