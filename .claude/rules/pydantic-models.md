---
globs: ["hathor/event/**/*.py", "hathor/**/resources/**/*.py", "hathor/conf/**/*.py", "hathor/utils/pydantic.py"]
---

# Pydantic Usage

## Custom BaseModel

Always use the project's BaseModel, never raw pydantic:

```python
from hathor.utils.pydantic import BaseModel

class MyModel(BaseModel):
    name: str
    value: int
```

This BaseModel enforces `extra='forbid'` (no unknown fields) and `frozen=True` (immutable instances).

## Hex Serialization

Use `Hex[T]` for bytes fields that should serialize as hex strings in JSON:

```python
from hathor.utils.pydantic import BaseModel, Hex

class TxInfo(BaseModel):
    tx_id: Hex[VertexId]  # bytes in Python, hex string in JSON
```

## Settings

Avoid using `get_global_settings()` — inject `HathorSettings` as a dependency instead:

```python
# PREFERRED: dependency injection
class MyClass:
    def __init__(self, settings: HathorSettings) -> None:
        self._settings = settings

# AVOID: global singleton
from hathor.conf.get_settings import get_global_settings
settings = get_global_settings()
```

## Validators

Use pydantic v2 style validators:
```python
from pydantic import field_validator, model_validator
```
