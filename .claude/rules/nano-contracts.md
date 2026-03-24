---
globs: ["hathor/nanocontracts/**/*.py"]
---

# Nano Contracts Development

## Blueprint Structure

Blueprints inherit from `Blueprint` and use decorators to define methods:

```python
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import public, view

class MyBlueprint(Blueprint):
    balance: int  # State attributes declared as class annotations

    @public
    def initialize(self, ctx: Context) -> None:
        self.balance = 0

    @public(allow_deposit=True, allow_withdrawal=True)
    def transfer(self, ctx: Context, amount: int) -> None:
        self.balance += amount

    @view
    def get_balance(self) -> int:
        return self.balance
```

## Method Decorators
- `@public` — modifies state, receives `ctx: Context`. Optional params: `allow_deposit`, `allow_withdrawal`, `allow_grant_authority`, `allow_acquire_authority`, `allow_actions`, `allow_reentrancy`
- `@view` — read-only, does NOT receive `ctx: Context`, cannot modify state
- `@private` — internal helper, not callable externally

## Action Directions
- **DEPOSIT** = tokens flow TO the contract (appears on the **output** side)
- **WITHDRAWAL** = tokens flow FROM the contract (appears on the **input** side)

This is critical for balance calculations and fee handling.

## Key Components
- `Runner` — executes blueprint methods with proper context
- `BlockExecutor` — processes all nano actions in a block
- Types from `hathor.nanocontracts.types`
- Context from `hathor.nanocontracts.context`
