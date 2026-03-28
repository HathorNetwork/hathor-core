---
description: Create a new storage migration
---

Create a new storage migration named: $ARGUMENTS

Steps:
1. List existing migrations in `hathor/transaction/storage/migrations/` to determine the next sequence
2. Create a new migration file using this template:

```python
#  Copyright <YEAR> Hathor Labs  # Use the current year
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  ...full Apache 2.0 header...

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.transaction.storage.migrations import BaseMigration

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage


class Migration(BaseMigration):
    def skip_empty_db(self) -> bool:
        return True

    def get_db_name(self) -> str:
        return '$ARGUMENTS'

    def run(self, storage: 'TransactionStorage') -> None:
        # TODO: implement migration logic
        pass
```

3. Register the migration in the migrations `__init__.py` if needed
4. Explain to the user what `skip_empty_db`, `get_db_name`, and `run` should do
