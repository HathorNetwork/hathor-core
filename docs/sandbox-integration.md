# Sandbox Integration for Nano Contracts

This document describes how the CPython sandbox is integrated with the Hathor nano contracts system to provide secure, metered execution of untrusted blueprint code.

## Overview

The nano contracts sandbox provides multiple layers of protection:

1. **Execution Limits**: Operation counting, iteration limits, recursion depth
2. **Size Limits**: Restrict maximum sizes for integers, strings, lists, dicts, etc.
3. **Type Restrictions**: Disallow float and complex types
4. **Security Restrictions**: Block I/O, unsafe operations, and metaclasses
5. **Opcode Restrictions**: Allowlist-based opcode control (blocks exception handling, async, etc.)
6. **Import Restrictions**: Allowlist-based import control (defense in depth)
7. **Module Access Restrictions**: Block access to disallowed modules even if passed via namespace
8. **Frozen Mode**: Prevent mutation of objects passed from outside the sandbox
9. **Custom Builtins**: Replace dangerous builtins with safe alternatives

## PR Changes Summary

This PR implements the CPython sandbox integration for nano contracts execution:

### Sandbox Package

All sandbox-related code is organized in the `hathor/nanocontracts/sandbox/` package:

- `hathor/nanocontracts/sandbox/__init__.py` - Public API exports
- `hathor/nanocontracts/sandbox/config.py` - `SandboxConfig` dataclass and configuration
- `hathor/nanocontracts/sandbox/counts.py` - `SandboxCounts`, `SandboxCounters` for execution counters
- `hathor/nanocontracts/sandbox/constants.py` - `BLUEPRINT_FILENAME`, `PyCF_SANDBOX_COUNT`, `SANDBOX_AVAILABLE`
- `hathor/nanocontracts/sandbox/exceptions.py` - Portable sandbox exception types
- `hathor/nanocontracts/sandbox/config_loader.py` - YAML-based config loading
- `hathor/nanocontracts/sandbox/allowlist.py` - Opcode and import allowlists

### Other Related Files

- `hathor/sysctl/nanocontracts/sandbox_api.py` - Runtime sysctl API
- `hathor/nanocontracts/metered_exec.py` - `MeteredExecutor` using sandbox API
- `hathor/nanocontracts/runner/runner.py` - Integrated sandbox lifecycle management
- `hathor/nanocontracts/on_chain_blueprint.py` - Added loading cost tracking
- `hathor_tests/sandbox/` - Comprehensive test suite

---

## Sandbox Features Used

### 1. Operation Counting (`max_operations`)

The sandbox counts Python bytecode operations to prevent infinite loops and excessive computation.

**How it works:**
- Code is compiled with `PyCF_SANDBOX_COUNT` flag (0x8000)
- Only code with filenames registered via `sys.sandbox.add_filename()` is tracked
- Operations are counted at the AST level, not per-opcode

**Configuration:**
```python
max_operations: int = 1_000_000  # 1M operations per transaction
```

**Implementation:**
```python
# In MeteredExecutor.exec() and MeteredExecutor.call()
compile_flags = PyCF_SANDBOX_COUNT if sandbox_available else 0
code = compile(source, filename=BLUEPRINT_FILENAME, mode='exec', flags=compile_flags)
```

### 2. Iteration Counting (`max_iterations`)

Catches iteration in C builtins that bypass operation counting.

**Configuration:**
```python
max_iterations: int = 10_000_000  # 10M iterations
count_iterations_as_operations: bool = True  # Count towards operation limit
```

### 3. Recursion Depth (`max_recursion_depth`)

Prevents stack overflow attacks.

**Configuration:**
```python
max_recursion_depth: int = 100
```

### 4. Size Limits

Prevent DoS attacks via large object creation:

```python
max_int_digits: int = 100        # Prevents huge integer DoS (~10^900)
max_str_length: int = 1_000_000  # 1M characters
max_bytes_length: int = 1_000_000
max_list_size: int = 100_000     # 100K items
max_dict_size: int = 100_000
max_set_size: int = 100_000
max_tuple_size: int = 100_000
```

### 5. Type Restrictions

Disallow float and complex types for deterministic execution:

```python
allow_float: bool = False
allow_complex: bool = False
```

### 6. Security Restrictions

```python
allow_dunder_access: bool = False  # Block __dunder__ attribute access
allow_io: bool = False             # Block file/socket/fd operations
allow_class_creation: bool = True  # Allow class definitions
allow_magic_methods: bool = False  # Restrict magic method definitions
allow_metaclasses: bool = False    # Use whitelist instead
allow_unsafe: bool = False         # Block compile(), gc introspection
```

### 7. Import Restrictions (Defense in Depth)

Even if someone bypasses the custom `__import__` builtin, the sandbox blocks unauthorized imports:

```python
# In SandboxConfig.apply()
sys.sandbox.import_restrict_mode = True
sys.sandbox.allowed_imports = get_sandbox_allowed_imports()
```

The `allowed_imports` is a `frozenset[str]` of dotted module.attribute strings:

```python
def get_sandbox_allowed_imports() -> frozenset[str]:
    """Returns dotted strings: {'math.ceil', 'math.floor', 'hathor.Blueprint', ...}"""
    return frozenset(
        f'{module_name}.{attr_name}'
        for module_name, attributes in ALLOWED_IMPORTS.items()
        for attr_name in attributes
    )
```

### 8. Module Access Restrictions (Defense in Depth)

Even if sandboxed code gets a reference to a disallowed module (e.g., passed via namespace), the sandbox blocks its usage:

```python
# In SandboxConfig.apply()
sys.sandbox.module_access_restrict_mode = True
sys.sandbox.allowed_modules = get_sandbox_allowed_modules()
```

The `allowed_modules` is a `frozenset[str]` of module names:

```python
def get_sandbox_allowed_modules() -> frozenset[str]:
    """Returns module names: {'math', 'typing', 'collections', 'hathor'}"""
    return frozenset(ALLOWED_IMPORTS.keys())
```

### 9. Metaclass Whitelist

Since `allow_metaclasses=False`, we explicitly whitelist the Blueprint metaclass:

```python
from hathor.nanocontracts.blueprint import _BlueprintBase
sys.sandbox.allowed_metaclasses = frozenset({_BlueprintBase})
```

### 10. Frozen Mode

Prevents modification of objects passed from outside the sandbox:

```python
sys.sandbox.frozen_mode = True
sys.sandbox.auto_mutable = True  # Contract's self is automatically mutable
```

In `MeteredExecutor.call()`:
```python
# Mark the contract instance as mutable
bound_self = getattr(func, '__self__', None)
if bound_self is not None:
    sys.sandbox.set_mutable(bound_self)
```

### 11. Filename Scope Tracking

Only code from registered filenames is subject to sandbox limits:

```python
BLUEPRINT_FILENAME = '<blueprint>'
sys.sandbox.add_filename(BLUEPRINT_FILENAME)
```

---

### 12. Opcode Restrictions (Defense in Depth)

The sandbox restricts which Python bytecode opcodes can be executed, using an allowlist approach (fail-secure by default). This mirrors the OCB AST-level restrictions at the bytecode level.

```python
# In SandboxConfig.apply()
from hathor.nanocontracts.sandbox.allowlist import get_allowed_opcodes
sys.sandbox.opcode_restrict_mode = True
sys.sandbox.allowed_opcodes = get_allowed_opcodes()
```

**Allowlist Approach:**

New opcodes in future Python versions are automatically blocked until explicitly reviewed and added to the allowlist:

```python
# In hathor/nanocontracts/sandbox/allowlist.py
def get_allowed_opcodes() -> frozenset[int]:
    """Get allowed opcodes as opcode numbers."""
    return frozenset(
        dis.opmap[name] for name in ALLOWED_OPCODES if name in dis.opmap
    )
```

**Blocked Opcodes:**

| Category | Blocked Opcodes | Reason |
|----------|-----------------|--------|
| Star Imports | `IMPORT_STAR` | Star imports blocked at AST level |
| Exception Handling | `PUSH_EXC_INFO`, `POP_EXCEPT`, `CHECK_EXC_MATCH`, `CHECK_EG_MATCH`, `PREP_RERAISE_STAR`, `RERAISE`, `WITH_EXCEPT_START` | try/except blocked per OCB rules |
| Async | `GET_AWAITABLE`, `GET_AITER`, `GET_ANEXT`, `END_ASYNC_FOR`, `BEFORE_ASYNC_WITH`, `ASYNC_GEN_WRAP`, `SEND` | async/await blocked per OCB rules |
| Other | `PRINT_EXPR` | Interactive mode only |

**Note:** `IMPORT_NAME` and `IMPORT_FROM` are allowed because import restrictions are enforced separately via `import_restrict_mode` and `allowed_imports`. The OCB AST-level restrictions check WHICH modules are imported, not that imports themselves are forbidden.

**Allowed Opcodes (87 categories):**

- Stack/Control: `NOP`, `CACHE`, `RESUME`, `POP_TOP`, `PUSH_NULL`, `SWAP`, `COPY`, etc.
- Load/Store: `LOAD_CONST`, `LOAD_FAST`, `STORE_FAST`, `LOAD_GLOBAL`, etc.
- Operations: `BINARY_OP`, `UNARY_NEGATIVE`, `COMPARE_OP`, etc.
- Control Flow: `JUMP_FORWARD`, `FOR_ITER`, `RETURN_VALUE`, etc.
- Collections: `BUILD_LIST`, `BUILD_DICT`, `LIST_APPEND`, etc.
- Functions: `CALL`, `MAKE_FUNCTION`, etc.
- Generators: `YIELD_VALUE`, `RETURN_GENERATOR` (sync only)
- Context Managers: `BEFORE_WITH` (sync only)
- Sandbox-specific: `SANDBOX_COUNT` (operation counting opcode)

---

## Sandbox Features NOT Used

### 1. Default Safe Modules (`use_default_allowed_modules()`)

**What it does:** Sets a predefined list of safe modules.

**Why not used:** We have our own curated `ALLOWED_IMPORTS` dict that precisely controls what's available to blueprints.

### 3. `allow_submodules` for imports

**What it does:** Controls whether `from package import submodule` is allowed when only `package` is in the allowlist.

**Why not used:** Our `ALLOWED_IMPORTS` explicitly lists every allowed import, so submodule access isn't needed.

---

## Operation Limit Execution Flow

### Transaction Execution Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Nano Transaction Execution                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Runner._unsafe_call_public_method()                             │
│     ├── metered_executor.start()  ← Enable sandbox, reset counters  │
│     │                                                                │
│     ├── 2. Load Blueprint (if not cached)                           │
│     │      └── OCB loading costs added to operation count           │
│     │                                                                │
│     ├── 3. Execute method via metered_executor.call()               │
│     │      └── reset_counters=False (accumulate with loading)       │
│     │                                                                │
│     ├── 4. If cross-contract call:                                  │
│     │      ├── Load target blueprint (costs accumulate)             │
│     │      └── Execute target method (costs accumulate)             │
│     │                                                                │
│     └── metered_executor.end()  ← Suspend sandbox, cleanup          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Points

1. **Single counter per transaction**: Counters are reset once at the entry point (`_unsafe_call_public_method`), not on nested calls.

2. **Cross-contract calls share counters**: When Contract A calls Contract B, both contribute to the same operation count.

3. **OCB loading counts**: Loading blueprint code (even from cache) adds to the operation count.

4. **View methods also metered**: `call_view_method` follows the same pattern.

### Code Flow

```python
# Runner._unsafe_call_public_method()
self._metered_executor.start()  # Enable sandbox, apply config, reset counters
try:
    # Load blueprint - costs are tracked
    blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)

    # Execute method - reset_counters=False to accumulate
    ret = self._metered_executor.call(method, args=args, reset_counters=False)
finally:
    self._metered_executor.end()  # Suspend sandbox, cleanup
```

```python
# Runner._execute_public_method_call() - for nested/cross-contract calls
# Note: reset_counters=False ensures operation counts accumulate
ret = self._metered_executor.call(method, args=(ctx.copy(), *args), reset_counters=False)
```

---

## OCB Loading Cost Tracking

### Problem

Blueprint code is cached after first load. Without cost tracking, the first caller pays the loading cost, but subsequent callers don't.

### Solution

Loading costs are captured and replayed when serving from cache:

```python
@dataclass(frozen=True, slots=True)
class SandboxCounts:
    """Immutable container for sandbox execution counters."""
    operation_count: int = 0
    iteration_count: int = 0

@dataclass(frozen=True, slots=True)
class BlueprintCache:
    blueprint_class: type[Blueprint]
    env: dict[str, object]
    loading_costs: SandboxCounts  # Sandbox counter deltas from loading
```

```python
def get_blueprint_class(self, sandbox_config: SandboxConfig | None = None) -> type[Blueprint]:
    was_cached = self._blueprint_cache is not None
    cache = self._load_blueprint_code(sandbox_config)

    # Apply cached costs when returning from cache
    if was_cached and sandbox_config is not None and cache.loading_costs:
        if hasattr(sys, 'sandbox') and sys.sandbox.enabled and not sys.sandbox.suspended:
            sys.sandbox.add_counts(**cache.loading_costs.to_dict())

    return cache.blueprint_class
```

### Cost Capture During Loading

```python
def _load_blueprint_code_exec(self, sandbox_config):
    with metered_executor:
        # Capture counts BEFORE exec
        before_counts = SandboxCounts.capture()

        env = metered_executor.exec(self.code.text)

        # Calculate delta using SandboxCounts subtraction
        after_counts = SandboxCounts.capture()
        loading_costs = after_counts - before_counts
```

### Loading Cost Deduplication Per Call Chain

When the same blueprint is accessed multiple times within a single call chain (e.g., contract A calls B, B calls C, C calls B again), the loading cost for each blueprint should only be charged **once per call chain**.

**Problem:**

Without deduplication, if contract A uses blueprint X, and contract B also uses blueprint X, and A calls B, the loading cost for X would be charged twice - once when A is loaded, and again when B is loaded.

**Solution:**

The Runner tracks which blueprint IDs have already been charged in the current call chain:

```python
# In Runner.__init__
self._charged_blueprint_ids: set[BlueprintId] = set()

# Reset at the start of each call chain
def _unsafe_call_public_method(...):
    self._charged_blueprint_ids.clear()
    # ...

def call_view_method(...):
    self._charged_blueprint_ids.clear()
    # ...

# Skip loading cost if already charged
def _create_blueprint_instance(self, blueprint_id, changes_tracker):
    skip_loading_cost = blueprint_id in self._charged_blueprint_ids
    if not skip_loading_cost:
        self._charged_blueprint_ids.add(blueprint_id)

    blueprint_class = self.tx_storage.get_blueprint_class(
        blueprint_id,
        skip_loading_cost=skip_loading_cost
    )
    return blueprint_class(env)
```

**Behavior:**

| Scenario | Loading Cost Charged |
|----------|---------------------|
| First access to blueprint B in call chain | Yes |
| Second access to blueprint B in same call chain | No (skipped) |
| First access to blueprint B in new call chain | Yes (tracking reset) |

This ensures fair and consistent cost accounting regardless of call patterns.

### OCB Loading Cost in CallRecord

The `CallRecord` dataclass includes an `ocb_loading_cost` field that records whether a loading cost was charged for that specific call:

```python
@dataclass(slots=True, frozen=True, kw_only=True)
class CallRecord:
    # ... other fields ...

    # OCB loading cost charged for this call. None means no loading cost was charged
    # (either sandbox not active, catalog blueprint, or already loaded in this call chain).
    ocb_loading_cost: SandboxCounts | None = None
```

This provides visibility into which calls incurred loading costs:

```python
call_info = runner.get_last_call_info()
for call_record in call_info.calls:
    if call_record.ocb_loading_cost:
        print(f"Call to {call_record.method_name} charged loading cost: "
              f"ops={call_record.ocb_loading_cost.operation_count}, "
              f"iters={call_record.ocb_loading_cost.iteration_count}")
    else:
        print(f"Call to {call_record.method_name} had no loading cost "
              "(catalog blueprint or deduplicated)")
```

---

## Cross-Contract Call Operation Counting

### Scenario

Contract A calls Contract B which calls Contract C:

```
Transaction starts
├── Load Blueprint A (1000 ops)
├── Execute A.method() (5000 ops)
│   ├── A calls B.method()
│   │   ├── Load Blueprint B (800 ops)
│   │   └── Execute B.method() (3000 ops)
│   │       ├── B calls C.method()
│   │       │   ├── Load Blueprint C (600 ops)
│   │       │   └── Execute C.method() (2000 ops)
│   │       └── B continues (1000 ops)
│   └── A continues (2000 ops)
└── Total: 15,400 operations (must be < max_operations)
```

### Implementation

The key is `reset_counters=False` in all nested calls:

```python
# In _execute_public_method_call (handles both direct and cross-contract calls)
ret = self._metered_executor.call(method, args=(ctx.copy(), *args), reset_counters=False)
```

This ensures:
- Entry point resets counters once
- All nested calls accumulate to the same counter
- Single transaction limit applies to total work

---

## Custom Builtins

Instead of using standard Python builtins, blueprints use restricted versions:

### Replaced Builtins

| Builtin | Replacement | Reason |
|---------|-------------|--------|
| `range` | `custom_range` | Pure Python, subject to operation counting |
| `all` | `custom_all` | Pure Python iterator consumption |
| `any` | `custom_any` | Pure Python iterator consumption |
| `enumerate` | `enumerate` | Pure Python generator |
| `filter` | `filter` | Pure Python generator |
| `__import__` | Restricted import | Only allows `ALLOWED_IMPORTS` |

### Disabled Builtins

Many builtins are disabled and raise `NCDisabledBuiltinError`:

- `eval`, `exec`, `compile` - Dynamic code execution
- `open`, `input`, `print` - I/O operations
- `getattr`, `setattr`, `delattr`, `hasattr` - Dynamic attribute access
- `globals`, `locals`, `vars`, `dir` - Introspection
- `type`, `super`, `object` - Metaclass/inheritance escape
- `float`, `complex` - Disallowed types
- And many more (see `DISABLED_BUILTINS` in `custom_builtins.py`)

---

## Sandbox Exception Handling

### Exception Types

```python
SandboxRuntimeError    # Operation/iteration limit exceeded
SandboxMemoryError     # Memory limit exceeded
SandboxOverflowError   # Integer overflow
SandboxTypeError       # Disallowed type (float, complex)
SandboxSecurityError   # Import/module access blocked
SandboxImportError     # Import restriction violated
```

### Exception Wrapping

All sandbox exceptions are caught and wrapped in `NCFail`:

```python
# In MeteredExecutor.call()
try:
    exec(code, env)
except NCFail:
    raise  # Preserve explicit NCFail from blueprint
except Exception as e:
    exc_info = f'{type(e).__name__}: {e}'
    raise NCFail(f'Execution failed: {exc_info}') from e
```

---

## Configuration

### SandboxConfig Dataclass

```python
@dataclass(frozen=True)
class SandboxConfig:
    # Size limits
    max_int_digits: int = 100
    max_str_length: int = 1_000_000
    max_bytes_length: int = 1_000_000
    max_list_size: int = 100_000
    max_dict_size: int = 100_000
    max_set_size: int = 100_000
    max_tuple_size: int = 100_000

    # Execution limits
    max_operations: int = 1_000_000
    max_iterations: int = 10_000_000
    max_recursion_depth: int = 100

    # Type restrictions
    allow_float: bool = False
    allow_complex: bool = False

    # Security restrictions
    allow_dunder_access: bool = False
    allow_io: bool = False
    allow_class_creation: bool = True
    allow_magic_methods: bool = False
    allow_metaclasses: bool = False
    allow_unsafe: bool = False

    # Counting mode
    count_iterations_as_operations: bool = True

    # Frozen mode
    frozen_mode: bool = True
    auto_mutable: bool = True
```

### Applying Configuration

```python
def apply(self) -> None:
    # Set all config parameters
    sys.sandbox.set_config(
        max_int_digits=self.max_int_digits,
        # ... all other parameters
    )

    # Set frozen mode
    sys.sandbox.frozen_mode = self.frozen_mode
    sys.sandbox.auto_mutable = self.auto_mutable

    # Enable opcode restrictions (defense in depth)
    # Mirrors OCB AST-level restrictions at bytecode level
    from hathor.nanocontracts.sandbox.allowlist import get_allowed_opcodes
    sys.sandbox.opcode_restrict_mode = True
    sys.sandbox.allowed_opcodes = get_allowed_opcodes()

    # Enable import restrictions (defense in depth)
    sys.sandbox.import_restrict_mode = True
    sys.sandbox.allowed_imports = get_sandbox_allowed_imports()

    # Enable module access restrictions (defense in depth)
    sys.sandbox.module_access_restrict_mode = True
    sys.sandbox.allowed_modules = get_sandbox_allowed_modules()

    # Whitelist Blueprint metaclass
    sys.sandbox.allowed_metaclasses = frozenset({_BlueprintBase})

    # Register filename for scope tracking
    sys.sandbox.add_filename(BLUEPRINT_FILENAME)
```

---

## Defense in Depth Layers

The sandbox provides multiple overlapping security layers:

1. **AST Verification** (before execution)
   - Blocks disallowed imports at parse time
   - Blocks dangerous name access (`__builtins__`, etc.)
   - Blocks try/except, async/await, star imports

2. **Opcode Restrictions** (bytecode level)
   - Mirrors AST restrictions at bytecode level
   - Blocks exception handling, async, and star import opcodes
   - New Python opcodes blocked by default (allowlist approach)

3. **Custom `__import__`** (runtime)
   - Primary import control
   - Returns fake modules with only allowed attributes

4. **`import_restrict_mode`** (sandbox level)
   - Backup if custom `__import__` is bypassed
   - Raises `SandboxImportError`

5. **`module_access_restrict_mode`** (sandbox level)
   - Blocks module usage even if reference obtained
   - Raises `SandboxSecurityError`

6. **Disabled Builtins** (runtime)
   - `getattr`, `setattr`, etc. raise `NCDisabledBuiltinError`

7. **Frozen Mode** (sandbox level)
   - Prevents mutation of external objects

---

## Testing

The test suite covers:

- `test_sandbox.py` - Integration with Runner
- `test_sandbox_attacks.py` - Attack vector prevention
- `test_sandbox_counters.py` - Operation counting accuracy
- `test_sandbox_dangerous.py` - Dangerous code patterns
- `test_sandbox_opcodes.py` - Opcode allowlist and restriction tests
- `test_custom_import.py` - Import restriction tests

Key test scenarios:
- Infinite loops blocked
- Cross-contract operation accumulation
- OCB loading cost consistency
- Large integer/string attacks prevented
- Import escape attempts blocked
- Exception handling opcodes blocked (try/except)
- Async opcodes blocked (async/await)
- New/unknown opcodes blocked by default
