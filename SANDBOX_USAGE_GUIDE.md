# CPython Sandbox Usage Guide

A practical guide for using the CPython sandbox to safely execute untrusted Python code with resource limits and restrictions.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Concepts](#core-concepts)
3. [Setting Resource Limits](#setting-resource-limits)
4. [Scope Management](#scope-management)
5. [Execution Limits](#execution-limits)
6. [Operation Counting](#operation-counting)
7. [Frozen Mode](#frozen-mode)
8. [Dunder Access Control](#dunder-access-control)
9. [Opcode Restrictions](#opcode-restrictions)
10. [Object Creation Hooks](#object-creation-hooks)
11. [Suspend/Resume for Trusted Code](#suspendresume-for-trusted-code)
12. [Exception Handling](#exception-handling)
13. [Complete Examples](#complete-examples)
14. [Best Practices](#best-practices)
15. [API Quick Reference](#api-quick-reference)

---

## Quick Start

The sandbox is accessed through the `sys` module. Here is a minimal example that sets up limits and runs untrusted code:

```python
import sys

# 1. Set resource limits
sys.sandbox.set_limits(
    max_list_size=10_000,
    max_str_length=10_000,
    max_statements=50_000,
    max_iterations=100_000,
    max_allocations=5_000,
    allow_dunder_access=False,
)

# 2. Register a filename for scope tracking
sys.sandbox.add_filename("<sandbox>")

# 3. Reset counters before each execution
sys.sandbox.reset_counts()

# 4. Compile and execute untrusted code
untrusted_code = """
result = sum(range(100))
"""

code = compile(untrusted_code, "<sandbox>", "exec")
namespace = {}
try:
    exec(code, namespace)
    print("Result:", namespace.get("result"))
except SandboxError as e:
    print(f"Sandbox violation: {e}")
finally:
    sys.sandbox.clear_filenames()
```

---

## Core Concepts

### Sandbox State

The sandbox state is global to the interpreter. All limits, counters, and configuration are shared across all threads within the same interpreter.

### Scoped Limits

All sandbox limits are scoped -- they only apply to code whose `co_filename` is registered in the sandbox. This includes:

- Size limits (`max_list_size`, `max_str_length`, etc.)
- Type restrictions (`allow_float`, `allow_complex`)
- `max_statements` -- limits executed statements
- `max_allocations` -- limits object allocations
- `max_iterations` -- limits iterator steps
- `max_operations` -- limits AST-level operations

Code outside the registered filenames (e.g., stdlib, builtins, your harness) is not affected by any sandbox limits.

### Scope Tracking

The sandbox determines which code is "sandboxed" by tracking filenames. When you compile code with `compile(source, "<sandbox>", "exec")` and register `"<sandbox>"` as a sandbox filename, all scoped limits apply to that code.

### Zero Means No Limit

All numeric limit values default to `0`, which means no limit. You must explicitly set non-zero values to enable enforcement.

---

## Setting Resource Limits

### Data Size Limits

Control the maximum size of built-in data types:

```python
sys.sandbox.set_limits(
    max_int_digits=100,       # Max internal digits (~9 decimal digits each)
    max_str_length=100_000,   # Max string characters
    max_bytes_length=100_000, # Max bytes length
    max_list_size=100_000,    # Max list items
    max_dict_size=100_000,    # Max dict entries
    max_set_size=100_000,     # Max set members
    max_tuple_size=100_000,   # Max tuple items
)
```

When a limit is exceeded, a `SandboxOverflowError` is raised:

```python
sys.sandbox.set_limits(max_list_size=10)
try:
    big_list = list(range(100))
except SandboxOverflowError as e:
    print(e)  # "List size (100) exceeds sandbox limit (10)"
```

### Type Restrictions

Forbid creation of specific types:

```python
sys.sandbox.set_limits(
    allow_float=False,    # Forbid float creation
    allow_complex=False,  # Forbid complex creation
)
```

Attempting to create a forbidden type raises `SandboxTypeError`:

```python
sys.sandbox.set_limits(allow_float=False)
try:
    x = 1.0  # SandboxTypeError: float type is forbidden in sandbox
except SandboxTypeError:
    pass
```

### Reading Current Limits

```python
limits = sys.sandbox.get_limits()
# Returns dict with all current limit values:
# {'max_int_digits': 100, 'max_str_length': 100000, ...,
#  'allow_float': True, 'allow_complex': True, 'allow_dunder_access': True}
```

### Resetting All State

Reset all limits, counters, modes, scope, and hooks to defaults:

```python
sys.sandbox.reset()  # All limits to 0, modes to defaults, counters to 0
```

---

## Scope Management

All sandbox limits require registering filenames to determine which code is "in scope".

### Method 1: Using `enter_scope()` (Simple)

For executing code in the current frame's context:

```python
sys.sandbox.set_limits(max_statements=10_000)

sys.sandbox.enter_scope()  # Registers current frame's filename + resets counters
try:
    # Code executed here and below is in scope
    exec(some_code)
finally:
    sys.sandbox.exit_scope()  # Clears all registered filenames
```

### Method 2: Using Filenames (Recommended)

For explicit control over what code is tracked:

```python
sys.sandbox.set_limits(max_statements=10_000)

# Register a virtual filename
sys.sandbox.add_filename("<user-code>")
sys.sandbox.reset_counts()

# Compile untrusted code with that filename
code = compile(user_source, "<user-code>", "exec")
try:
    exec(code)
except SandboxRuntimeError:
    print("Statement limit exceeded")
finally:
    sys.sandbox.clear_filenames()
```

This approach is preferred because:
- Only the user's code counts toward limits (not your harness code)
- The stdlib and builtins don't count toward scoped limits
- You have fine-grained control over what is tracked

### Method 3: Using `add_frame()`

Register the current frame's filename without resetting counters:

```python
sys.sandbox.add_frame()  # Adds current frame's co_filename to tracked set
```

### Checking Scope Status

```python
if sys.sandbox.in_scope():
    print("Currently executing in sandbox scope")
```

### Managing Filenames

```python
sys.sandbox.add_filename("<module-a>")
sys.sandbox.add_filename("<module-b>")
sys.sandbox.remove_filename("<module-a>")  # Remove specific filename
sys.sandbox.clear_filenames()               # Remove all filenames
```

---

## Execution Limits

### Statement Limit

Prevents infinite loops and long-running code by counting statement executions within scope:

```python
sys.sandbox.set_limits(max_statements=1000)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

code = compile("""
x = 0
while True:
    x += 1  # Each iteration counts as statements
""", "<sandbox>", "exec")

try:
    exec(code)
except SandboxRuntimeError as e:
    print(e)  # "Sandbox statement limit exceeded"
```

### Iteration Limit

Prevents excessive iteration even through C builtins like `sum()`, `list()`, `sorted()`:

```python
sys.sandbox.set_limits(max_iterations=10_000)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

code = compile("""
# Even though sum() runs in C, the iterator is wrapped
# and each step counts toward the iteration limit
total = sum(range(1_000_000))  # Will exceed iteration limit
""", "<sandbox>", "exec")

try:
    exec(code)
except SandboxRuntimeError as e:
    print(e)  # "Sandbox iteration limit exceeded"
```

### Allocation Limit

Limits GC-tracked object allocations from code whose filename is registered:

```python
sys.sandbox.set_limits(max_allocations=500)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

code = compile("""
items = []
for i in range(10000):
    items.append([i])
""", "<sandbox>", "exec")

try:
    exec(code)
except SandboxMemoryError:
    print("Allocation limit reached")
```

### Reading Counters

Check current counter values at any time:

```python
counts = sys.sandbox.get_counts()
print(f"Allocations: {counts['allocation_count']}")
print(f"Statements executed: {counts['statement_count']}")
print(f"Iterator steps: {counts['iteration_count']}")
print(f"Operations counted: {counts['operation_count']}")
```

### Resetting Counters

Reset all counters to 0 before each execution:

```python
sys.sandbox.reset_counts()
```

---

## Operation Counting

Operation counting provides an alternative to statement counting that works at the AST level. Instead of counting source lines via tracing, the compiler emits `SANDBOX_COUNT` opcodes at specific AST nodes. This has zero overhead for non-sandbox code and does not depend on the tracing mechanism.

### How It Works

1. **Compile with `PyCF_SANDBOX_COUNT` flag**: Code must be compiled with `flags=0x8000` to enable operation counting.
2. **Set `max_operations`**: Configure the maximum number of counted operations.
3. **Register filenames and reset counters**: Same as with statement counting.

### Basic Usage

```python
import sys

PyCF_SANDBOX_COUNT = 0x8000

sys.sandbox.set_limits(max_operations=1000)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

# Compile with the SANDBOX_COUNT flag
code = compile(user_source, "<sandbox>", "exec", flags=PyCF_SANDBOX_COUNT)

try:
    exec(code, {"__builtins__": __builtins__})
except SandboxRuntimeError as e:
    print(e)  # "Sandbox operation limit exceeded"
finally:
    sys.sandbox.clear_filenames()
```

### What Gets Counted

Each `SANDBOX_COUNT` opcode increments the `operation_count` counter. The compiler emits one opcode per AST node for:

**Counted Statements:**
- `Assign`, `AugAssign`, `Delete`
- `Pass`, `Break`, `Continue`, `Return`
- `If`, `For`, `While`, `Try`
- `Import`, `ImportFrom`
- `Assert`
- `FunctionDef`, `ClassDef`

**Counted Expressions:**
- `Call` (function/method calls)
- `BinOp` (e.g., `a + b`)
- `UnaryOp` (e.g., `-a`)
- `Compare` (e.g., `a < b`)
- `BoolOp` (e.g., `a and b`)
- `Attribute` (e.g., `obj.attr`)
- `Subscript` (e.g., `a[0]`)

**Not Counted:**
- `Expr` statement wrapper (the inner expression is counted instead)
- `Global`, `Nonlocal` (compile-time directives)
- Literal values, `Name` loads, `Starred`

### Counting Examples

```python
# a = 1          -> Assign(1) = 1 operation
# a = len([])    -> Assign(1) + Call(1) = 2 operations
# a = len([]) + 1 -> Assign(1) + Call(1) + BinOp(1) = 3 operations
# for i in range(3): a = i -> For(1) + Call(1) + Assign*3 = 5 operations
```

### Reading the Operation Counter

```python
counts = sys.sandbox.get_counts()
print(f"Operations: {counts['operation_count']}")
```

### Independence from Statement Counting

Operation counting (`max_operations`) and statement counting (`max_statements`) are independent mechanisms. You can use either or both:

```python
sys.sandbox.set_limits(
    max_statements=100_000,   # Tracing-based line counting
    max_operations=50_000,    # Opcode-based AST node counting
)
```

Code compiled **without** `PyCF_SANDBOX_COUNT` has zero operation counting overhead. Code compiled **with** the flag but without `max_operations` set has minimal overhead (one pointer dereference + comparison per counted node).

### Counting Iterations as Operations

By default, iterator steps only increment `iteration_count`. When `count_iterations_as_operations` is enabled, each iterator yield also increments `operation_count`, allowing you to enforce a single unified limit via `max_operations` for both AST-level operations and iterator steps:

```python
sys.sandbox.set_limits(
    max_operations=10_000,
    count_iterations_as_operations=True,
)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

code = compile("""
total = sum(range(1_000_000))  # Each iterator step counts as an operation
""", "<sandbox>", "exec", flags=0x8000)

try:
    exec(code)
except SandboxRuntimeError:
    print("Operation limit exceeded (includes iteration steps)")
finally:
    sys.sandbox.clear_filenames()
```

The flag can also be set as a property:

```python
sys.sandbox.count_iterations_as_operations = True
```

### No-Flag Code Is Not Counted

Code compiled without `PyCF_SANDBOX_COUNT` does not contain `SANDBOX_COUNT` opcodes, so operations are never counted regardless of limits:

```python
# This code will NOT count operations (no flag)
code = compile("a = 1\nb = 2", "<sandbox>", "exec")

# This code WILL count operations (flag set)
code = compile("a = 1\nb = 2", "<sandbox>", "exec", flags=0x8000)
```

---

## Frozen Mode

Frozen mode prevents attribute modifications (set/delete) on objects. This is useful for protecting shared state from sandboxed code.

### Global Frozen Mode

Block all attribute mutations within sandbox scope:

```python
# Set up scope first
sys.sandbox.add_filename("<sandbox>")

# Enable frozen mode
sys.sandbox.frozen_mode = True

code = compile("""
class Foo:
    pass
obj = Foo()
obj.x = 1  # SandboxAttributeError: cannot modify 'Foo' object: sandbox frozen mode is active
""", "<sandbox>", "exec")

try:
    exec(code)
except SandboxAttributeError as e:
    print(e)
finally:
    sys.sandbox.frozen_mode = False
    sys.sandbox.clear_filenames()
```

### Per-Object Freezing

Freeze specific objects regardless of global frozen mode:

```python
class Config:
    pass

config = Config()
config.api_key = "secret"
config.timeout = 30

# Freeze this specific object
sys.sandbox.freeze(config)

# Now even without global frozen mode:
try:
    config.api_key = "hacked"  # SandboxAttributeError
except SandboxAttributeError:
    print("Cannot modify frozen config")

# Check if frozen
print(sys.sandbox.is_frozen(config))  # True
```

### Mutable Override

Mark specific objects as always mutable, even when global frozen mode is active:

```python
# Create an output object that sandboxed code CAN modify
output = type('Output', (), {})()
sys.sandbox.set_mutable(output)

sys.sandbox.frozen_mode = True
sys.sandbox.add_filename("<sandbox>")

code = compile("""
output.result = 42  # Allowed because output is marked mutable
""", "<sandbox>", "exec")

exec(code, {"output": output})
print(output.result)  # 42

# Remove mutable flag if needed
sys.sandbox.set_mutable(output, False)
```

### Auto-Mutable Mode

When frozen mode is active, sandboxed code cannot modify any objects -- including objects it creates itself (classes, instances, functions). Auto-mutable mode solves this by automatically marking newly created objects as mutable when they are created within sandbox scope.

```python
# Enable both frozen mode and auto-mutable mode
sys.sandbox.frozen_mode = True
sys.sandbox.auto_mutable = True
sys.sandbox.add_filename("<sandbox>")

code = compile("""
class Foo:
    pass
obj = Foo()
obj.x = 42  # Allowed - obj was created in sandbox scope and auto-marked mutable
""", "<sandbox>", "exec")

exec(code)

# Check the mode
print(sys.sandbox.auto_mutable)  # True

# Clean up
sys.sandbox.auto_mutable = False
sys.sandbox.frozen_mode = False
sys.sandbox.clear_filenames()
```

Auto-mutable mode automatically applies `Py_OBJFLAGS_MUTABLE` to objects created via `type.__call__` (classes and instances) and `MAKE_FUNCTION` (function definitions) when:
- Both `auto_mutable` and `frozen_mode` are active
- The current frame is within sandbox scope
- The sandbox is not suspended

This allows sandboxed code to define and use its own classes and functions naturally while still preventing modification of imported or pre-existing objects.

### Frozen Mode with Scope

Frozen mode is scope-aware. Only code with registered filenames is restricted:

```python
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.frozen_mode = True

# Your harness code (not in scope) can still modify objects
class Container:
    pass
c = Container()
c.value = 42  # Works fine - your code is not in sandbox scope

# But sandboxed code cannot
code = compile("c.value = 99", "<sandbox>", "exec")
try:
    exec(code, {"c": c})
except SandboxAttributeError:
    print("Sandboxed code blocked from modifying c")
```

---

## Dunder Access Control

Block access to double-underscore (`__dunder__`) attributes from sandboxed code. This prevents introspection-based escapes like `obj.__class__.__subclasses__()`.

### Enabling Dunder Blocking

```python
sys.sandbox.set_limits(allow_dunder_access=False)
sys.sandbox.add_filename("<sandbox>")

code = compile("""
x = {}
# All of these are blocked:
# x.__class__
# x.__class__.__subclasses__()
# type.__bases__
try:
    cls = x.__class__  # SandboxAttributeError
except SandboxAttributeError:
    pass  # Blocked

# Normal attributes still work
class Foo:
    pass
Foo.bar = 42  # OK - not a dunder
""", "<sandbox>", "exec")

exec(code)
```

### What Counts as a Dunder

Any attribute name containing `__` (double underscore) anywhere in the name is blocked. This includes:
- `__class__`, `__dict__`, `__bases__`, `__subclasses__`
- `__init__`, `__new__`, `__del__`
- `__getattr__`, `__setattr__`, `__delattr__`

Single underscore attributes (`_private`) are not affected.

### Scope-Aware

Dunder blocking only applies within sandbox scope. Your harness code can freely use dunder attributes:

```python
sys.sandbox.set_limits(allow_dunder_access=False)
sys.sandbox.add_filename("<sandbox>")

# Your code (not in scope) - works fine
print(dict.__bases__)

# Sandboxed code - blocked
code = compile("print(dict.__bases__)", "<sandbox>", "exec")
try:
    exec(code)
except SandboxAttributeError:
    print("Blocked dunder access in sandbox")
```

---

## Opcode Restrictions

Ban specific bytecode opcodes from executing in sandbox scope. This provides fine-grained control over what operations sandboxed code can perform.

### Setting Up Opcode Restrictions

```python
import dis

# Ban import-related opcodes
banned = {
    dis.opmap['IMPORT_NAME'],
    dis.opmap['IMPORT_FROM'],
    dis.opmap['IMPORT_STAR'],
}

sys.sandbox.banned_opcodes = banned
sys.sandbox.opcode_restrict_mode = True
sys.sandbox.add_filename("<sandbox>")

code = compile("""
import os  # SandboxRuntimeError: Opcode N is not allowed in sandbox scope
""", "<sandbox>", "exec")

try:
    exec(code)
except SandboxRuntimeError as e:
    print(e)
finally:
    sys.sandbox.opcode_restrict_mode = False
    sys.sandbox.banned_opcodes = None  # Clear all banned opcodes
```

### Common Opcode Sets to Ban

```python
import dis

# Ban imports
IMPORT_OPCODES = {
    dis.opmap['IMPORT_NAME'],
    dis.opmap['IMPORT_FROM'],
    dis.opmap['IMPORT_STAR'],
}

# Ban global/nonlocal variable access
GLOBAL_OPCODES = {
    dis.opmap.get('STORE_GLOBAL'),
    dis.opmap.get('DELETE_GLOBAL'),
    dis.opmap.get('LOAD_GLOBAL'),  # Note: this also blocks function calls
}

# Ban raise/exception manipulation
EXCEPTION_OPCODES = {
    dis.opmap.get('RAISE_VARARGS'),
    dis.opmap.get('RERAISE'),
}
```

### Reading Current Banned Opcodes

```python
banned = sys.sandbox.banned_opcodes  # Returns frozenset of ints
print(f"Banned opcodes: {banned}")

mode = sys.sandbox.opcode_restrict_mode
print(f"Opcode restriction active: {mode}")
```

---

## Object Creation Hooks

Intercept object creation for monitoring or replacement.

### Setting a Hook

```python
def creation_hook(obj, type_, frame, context):
    """Called for every object created via type.__call__."""
    print(f"Created: {type_.__name__}")
    return obj  # Return original object

sys.sandbox.creation_hook = creation_hook

class Foo:
    pass

instance = Foo()  # Prints: Created Foo

sys.sandbox.creation_hook = None  # Remove hook
```

### Blocking Object Creation

```python
def block_types(obj, type_, frame, context):
    """Block creation of specific types."""
    if type_.__name__ in ('socket', 'Process'):
        raise SandboxTypeError(f"Cannot create {type_.__name__} in sandbox")
    return obj

sys.sandbox.creation_hook = block_types
```

### Replacing Objects

```python
def replace_hook(obj, type_, frame, context):
    """Replace objects at creation time."""
    if type_.__name__ == 'dict':
        # Replace with a read-only wrapper (hypothetical)
        return ReadOnlyDict(obj)
    return obj

sys.sandbox.creation_hook = replace_hook
```

### Reading Current Hook

```python
hook = sys.sandbox.creation_hook
if hook is not None:
    print(f"Hook active: {hook}")
```

---

## Suspend/Resume for Trusted Code

Temporarily bypass all sandbox limits when executing trusted code.

### Basic Usage

```python
sys.sandbox.set_limits(max_list_size=10)

# Create a large list in trusted code
count = sys.sandbox.suspend()  # Returns 1
large_list = list(range(1000))       # Works - limits suspended
sys.sandbox.resume()            # Limits active again

# Now this would fail
try:
    another_list = list(range(100))  # SandboxOverflowError
except SandboxOverflowError:
    pass
```

### Nested Suspend/Resume

Suspend calls nest. Limits resume only when the count reaches 0:

```python
sys.sandbox.suspend()  # count = 1
sys.sandbox.suspend()  # count = 2
sys.sandbox.resume()   # count = 1 (still suspended)
sys.sandbox.resume()   # count = 0 (limits active again)
```

### Check Suspend Status

```python
if sys.sandbox.suspended:
    print("Limits are currently suspended")
```

### Context Manager Pattern

For cleaner code, wrap suspend/resume in a context manager:

```python
from contextlib import contextmanager

@contextmanager
def sandbox_suspended():
    sys.sandbox.suspend()
    try:
        yield
    finally:
        sys.sandbox.resume()

# Usage:
with sandbox_suspended():
    # All limits bypassed here
    large_data = process_untrusted_output(result)
```

### What Suspend Bypasses

Suspend bypasses **all** sandbox restrictions:
- Size limits (int, str, bytes, list, dict, set, tuple)
- Type restrictions (float, complex)
- Allocation counting
- Statement counting
- Iteration counting
- Operation counting
- Frozen mode (including auto-mutable marking)
- Dunder access blocking
- Opcode restrictions

---

## Exception Handling

All sandbox violations raise exceptions from a dedicated hierarchy.

### Exception Hierarchy

```
Exception
 +-- SandboxError                    # Base class for all sandbox violations
      +-- SandboxOverflowError       # Size/length limit exceeded
      +-- SandboxMemoryError         # Allocation limit exceeded
      +-- SandboxRuntimeError        # Statement/iteration/operation limit, banned opcode
      +-- SandboxTypeError           # Forbidden type creation
      +-- SandboxAttributeError      # Frozen mode or dunder access blocked
```

### Catching All Sandbox Errors

```python
try:
    exec(sandboxed_code)
except SandboxError as e:
    # Catches any sandbox violation
    print(f"Sandbox violation: {type(e).__name__}: {e}")
```

### Catching Specific Errors

```python
try:
    exec(sandboxed_code)
except SandboxOverflowError:
    print("Data too large")
except SandboxMemoryError:
    print("Too many object allocations")
except SandboxRuntimeError:
    print("Execution limit exceeded (statements, iterations, operations, or banned opcode)")
except SandboxTypeError:
    print("Forbidden type creation attempted")
except SandboxAttributeError:
    print("Attribute access blocked (frozen mode or dunder)")
except SandboxError:
    print("Other sandbox violation")
```

### Exception Availability

All sandbox exceptions are available as builtins -- no import needed:

```python
# These all work without imports:
try:
    exec(code)
except SandboxError:
    pass
except SandboxOverflowError:
    pass
```

### Single-Raise Behavior

Statement, iteration, and operation limits raise their exception **exactly once** on first violation. This allows `except` and `finally` blocks to execute normally:

```python
sys.sandbox.set_limits(max_statements=100)
sys.sandbox.add_filename("<sandbox>")
sys.sandbox.reset_counts()

code = compile("""
try:
    while True:
        pass  # Will hit statement limit
except SandboxRuntimeError:
    # This except block runs normally (no second exception)
    result = "caught"
""", "<sandbox>", "exec")

ns = {}
exec(code, ns)
print(ns["result"])  # "caught"
```

---

## Complete Examples

### Example 1: Safe Code Evaluation

```python
import sys

def safe_eval(source, allowed_globals=None, timeout_statements=100_000):
    """Safely evaluate Python code with sandbox limits."""
    # Save original limits
    original = sys.sandbox.get_limits()

    try:
        # Configure sandbox
        sys.sandbox.set_limits(
            max_int_digits=50,
            max_str_length=50_000,
            max_bytes_length=50_000,
            max_list_size=50_000,
            max_dict_size=10_000,
            max_set_size=10_000,
            max_tuple_size=50_000,
            max_statements=timeout_statements,
            max_iterations=500_000,
            max_allocations=5_000,
            allow_dunder_access=False,
        )

        # Set up scope
        sys.sandbox.add_filename("<safe-eval>")
        sys.sandbox.reset_counts()

        # Enable frozen mode to protect shared state
        sys.sandbox.frozen_mode = True

        # Enable auto-mutable so sandboxed code can define and use its own
        # classes, functions, and instances without manual mutable marking
        sys.sandbox.auto_mutable = True

        # Prepare namespace
        namespace = {"__builtins__": __builtins__}
        if allowed_globals:
            namespace.update(allowed_globals)

        # Mark namespace as mutable so sandboxed code can write results
        sys.sandbox.set_mutable(namespace)

        # Compile and execute
        code = compile(source, "<safe-eval>", "exec")
        exec(code, namespace)

        return namespace

    except SandboxError as e:
        return {"error": f"{type(e).__name__}: {e}"}

    finally:
        sys.sandbox.auto_mutable = False
        sys.sandbox.frozen_mode = False
        sys.sandbox.clear_filenames()
        sys.sandbox.set_limits(**original)
        sys.sandbox.reset_counts()


# Usage
result = safe_eval("x = sum(range(100))")
print(result.get("x"))  # 4950

result = safe_eval("while True: pass")
print(result.get("error"))  # "SandboxRuntimeError: Sandbox statement limit exceeded"
```

### Example 2: Restricted Expression Evaluator

```python
import sys
import dis

def eval_expression(expr):
    """Evaluate a mathematical expression with strong restrictions."""
    original = sys.sandbox.get_limits()

    try:
        # Strict limits for expressions
        sys.sandbox.set_limits(
            max_int_digits=20,
            max_str_length=1000,
            allow_float=True,
            allow_complex=False,
            allow_dunder_access=False,
            max_statements=100,
            max_iterations=1000,
        )

        # Ban imports
        banned = {
            dis.opmap['IMPORT_NAME'],
            dis.opmap['IMPORT_FROM'],
            dis.opmap['IMPORT_STAR'],
        }
        sys.sandbox.banned_opcodes = banned
        sys.sandbox.opcode_restrict_mode = True

        # Set up scope
        sys.sandbox.add_filename("<expr>")
        sys.sandbox.reset_counts()

        # Compile as eval (expression only, no statements)
        code = compile(expr, "<expr>", "eval")
        result = eval(code, {"__builtins__": {}})
        return result

    except SandboxError as e:
        raise ValueError(f"Expression error: {e}") from e

    finally:
        sys.sandbox.opcode_restrict_mode = False
        sys.sandbox.banned_opcodes = None
        sys.sandbox.clear_filenames()
        sys.sandbox.set_limits(**original)
        sys.sandbox.reset_counts()


# Usage
print(eval_expression("2 + 3 * 4"))    # 14
print(eval_expression("2 ** 10"))       # 1024
```

### Example 3: Multi-Tenant Code Runner

```python
import sys

class SandboxRunner:
    """Run code for multiple tenants with per-tenant limits."""

    def __init__(self, max_statements=50_000, max_allocations=10_000):
        self.max_statements = max_statements
        self.max_allocations = max_allocations

    def run(self, tenant_id, source):
        """Run source code for a tenant, return results or error."""
        filename = f"<tenant-{tenant_id}>"
        original = sys.sandbox.get_limits()

        try:
            sys.sandbox.set_limits(
                max_int_digits=50,
                max_str_length=10_000,
                max_bytes_length=10_000,
                max_list_size=10_000,
                max_dict_size=5_000,
                max_set_size=5_000,
                max_tuple_size=10_000,
                max_statements=self.max_statements,
                max_iterations=self.max_statements * 10,
                max_allocations=self.max_allocations,
                allow_dunder_access=False,
            )

            sys.sandbox.add_filename(filename)
            sys.sandbox.reset_counts()
            sys.sandbox.frozen_mode = True

            namespace = {"__builtins__": __builtins__}
            sys.sandbox.set_mutable(namespace)

            code = compile(source, filename, "exec")
            exec(code, namespace)

            counts = sys.sandbox.get_counts()
            return {
                "success": True,
                "namespace": {k: v for k, v in namespace.items()
                             if not k.startswith("_")},
                "statements": counts["statement_count"],
                "allocations": counts["allocation_count"],
            }

        except SandboxError as e:
            counts = sys.sandbox.get_counts()
            return {
                "success": False,
                "error": f"{type(e).__name__}: {e}",
                "statements": counts["statement_count"],
                "allocations": counts["allocation_count"],
            }

        finally:
            sys.sandbox.frozen_mode = False
            sys.sandbox.clear_filenames()
            sys.sandbox.set_limits(**original)
            sys.sandbox.reset_counts()


# Usage
runner = SandboxRunner()

result = runner.run("alice", "x = [i**2 for i in range(10)]")
print(result)
# {'success': True, 'namespace': {'x': [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]},
#  'statements': ..., 'allocations': ...}

result = runner.run("bob", "while True: pass")
print(result)
# {'success': False, 'error': 'SandboxRuntimeError: ...', ...}
```

---

## Best Practices

### 1. Always Use Scope Tracking

Without scope tracking, limits (statements, iterations, allocations) are not enforced. Always register filenames:

```python
# Good
sys.sandbox.add_filename("<sandbox>")
code = compile(source, "<sandbox>", "exec")

# Bad - scoped limits won't apply
code = compile(source, "<string>", "exec")
# ("<string>" is not registered, so no scoped enforcement)
```

### 2. Reset Counters Before Each Execution

```python
sys.sandbox.reset_counts()  # Always reset before running untrusted code
exec(code)
```

### 3. Clean Up in Finally Blocks

Always restore sandbox state, even if execution fails:

```python
original = sys.sandbox.get_limits()
try:
    sys.sandbox.set_limits(...)
    sys.sandbox.add_filename("<sandbox>")
    exec(code)
finally:
    sys.sandbox.auto_mutable = False
    sys.sandbox.frozen_mode = False
    sys.sandbox.opcode_restrict_mode = False
    sys.sandbox.banned_opcodes = None
    sys.sandbox.clear_filenames()
    sys.sandbox.set_limits(**original)
    sys.sandbox.reset_counts()
```

### 4. Use Multiple Execution Limits

Statement limits catch Python-level loops, but C builtins like `sum()`, `list()`, `sorted()` bypass the statement counter. Use iteration limits to catch these. Operation limits provide precise AST-level counting with zero tracing overhead:

```python
sys.sandbox.set_limits(
    max_statements=100_000,   # Catches: while True: pass
    max_iterations=1_000_000, # Catches: sum(range(10**9))
    max_operations=50_000,    # AST-level counting (requires PyCF_SANDBOX_COUNT)
)
```

### 5. Combine Multiple Protections

No single limit is sufficient. Use multiple layers:

```python
sys.sandbox.set_limits(
    # Data size limits
    max_list_size=100_000,
    max_str_length=100_000,

    # Execution limits
    max_statements=100_000,
    max_iterations=1_000_000,
    max_operations=50_000,   # Requires PyCF_SANDBOX_COUNT at compile time

    # Memory limits
    max_allocations=10_000,

    # Access control
    allow_dunder_access=False,
)

# Plus frozen mode for shared state protection
sys.sandbox.frozen_mode = True

# Plus opcode restrictions for import blocking
sys.sandbox.banned_opcodes = {dis.opmap['IMPORT_NAME'], ...}
sys.sandbox.opcode_restrict_mode = True
```

### 6. Use Mutable Objects for Output

When frozen mode is active, mark output containers as mutable:

```python
output = {}
sys.sandbox.set_mutable(output)
# Sandboxed code can write to output even in frozen mode
```

### 7. Security Warning

The sandbox limits are designed for resource protection, not as a complete security boundary. Code with access to C extensions, `ctypes`, or other low-level APIs can bypass these limits. For maximum restriction:

- Ban import opcodes
- Remove dangerous builtins from the namespace
- Block dunder access
- Use frozen mode
- Consider running in a subprocess with OS-level sandboxing

---

## API Quick Reference

### Limit Configuration

| Function | Description |
|----------|-------------|
| `sys.sandbox.set_limits(**kwargs)` | Set resource limits |
| `sys.sandbox.get_limits() -> dict` | Get current limits |
| `sys.sandbox.get_counts() -> dict` | Get current counters |
| `sys.sandbox.reset_counts()` | Reset all counters to 0 |

### Scope Management

| Function | Description |
|----------|-------------|
| `sys.sandbox.enter_scope()` | Register current frame + reset counters |
| `sys.sandbox.exit_scope()` | Clear all registered filenames |
| `sys.sandbox.in_scope() -> bool` | Check if current code is in scope |
| `sys.sandbox.add_frame()` | Register current frame's filename |
| `sys.sandbox.add_filename(name)` | Register a filename |
| `sys.sandbox.remove_filename(name)` | Remove a filename |
| `sys.sandbox.clear_filenames()` | Clear all filenames |

### Frozen Mode

| Function | Description |
|----------|-------------|
| `sys.sandbox.frozen_mode = bool` | Enable/disable global freeze |
| `sys.sandbox.frozen_mode -> bool` | Check global freeze status |
| `sys.sandbox.freeze(obj)` | Freeze a specific object |
| `sys.sandbox.is_frozen(obj) -> bool` | Check if object is frozen |
| `sys.sandbox.set_mutable(obj, bool)` | Set/clear mutable flag |
| `sys.sandbox.auto_mutable = bool` | Enable/disable auto-mutable mode |
| `sys.sandbox.auto_mutable -> bool` | Check auto-mutable mode status |

### Opcode Restrictions

| Function | Description |
|----------|-------------|
| `sys.sandbox.opcode_restrict_mode = bool` | Enable/disable opcode checking |
| `sys.sandbox.opcode_restrict_mode -> bool` | Check mode status |
| `sys.sandbox.banned_opcodes = set/None` | Set banned opcodes |
| `sys.sandbox.banned_opcodes -> frozenset` | Get banned opcodes |

### Object Creation Hook

| Function | Description |
|----------|-------------|
| `sys.sandbox.creation_hook = callable/None` | Set/remove creation hook |
| `sys.sandbox.creation_hook -> callable` | Get current hook |

### Suspend/Resume

| Function | Description |
|----------|-------------|
| `sys.sandbox.suspend() -> int` | Suspend limits |
| `sys.sandbox.resume() -> int` | Resume limits |
| `sys.sandbox.suspended -> bool` | Check suspend status |

### Exceptions

| Exception | Raised When |
|-----------|-------------|
| `SandboxError` | Base class for all sandbox violations |
| `SandboxOverflowError` | Size/length limit exceeded |
| `SandboxMemoryError` | Allocation limit exceeded |
| `SandboxRuntimeError` | Statement/iteration/operation limit or banned opcode |
| `SandboxTypeError` | Forbidden type creation |
| `SandboxAttributeError` | Frozen mode or dunder access blocked |

### `set_limits()` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_int_digits` | int | 0 | Max internal integer digits |
| `max_str_length` | int | 0 | Max string characters |
| `max_bytes_length` | int | 0 | Max bytes length |
| `max_list_size` | int | 0 | Max list items |
| `max_dict_size` | int | 0 | Max dict entries |
| `max_set_size` | int | 0 | Max set members |
| `max_tuple_size` | int | 0 | Max tuple items |
| `max_statements` | int | 0 | Max statements in scope |
| `max_allocations` | int | 0 | Max allocations in scope |
| `max_iterations` | int | 0 | Max iterator steps in scope |
| `max_operations` | int | 0 | Max AST operations in scope (requires `PyCF_SANDBOX_COUNT`) |
| `allow_float` | bool | True | Allow float creation |
| `allow_complex` | bool | True | Allow complex creation |
| `allow_dunder_access` | bool | True | Allow `__dunder__` attributes |
| `count_iterations_as_operations` | bool | False | Count iterator yields toward `operation_count` |
