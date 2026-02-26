# OCB Security: Attack Vector Catalog

> **Purpose:** Complete catalog of 30 attack vectors for reference
> **Companion to:** [0000-ocb.md](./0000-ocb.md) (main RFC)
> **Status:** Living document (update as new attacks discovered)

## How to Use This Document

- **Security reviewers:** Verify each attack is addressed by proposed solution
- **Implementers:** Use as test cases for AST validator and Rust VM
- **Auditors:** Verify no gaps in attack coverage

## Quick Reference

Jump to:
- [RCE Attacks (A1-A4)](#category-a-remote-code-execution-rce-attacks) - 4 vectors, 4 blocked ✅
- [Code Injection (B1-B4)](#category-b-code-injection-attacks) - 4 vectors, 4 blocked ✅
- [Non-Determinism (C1-C7)](#category-c-non-determinism-attacks) - 7 vectors, 5 blocked, 2 partial ⚠️
- [Computational DoS (D1.1-D1.3)](#subcategory-d1-computational-dos) - 3 vectors, 3 blocked ✅
- [Memory DoS (D2.1-D2.6)](#subcategory-d2-memory-dos) - 6 vectors, 6 blocked ✅
- [Time DoS (D3.1-D3.3)](#subcategory-d3-time-dos) - 3 vectors, 3 blocked ✅
- [Hash Collision DoS (D4.1)](#subcategory-d4-hash-collision-dos) - 1 vector, 1 partial ⚠️
- [Import Attacks (E1-E2)](#category-e-import-system-attacks) - 2 vectors, 2 blocked ✅

**Remaining gaps:** hash seed derivation

---

**Legend**: ✅ Fully blocked | ⚠️ Partially blocked | ❌ Not blocked

## Category A: Remote Code Execution (RCE) Attacks

**Goal**: Escape the sandbox to execute arbitrary system commands or access node resources.

---

### Attack A1: Python Introspection Chain

**Code:**
```python
# Attempt to access object.__subclasses__() to find dangerous classes
x.__class__.__bases__[0].__subclasses__()
```

**Status**: ✅ BLOCKED by AST validation (rejects `__` attributes in names)

---

### Attack A2: Builtin Attribute Access

**Code:**
```python
# Attempt to access private attributes via getattr
getattr(obj, '__class__')
getattr(obj, '__builtins__')
```

**Status**: ✅ BLOCKED - `getattr` disabled in `EXEC_BUILTINS`

---

### Attack A3: Direct Builtin Access

**Code:**
```python
# Direct use of dangerous functions
eval('malicious code')
exec('import os; os.system("rm -rf /")')
compile('bad code', '<string>', 'exec')
open('/etc/passwd', 'r')
__import__('os')
```

**Status**: ✅ BLOCKED - These builtins raise `NCDisabledBuiltinError`

---

### Attack A4: Dict-based Attribute Access

**Code:**
```python
# Bypass attribute access restrictions via __dict__
obj.__dict__['__class__']
```

**Status**: ✅ BLOCKED - `__dict__` rejected by AST validation

---

**Unresolved question**: Are there indirect paths to access `object` or `type` that bypass these protections?

---

## Category B: Code Injection Attacks

**Goal**: Modify the execution environment or inject malicious code into the interpreter state.

---

### Attack B1: RNG Manipulation via Direct Attribute Setting

**Code:**
```python
# Attempt to make RNG predictable
self.syscall.rng.random = lambda: 0.5
self.syscall.rng._NanoRNG__seed = b'x' * 32
```

**Status**: ✅ BLOCKED - `FauxImmutable` prevents `__setattr__`

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_b1_rng_direct_attribute_setting`

---

### Attack B2: RNG Manipulation via setattr()

**Code:**
```python
setattr(self.syscall.rng, 'random', lambda: 0.5)
```

**Status**: ✅ BLOCKED - `setattr` disabled in `EXEC_BUILTINS`

---

### Attack B3: RNG Manipulation via object.__setattr__()

**Code:**
```python
object.__setattr__(self.syscall.rng, 'random', lambda: 0.5)
```

**Status**: ✅ BLOCKED - `object` not available in `EXEC_BUILTINS`

---

### Attack B4: Class Modification

**Code:**
```python
# Attempt to modify class behavior
MyClass.__init__ = malicious_init
MyClass.method = malicious_method
```

**Status**: ✅ BLOCKED - `FauxImmutableMeta` prevents class modification

---

**Unresolved question**: Can `object` type be accessed indirectly to bypass `FauxImmutable`?

---

## Category C: Non-Determinism Attacks

**Goal**: Create execution that produces different results on different nodes, breaking consensus.

---

### Attack C1: Float Literals

**Code:**
```python
x = 3.14          # Float literal
y = 1 / 2         # True division
z = 1.0           # Float with .0
w = .5            # Float without leading zero
```

**Status**: ✅ BLOCKED - AST rejects float literals and `/` operator

---

### Attack C2: Complex Literals

**Code:**
```python
x = 1j            # Imaginary number
y = 2 + 3j        # Complex number
```

**Status**: ✅ BLOCKED - AST rejects complex literals

---

### Attack C3: Float/Complex Constructor Functions

**Code:**
```python
x = float(5)
y = complex(1, 2)
```

**Status**: ✅ BLOCKED - `float()` and `complex()` disabled builtins

---

### Attack C4: Runtime Float via Power Operator

**Code:**
```python
x = 2**-1         # Produces 0.5 (float) at runtime
y = 10**-3        # Produces 0.001 (float)
z = 5**-2         # Produces 0.04 (float)
```

**Status**: ✅ BLOCKED - Sandbox type restrictions block float creation at runtime

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_c4_runtime_float_via_power_operator`

---

### Attack C5: Runtime Float via pow() Builtin

**Code:**
```python
x = pow(2, -1)    # Produces 0.5 (float)
y = pow(10, -3)   # Produces 0.001 (float)
```

**Status**: ✅ BLOCKED - Sandbox type restrictions block float creation at runtime

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_c5_runtime_float_via_pow`

---

### Attack C6: Hash Randomization - Set Operations

**Code:**
```python
# Set iteration order depends on PYTHONHASHSEED
s = {1, 2, 3}
x = s.pop()       # Non-deterministic result without fixed seed

# Set iteration
for item in {1, 2, 3}:
    process(item)  # Order may vary across nodes
```

**Status**: ⚠️ PARTIAL - Deterministic within same process; needs block-derived PYTHONHASHSEED for cross-node consensus

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_c6_hash_randomization_sets`

---

### Attack C7: Hash Randomization - Dictionary Operations

**Code:**
```python
# Hash function depends on PYTHONHASHSEED
d = {hash(i): i for i in data}  # Order depends on seed

# Dictionary iteration (Python 3.7+ is insertion-ordered, but hash affects insertion)
for key in some_dict:
    process(key)
```

**Status**: ⚠️ PARTIAL - Deterministic within same process; needs block-derived PYTHONHASHSEED for cross-node consensus

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_c7_hash_randomization_dicts`

---

## Category D: Denial of Service (DoS) Attacks

**Goal**: Consume excessive resources (CPU, memory, time) to disrupt node operation.

### Subcategory D1: Computational DoS

---

### Attack D1.1: Exponential Computation

**Code:**
```python
# Exponential tower
result = 10**10**10

# Nested exponentiation
x = 2
for _ in range(1000):
    x = x ** x

# Large power operations
y = 2 ** (10**9)  # Massive number
```

**Status**: ✅ BLOCKED - Sandbox operation limits prevent excessive computation

**Test:** `hathor_tests/sandbox/test_sandbox_dangerous.py::DangerousSandboxTestCase::test_d1_1_exponential_computation`

---

### Attack D1.2: Large Number Operations

**Code:**
```python
# Sum of huge range
sum(range(10**15))  # Would take forever

# Repeated operations on large ranges
for i in range(10**12):
    expensive_operation(i)

# Large number arithmetic
x = (10**1000) * (10**1000)
```

**Status**: ✅ BLOCKED - Sandbox operation limits prevent excessive computation

**Test:** `hathor_tests/sandbox/test_sandbox_dangerous.py::DangerousSandboxTestCase::test_d1_2_large_loop_10m_iterations`

---

### Attack D1.3: Inefficient Algorithms

**Code:**
```python
# Repeated string concatenation (O(n²) memory copies)
result = ""
for i in range(10**6):
    result = result + "x"

# Nested loops with large iterations
for i in range(10**6):
    for j in range(10**6):
        pass  # 10^12 iterations
```

**Status**: ✅ BLOCKED - Sandbox operation limits prevent excessive computation

**Test:** `hathor_tests/sandbox/test_sandbox_dangerous.py::DangerousSandboxTestCase::test_d1_3_nested_loops_100m_iterations`

---

### Subcategory D2: Memory DoS

---

### Attack D2.1: Large List Allocation

**Code:**
```python
# Attempt to allocate massive list
a = [0] * (10**10)  # 10 billion elements
b = [None] * (10**12)
```

**Status**: ✅ BLOCKED - Sandbox memory/operation limits prevent large allocation

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_1_large_list_allocation`

---

### Attack D2.2: Large String Allocation

**Code:**
```python
# Attempt to allocate huge string
s = 'x' * (10**10)  # 10 GB string
t = 'abc' * (10**9)
```

**Status**: ✅ BLOCKED - Sandbox memory/operation limits prevent large allocation

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_2_large_string_allocation`

---

### Attack D2.3: Exponential String Growth

**Code:**
```python
s = 'a'
for _ in range(100):
    s = s + s  # Doubles each iteration: 2^100 bytes ≈ 10^30 bytes
```

**Status**: ✅ BLOCKED - Sandbox memory/operation limits prevent exponential growth

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_3_exponential_string_growth`

---

### Attack D2.4: Dictionary/Set Explosion

**Code:**
```python
# Large dictionary with large values
d = {i: 'x' * 1000000 for i in range(10**6)}

# Large set
s = {i for i in range(10**10)}
```

**Status**: ✅ BLOCKED - Sandbox size limits prevent excessive allocation

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_4a_dict_size_explosion`
**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_4b_dict_large_string_values`

---

### Attack D2.5: Nested Container Explosion

**Code:**
```python
# Many small lists consuming exponential memory
a = []
for _ in range(10**10):
    a = [a]  # Creates new 1-element list each iteration

# Nested list creation
nested = [[0] * 1000 for _ in range(1000)]  # 1M elements
```

**Status**: ✅ BLOCKED - Sandbox operation limits prevent excessive iterations

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_5_nested_container_explosion`

---

### Attack D2.6: Large Integer (Bigint) Allocation

**Code:**
```python
# Python integers can be arbitrarily large
x = 2 ** (10**9)  # Massive integer, gigabytes of memory

# Large factorial
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n-1)

factorial(10**6)  # Huge result
```

**Status**: ✅ BLOCKED - Sandbox operation limits prevent large computations

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d2_6_large_integer_allocation`

---

### Subcategory D3: Time DoS

---

### Attack D3.1: Infinite Loop

**Code:**
```python
while True:
    pass

# Infinite recursion (until stack overflow)
def infinite():
    infinite()
infinite()
```

**Status**: ❌ NOT BLOCKED - No execution time limits
**Impact**: Node hangs indefinitely
**Priority**: CRITICAL

---

### Attack D3.2: Effectively Infinite Loop

**Code:**
```python
# Loop with extremely large iteration count
for i in range(10**15):
    pass

# Nested effectively-infinite loops
for i in range(10**9):
    for j in range(10**9):
        pass  # 10^18 iterations
```

**Status**: ❌ NOT BLOCKED - No instruction counting
**Impact**: Node frozen for extended period
**Priority**: CRITICAL

---

### Attack D3.3: Recursion Depth Explosion

**Code:**
```python
def recurse(n):
    return recurse(n + 1)
recurse(0)

# Deep recursion
def deep(n):
    if n > 0:
        return deep(n - 1)
deep(100000)
```

**Status**: ✅ BLOCKED - Python recursion limit and sandbox operation limits prevent stack exhaustion

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d3_3_recursion_depth_explosion`

---

### Subcategory D4: Hash Collision DoS

---

### Attack D4.1: Crafted Hash Collisions

**Code:**
```python
# If PYTHONHASHSEED is fixed and known, attacker can craft
# inputs that all hash to same value, degrading dict/set to O(n²)
malicious_keys = craft_colliding_keys()  # All hash to same bucket
d = {k: v for k, v in malicious_keys}    # O(n²) insertion
```

**Status**: ⚠️ PARTIAL - Hash consistency verified within same process; block-derived seed needed for full mitigation

**Test:** `hathor_tests/sandbox/test_sandbox_attack_vectors.py::test_d4_1_hash_collision_dos`

---

## Category E: Import System Attacks

---

### Attack E1: Unauthorized Module Import

**Code:**
```python
import os
import subprocess
import socket
from sys import exit
import urllib
```

**Status**: ✅ BLOCKED - Custom `__import__` only allows whitelisted modules:
- `math` (only `ceil`, `floor`)
- `typing` (type hints only)
- `collections` (only `OrderedDict`)
- `hathor` (nano contract types)

---

### Attack E2: Import Bypass via __import__()

**Code:**
```python
__import__('os')
__import__('subprocess')
```

**Status**: ✅ BLOCKED - `__import__` overridden with custom implementation

---

## Summary

| Category | Total | Blocked (✅) | Partial (⚠️) | Unblocked (❌) | Priority |
|----------|-------|--------------|--------------|----------------|----------|
| **A. RCE** | 4 | 4 | 0 | 0 | ✅ Complete |
| **B. Code Injection** | 4 | 4 | 0 | 0 | ✅ Complete |
| **C. Non-Determinism** | 7 | 5 | 2 | 0 | ⚠️ Partial (hash seed) |
| **D1. Computational DoS** | 3 | 3 | 0 | 0 | ✅ Complete |
| **D2. Memory DoS** | 6 | 6 | 0 | 0 | ✅ Complete |
| **D3. Time DoS** | 3 | 3 | 0 | 0 | ✅ Complete |
| **D4. Hash Collision DoS** | 1 | 0 | 1 | 0 | ⚠️ Partial |
| **E. Import Attacks** | 2 | 2 | 0 | 0 | ✅ Complete |
| **TOTAL** | **30** | **27** | **3** | **0** | |

**Protection Status**: 90% fully protected (27/30), 10% partially protected (3/30), 0% unprotected (0/30)

**Key Findings**:
- RCE, code injection, and import attacks are fully protected
- Non-determinism attacks (C4, C5) now blocked by sandbox type restrictions
- Memory DoS (D2) fully blocked by sandbox size limits (dict size, string length) and operation limits
- Time DoS (D3) blocked by operation limits and recursion limits
- Remaining gaps: hash seed derivation

---

## Test Coverage

Test file: `hathor_tests/sandbox/test_sandbox_attack_vectors.py`

| Attack | Test Method | Status |
|--------|-------------|--------|
| B1 | `test_b1_rng_direct_attribute_setting` | ✅ Pass |
| C4 | `test_c4_runtime_float_via_power_operator` | ✅ Pass |
| C5 | `test_c5_runtime_float_via_pow` | ✅ Pass |
| C6 | `test_c6_hash_randomization_sets` | ✅ Pass |
| C7 | `test_c7_hash_randomization_dicts` | ✅ Pass |
| D2.1 | `test_d2_1_large_list_allocation` | ✅ Pass |
| D2.2 | `test_d2_2_large_string_allocation` | ✅ Pass |
| D2.3 | `test_d2_3_exponential_string_growth` | ✅ Pass |
| D2.4a | `test_d2_4a_dict_size_explosion` | ✅ Pass |
| D2.4b | `test_d2_4b_dict_large_string_values` | ✅ Pass |
| D2.5 | `test_d2_5_nested_container_explosion` | ✅ Pass |
| D2.6 | `test_d2_6_large_integer_allocation` | ✅ Pass |
| D3.3 | `test_d3_3_recursion_depth_explosion` | ✅ Pass |
| D4.1 | `test_d4_1_hash_collision_dos` | ✅ Pass |

### Running Tests

```bash
# Run all attack vector tests
poetry run pytest hathor_tests/sandbox/test_sandbox_attack_vectors.py -v

# Run all sandbox tests
poetry run pytest hathor_tests/sandbox/ -v
```

### Other Test Files

- `hathor_tests/sandbox/test_sandbox_dangerous.py` - D3.1, D3.2, D1.1-D1.3 (dangerous tests with timeouts)
- `hathor_tests/sandbox/test_sandbox_attacks.py` - Operation limit tests
- `hathor_tests/nanocontracts/on_chain_blueprints/test_script_restrictions.py` - AST validation tests
