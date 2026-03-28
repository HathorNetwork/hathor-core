---
description: Generate test boilerplate for a source module
---

Generate a test file for the given source module: $ARGUMENTS

Steps:
1. Read the source module to understand its classes and methods
2. Determine the correct test base class:
   - General code → `TestCase` from `hathor_tests.unittest`
   - DAG/consensus → `SimulatorTestCase`
   - Nano contracts → `BlueprintTestCase`
   - API resources → `_ResourceTest`
3. Create the test file at the mirror path in `hathor_tests/` (e.g., `hathor/verification/foo.py` → `hathor_tests/verification/test_foo.py`)
4. Include:
   - Apache 2.0 license header
   - `from __future__ import annotations`
   - Appropriate base class import
   - Test class with `setUp` using `self.get_builder()` + `self.create_peer_from_builder()` if needed
   - Stub test methods for each public method/class in the source
   - Use `self.rng` for randomness, `self.clock` for time
   - `async def` + `await` for async operations
5. **Creating vertices (blocks and transactions)**: Prefer `DAGBuilder` over manual vertex construction. DAGBuilder provides a declarative, deterministic way to build DAG structures. Search for existing DAGBuilder usage in `hathor_tests/dag_builder/test_dag_builder.py` for examples.
6. **Determinism is critical**: All test behavior must be fully reproducible. Never use non-deterministic patterns (random without seed, real clocks, system state). Use `self.rng` and `self.clock`. Flaky tests break CI and erode trust — when in doubt, choose the more deterministic approach.
