---
globs: ["hathor_tests/**/*.py"]
---

# Testing Conventions

## Base Classes
- `TestCase` — general tests (from `hathor_tests.unittest`)
- `SimulatorTestCase` — DAG/consensus simulation tests
- `BlueprintTestCase` — nano contract blueprint tests
- `_ResourceTest` — API resource tests (uses StubSite for HTTP)

## DAGBuilder (preferred for creating vertices)

Use `DAGBuilder` for creating blocks and transactions in tests. It provides a declarative, deterministic way to build DAG structures:

```python
def test_something(self):
    manager = ...  # from create_peer_from_builder
    dag_builder = manager.dag_builder  # or construct from test helper
    # Use DAGBuilder to create vertices — see hathor_tests/ for examples
```

Prefer DAGBuilder over manual vertex construction to avoid flaky tests and ensure determinism.

## TestBuilder Pattern

```python
def test_something(self):
    builder = self.get_builder()
    # configure builder...
    manager = self.create_peer_from_builder(builder)
```

- `self.get_builder(settings=None)` returns a `TestBuilder` pre-configured with `self.rng` and `self.clock`
- Chain builder methods: `builder.set_settings(s)`, `builder.enable_sync_v2()`, etc.
- `self.create_peer_from_builder(builder)` calls `builder.build()` and returns the `HathorManager`

## Async Tests
- Use `@inlineCallbacks` decorator with `yield` (Twisted-style), not `async/await`
- For HTTP: use `StubSite` to wrap a resource, then `yield web.get(...)` or `yield web.post(...)`

## Determinism
- Use `self.rng` (seeded Random instance) for all randomness — never `random.random()`
- Use `self.clock` as the reactor for time-dependent tests
- Tests must be deterministic and reproducible

## Naming & Structure
- Files: `test_*.py` inside `hathor_tests/`
- Classes: `Test*` prefix
- Directory structure mirrors `hathor/` (e.g., `hathor/verification/` → `hathor_tests/verification/`)

## Running Tests
```bash
pytest hathor_tests/path/to/test_file.py -n0         # single file, no parallelism
pytest hathor_tests/path/to/test_file.py::TestClass::test_method -n0  # single test
```
