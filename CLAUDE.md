# Hathor Core

A full-node implementation for the Hathor Network — a DAG-based cryptocurrency with nano contracts.

## Environment

Always run Python commands through `poetry run` (or the equivalent `uv` command). Verify a virtual environment is active before running tests or linting. Example: `poetry run pytest ...`, `poetry run make check`.

## Build & Test Commands

```bash
# Linting & type checking
make check          # runs: flake8, isort-check, mypy, yamllint, custom checks
make fmt            # auto-format with isort
make mypy           # type check hathor + hathor_tests

# Tests
make tests          # full test suite (cli, lib, genesis, custom, ci)
make tests-quick    # fast subset, skips slow tests (--maxfail=1 -m "not slow")
make tests-nano     # nano contracts tests with coverage

# Single test
pytest hathor_tests/path/to/test_file.py -n0            # single file, no parallelism
pytest hathor_tests/path/to/test_file.py::TestClass -n0  # single class
pytest hathor_tests/path/to/test_file.py::TestClass::test_method -n0  # single test
```

## Rust Crypto Library (hathor-ct-crypto/)

```bash
cd hathor-ct-crypto
cargo test                        # run Rust tests
cargo fmt && cargo clippy         # format + lint
maturin develop --features python # build Python bindings (needs active venv)
```

## Architecture Overview

### DAG Structure
The ledger is a DAG where vertices are either **blocks** (consensus/weight) or **transactions** (value transfer). Each vertex references 2+ parent vertices. Blocks form a blockchain backbone; transactions hang between blocks.

### TxVersion Dispatch
Every vertex has a `TxVersion` (IntEnum): REGULAR_BLOCK(0), REGULAR_TRANSACTION(1), TOKEN_CREATION_TRANSACTION(2), MERGE_MINED_BLOCK(3), POA_BLOCK(5), ON_CHAIN_BLUEPRINT(6). The version drives `match/case` dispatch throughout verification, serialization, and consensus.

### Verification Pipeline
`VerificationService` dispatches to `VertexVerifiers` (NamedTuple of per-type verifiers):
- **verify_basic**: structural checks (timestamps, weights, scripts) — no storage access
- **verify** (full): semantic checks requiring storage (inputs exist, balances, consensus)
- Verifiers **raise exceptions** on failure (never return bool)
- `ValidationState`: INITIAL(0) → BASIC(1) → FULL(3), or INVALID(-1)

### Nano Contracts
Blueprints define on-chain logic with `@public`, `@view` decorators. The `Runner` executes methods; `BlockExecutor` processes all nano actions in a block. Actions: DEPOSIT (tokens → contract, output side), WITHDRAWAL (tokens ← contract, input side).

### Feature Activation
State machine for network upgrades: DEFINED → STARTED → MUST_SIGNAL → LOCKED_IN → ACTIVE. Controlled by `Feature` enum + per-network criteria. Guard code with `feature_service.is_feature_active(Feature.X, block)`.

## Project Layout

```
hathor/                  # Main package
  consensus/             # DAG consensus algorithm
  crypto/                # Crypto utilities + confidential tx
  event/                 # Event framework
  feature_activation/    # Feature flags state machine
  nanocontracts/         # Nano contracts (blueprints, runner, executor)
  p2p/                   # Peer-to-peer networking
  transaction/           # Vertex types, storage, serialization
  verification/          # Verification pipeline
  wallet/                # Wallet + API resources
hathor_cli/              # CLI entry points
hathor_tests/            # Tests (mirrors hathor/ structure)
hathorlib/               # Lightweight shared library
hathor-ct-crypto/        # Rust confidential transaction crypto (PyO3)
```

## Key Conventions

See `.claude/rules/` for detailed, scoped rules on Python style, testing, API endpoints, pydantic, nano contracts, and verification. Key highlights:

- **License**: Apache 2.0, Hathor Labs header on all new Python files (template below).
- **Settings**: Prefer injecting `HathorSettings` as a dependency; avoid `get_global_settings()` singleton.

## License

```python
#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
```
