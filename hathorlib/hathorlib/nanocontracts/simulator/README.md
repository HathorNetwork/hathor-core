# NanoContracts Blueprint Simulator

An in-memory simulator for developing and testing Hathor NanoContract blueprints without running a full node. It provides a developer-friendly API that mirrors the on-chain execution model while giving you full control over time, blocks, tokens, and state.

## Quick Start

```python
from hathorlib.nanocontracts.simulator import NanoSimulatorBuilder

# Create a simulator
sim = NanoSimulatorBuilder().build()

# Register a blueprint from a file (mirrors the on-chain flow)
bid = sim.register_blueprint('./blueprints/my_blueprint.py')  # str or Path
alice = sim.create_address('alice')

# Deploy a contract and interact with it via a ContractProxy
contract = sim.create_contract(bid, caller=alice)
contract.do_something(caller=alice)
value = contract.get_value()
```

## NanoSimulatorBuilder

The builder configures and creates `NanoSimulator` instances with a fluent API:

```python
sim = (NanoSimulatorBuilder()
    .with_seed(b'my_test_seed')        # Deterministic RNG seed
    .with_initial_time(1700000000)     # Starting clock timestamp
    .with_auto_new_block(False)        # Manual block control
    .with_unlimited_fuel()             # Disable fuel metering
    .with_checksig(my_backend)         # Custom signature verification
    .with_settings(custom_settings)    # Custom HathorSettings
    .build())
```

| Method                      | Default                     | Description                                                                     |
|-----------------------------|-----------------------------|---------------------------------------------------------------------------------|
| `with_seed(seed)`           | `b'simulator_default_seed'` | RNG seed for deterministic ID generation                                        |
| `with_initial_time(ts)`     | Current time                | Initial simulated clock timestamp                                               |
| `with_auto_new_block(bool)` | `True`                      | Auto-advance blocks after each successful call                                  |
| `with_unlimited_fuel()`     | Off                         | Disable fuel/memory limits for rapid prototyping                                |
| `with_checksig(backend)`    | Simulated backend           | Signature verification backend (see [Checksig](#checksig-simulated-signatures)) |
| `with_settings(settings)`   | Mainnet-like                | Custom `HathorSettings`                                                         |
| `with_runtime_version(v)`   | `V2`                        | Nano runtime version                                                            |

## Addresses and Tokens

```python
# Create deterministic test addresses
alice = sim.create_address('alice')
bob = sim.create_address('bob')

# Get the output script for an address (needed by some blueprints)
oracle_script = sim.get_output_script(alice)

# Create custom tokens
from hathorlib.nanocontracts.types import NC_HTR_TOKEN_UID
my_token = sim.create_token('MyToken', 'MTK')
```

The built-in HTR token (`NC_HTR_TOKEN_UID`) is always available.

## Blueprint Registration

The preferred way to register a blueprint is to load it from a file. This mirrors the
on-chain `OnChainBlueprint` flow, uses the same `from hathor import ...` import surface
blueprints run against in production, and keeps your simulator tests honest about the
blueprint's actual source layout.

```python
bid = sim.register_blueprint('./blueprints/bet.py')
```

The file must contain a class decorated with `@export` that subclasses `Blueprint`. The
simulator resolves `from hathor import ...` imports automatically via a shim module.

For special cases (not entirely bound to the on-chain constraints) the developer can define a
blueprint class and register it into the simulator with `register_blueprint_class`:

```python
class MyBlueprint(Blueprint):
    def initialize(self, ctx: Context):
        self.value = 0

    @public
    def increase(self, ctx: Context, value: int):
        self.value += value

    @value
    def get_value(self, ctx: Context):
        return self.value

bid = sim.register_blueprint_class(MyBlueprint)
```

Both forms are idempotent: calling them again with the same file or class returns the
same `BlueprintId`.

## Contract Lifecycle

### Creating contracts

`create_contract` returns a `ContractProxy` that exposes the blueprint's public and view
methods as regular Python methods.

```python
# Basic creation
contract = sim.create_contract(bid, caller=alice)

# With constructor arguments
contract = sim.create_contract(bid, caller=alice, args=(oracle_script, token_uid, Timestamp(1000)))

# With actions (e.g. initial deposit)
contract = sim.create_contract(
    bid,
    caller=alice,
    actions=[sim.deposit(NC_HTR_TOKEN_UID, 1000)],
)
```

The proxy also exposes the underlying `TxResult` via `contract.tx_result` and the
contract's id via `contract.contract_id`.

### Calling methods via the proxy

Public methods require `caller` (and optionally `actions`) as keyword arguments and
return a `TxResult`. View methods take positional arguments and return the view's value
directly.

```python
contract.bet(alice, '1x0', caller=alice, actions=[sim.deposit(NC_HTR_TOKEN_UID, 1000)])
result = contract.has_result()
amount = contract.get_max_withdrawal(bob)
```

### Retrieving an existing contract

```python
contract = sim.get_contract(contract_id)
```

### Low-level API

For generic tooling, dynamic calls, or tests that want to pin down the low-level
surface, the simulator exposes string-based primitives:

```python
# Raw creation returns TxResult instead of a proxy
tx_result = sim.create_contract_raw(
    bid,
    caller=alice,
    args=(...),
    actions=[sim.deposit(NC_HTR_TOKEN_UID, 500)],
)

# Public method calls by name
tx_result = sim.call_public(
    contract_id, 'method_name',
    caller=alice,
    args=(arg1, arg2),
    actions=[sim.deposit(NC_HTR_TOKEN_UID, 500)],
)

# View method calls by name
value = sim.call_view(contract_id, 'get_something', arg1, arg2)
```

Prefer the proxy-based API above for day-to-day blueprint testing.

## Actions (Deposits, Withdrawals, Authority)

Actions represent token operations attached to method calls:

```python
# Deposit tokens into a contract
sim.deposit(token_uid, amount)

# Withdraw tokens from a contract
sim.withdrawal(token_uid, amount)

# Grant token authority to a contract
sim.grant_authority(token_uid, mint=True)
sim.grant_authority(token_uid, melt=True)

# Acquire token authority from a contract
sim.acquire_authority(token_uid, mint=True, melt=True)
```

Actions are passed as a list to `actions=` in `call_public`, `create_contract`, or proxy public methods.

## TxResult

Every successful `call_public` or `create_contract_raw` returns a `TxResult`:

```python
result = sim.call_public(cid, 'emit_one', caller=alice)

result.tx_hash        # Transaction hash (VertexId)
result.block_hash     # Block hash this tx belongs to (VertexId)
result.contract_id    # Contract ID
result.events         # List of NCEvent emitted during execution
result.exec_entry     # Execution log entry (NCExecEntry)
```

Failed calls raise `NCFail` (or a subclass). Changes are **not** committed on failure.

## Time Control

The simulator has a virtual clock that you control:

```python
sim = NanoSimulatorBuilder().with_initial_time(100).build()

# Advance time by a number of seconds
sim.advance_time(1000)

# Set time to an absolute timestamp
sim.set_time(5000)

# Read the current time
print(sim.clock_time)
```

Time is used by the block's `timestamp` field, which blueprints access via `ctx.block.timestamp`.

## Block Management

By default (`auto_new_block=True`), each successful call creates its own block. For fine-grained control:

```python
# Option 1: Disable at build time
sim = NanoSimulatorBuilder().with_auto_new_block(False).build()

# Option 2: Toggle at runtime
sim.auto_new_block = False

# Multiple calls in the same block
sim.call_public(cid, 'increment', caller=alice)
sim.call_public(cid, 'increment', caller=alice)
sim.call_public(cid, 'increment', caller=alice)

# Commit the block manually
block_result = sim.new_block()
print(block_result.block_height)
print(len(block_result.tx_results))  # 3
```

`BlockResult` contains:
- `block_hash` -- the hash of the committed block
- `block_height` -- the block height
- `tx_results` -- list of `TxResult` for all transactions in the block

## Events and Logs

Blueprints can emit events via `self.syscall.emit_event(data)`. The simulator captures these along with execution logs.

```python
# Events from a specific transaction
events = sim.get_events(tx_hash=tx_result.tx_hash)

# Events from a specific block
events = sim.get_events(block_hash=block_result.block_hash)

# All events across the simulation
all_events = sim.get_events()

# Execution logs (same filtering options)
logs = sim.get_logs(tx_hash=tx_result.tx_hash)
all_logs = sim.get_logs()
```

Each event has a `.data` attribute (bytes). Execution logs (`NCExecEntry`) include an `error_traceback` field that is `None` on success and contains the traceback string on failure.

## Checksig (Simulated Signatures)

The simulator provides a simulated checksig backend so you can test `SignedData` without real cryptography:

```python
from hathorlib.nanocontracts.simulator import CHECKSIG_VALID, CHECKSIG_INVALID
from hathorlib.nanocontracts.types import SignedData

# Create signed data that will pass checksig
valid_data = SignedData[str]('my_value', CHECKSIG_VALID)

# Create signed data that will fail checksig
invalid_data = SignedData[str]('my_value', CHECKSIG_INVALID)
```

Use `CHECKSIG_VALID` / `CHECKSIG_INVALID` as the `script_input` parameter when constructing `SignedData`. The simulated backend recognizes these sentinel values and returns `True` / `False` accordingly.

To disable checksig or provide a custom backend:

```python
# Disable (checksig raises NotImplementedError)
sim = NanoSimulatorBuilder().with_checksig(None).build()

# Custom backend
def my_backend(sighash_all_data: bytes, script_input: bytes, script: bytes) -> bool:
    return verify_signature(script_input, script)

sim = NanoSimulatorBuilder().with_checksig(my_backend).build()
```

## Snapshot and Restore

Save and restore the full simulation state for branching test scenarios:

```python
sim.call_public(cid, 'increment', caller=alice)
sim.call_public(cid, 'increment', caller=alice)
assert sim.call_view(cid, 'get_count') == 2

# Take a snapshot
snap = sim.snapshot()

# Continue modifying state
sim.call_public(cid, 'increment', caller=alice)
sim.call_public(cid, 'increment', caller=alice)
assert sim.call_view(cid, 'get_count') == 4

# Restore to the snapshot
sim.restore(snap)
assert sim.call_view(cid, 'get_count') == 2
```

Snapshots capture contract storage, token registry, clock time, block height, ID counters, and events/logs. You can take multiple snapshots and restore to any of them.

## State Inspection

```python
# Check contract balance
balance = sim.get_balance(contract_id, token_uid)
print(balance.available)

# Check if a contract exists
sim.has_contract(contract_id)

# Current block height
sim.block_height

# Current clock time
sim.clock_time
```

## Error Handling

Failed calls raise `NCFail` (or subclasses). State is **not** modified on failure:

```python
from hathorlib.nanocontracts import NCFail

try:
    contract.bet(bob, '1x1', caller=bob, actions=[sim.deposit(NC_HTR_TOKEN_UID, 5000)])
except NCFail as err:
    print(f"Call failed: {err}")
    # Contract state is unchanged
```

Failed calls still record execution logs (with traceback) for debugging, queryable via `sim.get_logs()`.

## Writing Blueprints for the Simulator

Blueprint files use `from hathor import ...` for all imports. The simulator provides a shim that maps these to the correct `hathorlib` types.

```python
from hathor import (
    Address, Blueprint, Context, NCFail, SignedData,
    Timestamp, TokenUid, TxOutputScript,
    export, public, view,
)

@export
class MyBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public(allow_deposit=True)
    def deposit(self, ctx: Context) -> None:
        action = ctx.get_single_action(self.token_uid)
        self.value += action.amount

    @view
    def get_value(self) -> int:
        return self.value
```

Key decorators:
- `@export` -- marks the class as the blueprint to be loaded by `register_blueprint()`
- `@public` -- marks a method as callable via transactions
- `@public(allow_deposit=True)` / `@public(allow_withdrawal=True)` -- allows deposit/withdrawal actions
- `@view` -- marks a read-only method (no `ctx` parameter, no state changes)

## Using with pytest

```python
import pytest
from hathorlib.nanocontracts.types import NC_HTR_TOKEN_UID
from hathorlib.nanocontracts.simulator import NanoSimulatorBuilder

@pytest.fixture
def sim():
    return NanoSimulatorBuilder().with_initial_time(100).build()

@pytest.fixture
def alice(sim):
    return sim.create_address('alice')

@pytest.fixture
def contract(sim, alice):
    bid = sim.register_blueprint('./blueprints/my_blueprint.py')
    return sim.create_contract(bid, caller=alice)

class TestMyBlueprint:
    def test_initial_state(self, contract):
        assert contract.get_value() == 0

    def test_deposit(self, sim, contract, alice):
        contract.deposit(caller=alice, actions=[sim.deposit(NC_HTR_TOKEN_UID, 100)])
        assert contract.get_value() == 100
```
