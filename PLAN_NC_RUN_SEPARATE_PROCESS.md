# Plan: Subprocess Execution for Nano Contracts with PYTHONHASHSEED

## Problem Statement

Nano contract execution needs to run in a separate process where `PYTHONHASHSEED` can be controlled for:
1. **Consensus correctness** - Different nodes must produce identical execution results
2. **Deterministic replay** - Replaying executions should produce same results for debugging

## Requirements (from user clarification)

- **Latency budget**: 10-100ms per block (moderate overhead acceptable)
- **Storage**: Share RocksDB between processes (subprocess reads, main process writes)
- **Async**: Synchronous blocking is acceptable (no need to make consensus async)

## Architecture Decision: Transparent Subprocess Proxy with Effect Streaming

### Why This Approach

The current architecture has an elegant separation:
- `NCBlockExecutor.execute_block()` - Pure generator yielding effects (no side effects)
- `NCConsensusBlockExecutor._apply_effect()` - Applies side effects (commits, metadata, logging)

**Solution**: Add a transparent subprocess layer that:
1. Runs `NCBlockExecutor` in a subprocess with `PYTHONHASHSEED=0`
2. Streams serialized effects back to the main process
3. Main process applies effects via existing `NCConsensusBlockExecutor._apply_effect()`

### Data Flow

```
Main Process (PYTHONHASHSEED=random):
  NCConsensusBlockExecutor.execute_block_and_apply()
    │
    └─> NCSubprocessBlockExecutor.execute_block()
          │
          └─> Send BlockExecutionRequest to worker
                │
                ↓ [IPC via Queue]

Subprocess (PYTHONHASHSEED=0):
  NCSubprocessWorker.run()
    │
    └─> NCBlockExecutor.execute_block()
          │
          └─> Runner.execute_from_tx()  ← Deterministic dict hashing here
                │
                └─> Yield effects
                      │
                      ↓ [Serialize + IPC via Queue]

Main Process:
  NCSubprocessBlockExecutor receives effects
    │
    └─> Deserialize + hydrate (load full objects from hashes)
          │
          └─> NCConsensusBlockExecutor._apply_effect()
                │
                └─> runner.commit() → RocksDB writes
```

### Why Share RocksDB

- PatriciaTrie nodes are **immutable** and **content-addressed**
- Subprocess only **reads** existing data and computes new roots
- Main process **writes** after receiving effects
- No locking needed - reads are safe concurrent with writes to different nodes

## Implementation Plan

### Phase 1: Core Subprocess Infrastructure

**New Files:**

1. **`hathor/nanocontracts/execution/subprocess_worker.py`**
   - `NCSubprocessWorker` - runs in subprocess with PYTHONHASHSEED set
   - `BlockExecutionRequest` - minimal data to send (block_hash, parent_root_id, skipped tx hashes)
   - Worker loop: receive request → execute → stream serialized effects

2. **`hathor/nanocontracts/execution/subprocess_pool.py`**
   - `NCSubprocessPool` - manages worker lifecycle
   - Spawns workers with `PYTHONHASHSEED` in environment
   - Handles timeouts (30s default), crash recovery (respawn worker)
   - Initial pool size: 1 worker

3. **`hathor/nanocontracts/execution/effect_serialization.py`**
   - `SerializedRunner` - minimal runner state for IPC:
     - `call_info_json` - for logging/debugging (~10KB)
     - `storage_root_ids` - dict of contract_id → root (for commit verification)
     - `updated_tokens_totals`, `paid_actions_fees` - for validation
   - `serialize_effect()` / `deserialize_effect()` - using msgpack
   - Effects contain hashes only, not full objects (~100KB per block)

### Phase 2: Drop-in Replacement Executor

4. **`hathor/nanocontracts/execution/subprocess_block_executor.py`**
   - `NCSubprocessBlockExecutor` - same interface as `NCBlockExecutor`
   - `execute_block()` builds request, sends to pool, yields hydrated effects
   - "Hydration" = load full Block/Transaction objects from hashes using tx_storage

**Modified Files:**

5. **`hathor/nanocontracts/execution/consensus_block_executor.py`**
   - Accept either `NCBlockExecutor` or `NCSubprocessBlockExecutor` in constructor
   - Add `_reconstruct_runner()` method - creates lightweight Runner from `SerializedRunner`
   - Modify `_apply_effect()` to handle `SerializedRunner` (reconstruct before commit)

### Phase 3: Consensus Integration

6. **`hathor/consensus/consensus.py`**
   - Add constructor parameters:
     - `enable_subprocess_execution: bool = False`
     - `subprocess_pool_size: int = 1`
     - `subprocess_pythonhashseed: int = 0`
     - `subprocess_timeout: float = 30.0`
   - Conditionally create `NCSubprocessPool` and `NCSubprocessBlockExecutor`
   - Add `shutdown()` method for graceful pool termination

7. **Configuration (settings or initialization code)**
   - Add settings: `NC_ENABLE_SUBPROCESS_EXECUTION`, `NC_SUBPROCESS_POOL_SIZE`, etc.

## Key Implementation Details

### Serialization (~100KB per block)

**Input (Main → Subprocess):**
```python
BlockExecutionRequest:
  block_hash: bytes              # 32 bytes
  parent_root_id: bytes          # 32 bytes
  should_skip_tx_hashes: set     # ~3KB (voided transactions)
```

**Output (Subprocess → Main, per successful tx):**
```python
SerializedNCTxExecutionSuccess:
  tx_hash: bytes                 # 32 bytes
  runner:
    call_info_json: str          # ~10KB
    storage_root_ids: dict       # ~160 bytes
    token_counters: dict         # ~100 bytes
```

### Runner Reconstruction

The subprocess executes contracts and produces storage root IDs. The main process:
1. Creates empty Runner via `runner_factory.create()`
2. Loads contract storages with roots from `SerializedRunner.storage_root_ids`
3. Restores `_last_call_info` from JSON for logging/metadata extraction
4. Calls `runner.commit()` which writes to RocksDB

### Error Handling

- **Timeout**: Kill worker after 30s, respawn, fail block or retry
- **Worker crash**: Detect via `process.is_alive()`, respawn, log
- **Serialization error**: Log, treat as execution failure

### PYTHONHASHSEED Control

```python
# In subprocess_pool.py
def _spawn_worker(self):
    os.environ['PYTHONHASHSEED'] = str(self._pythonhashseed)
    process = Process(target=worker_entry_point, args=(...))
    process.start()
    return process
```

## Files to Create

| File | Purpose |
|------|---------|
| `hathor/nanocontracts/execution/subprocess_worker.py` | Worker process implementation |
| `hathor/nanocontracts/execution/subprocess_pool.py` | Pool manager |
| `hathor/nanocontracts/execution/subprocess_block_executor.py` | Proxy executor |
| `hathor/nanocontracts/execution/effect_serialization.py` | IPC serialization |

## Files to Modify

| File | Changes |
|------|---------|
| `hathor/nanocontracts/execution/consensus_block_executor.py` | Accept either executor type, add `_reconstruct_runner()`, handle `SerializedRunner` |
| `hathor/consensus/consensus.py` | Add subprocess config params, conditionally create pool, add `shutdown()` |

## Testing Strategy

1. **Unit tests**: Each new module in isolation
2. **Integration tests**: Execute blocks through subprocess, compare with in-process
3. **Determinism tests**: Same block with different PYTHONHASHSEED values → identical results
4. **Performance tests**: Measure latency (target: 10-100ms per block)

## Verification

After implementation:
1. Run existing NC tests with subprocess enabled - must pass
2. Run determinism test: execute same block 100x with PYTHONHASHSEED=0 → identical roots
3. Measure latency overhead: should be <50ms for typical blocks (10 transactions)

## Performance Estimates

- **Typical block (10 txs)**: ~103KB IPC, ~2ms serialization, ~2ms queue overhead = **~5ms total overhead**
- **Large block (100 txs)**: ~1MB IPC, ~10ms serialization, ~5ms queue overhead = **~15ms total overhead**
- **Worker memory**: ~500MB RSS per worker

Both well within the 10-100ms latency budget.
