---
description: "Diagnose why a nano contract transaction failed execution, including NCFail exceptions, runner errors, and fuel/memory limits"
---

# Why a Nano Contract TX Failed

When the user asks why a nano contract transaction failed, follow these steps:

## Step 1: Identify the failure type
Read the exception hierarchy:
- `hathor/nanocontracts/exception.py` — all NC exception types, especially `NCFail` and its subclasses

## Step 2: Check the runner error paths
- `hathor/nanocontracts/runner/runner.py` — the `Runner` class executes contract methods; look for all places that raise `NCFail` or related exceptions
- Check method resolution, argument validation, and return value handling

## Step 3: Check the block executor
- `hathor/nanocontracts/execution/block_executor.py` — `BlockExecutor` orchestrates NC execution during block processing
- Look for error handling, rollback logic, and how failures are recorded

## Step 4: Common failure causes
Investigate these common failure paths:
1. **Seqnum validation** — NC transactions must have sequential seqnum per contract
2. **Fuel/memory limits** — resource limits that abort execution
3. **Method not found** — calling a non-existent blueprint method
4. **Invalid arguments** — wrong types or number of arguments
5. **Storage errors** — reading non-existent keys, type mismatches
6. **Action validation failures** — insufficient balance for withdrawals, invalid token operations
7. **Blueprint-level assertions** — custom `raise NCFail(...)` in blueprint code

## Step 5: Check the execution result
- Look at how execution results are stored and how the failure is surfaced (metadata, events, API responses)
- Check `hathor/nanocontracts/execution/result.py` if it exists

## Step 6: Explain the failure chain
Present the full failure path: what triggered the error, which check failed, and what the user can do to fix it.
