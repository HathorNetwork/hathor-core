---
description: "Investigate nano contract architecture, blueprints, runner execution, storage layer, actions, and inter-contract calls"
---

# Nano Contract Architecture

When the user asks about nano contracts, blueprints, runner, storage, or actions, follow these steps:

## Step 1: Understand the blueprint system
- `hathor/nanocontracts/` — main nano contracts package
- Blueprints are contract templates that define methods, fields, and behavior
- Look for blueprint base class and how blueprints are registered

## Step 2: Read the runner
- `hathor/nanocontracts/runner/runner.py` — `Runner` executes contract methods
- Understand the execution model: method dispatch, argument parsing, context injection
- Check how the runner manages contract state during execution

## Step 3: Read the execution layer
- `hathor/nanocontracts/execution/` — block-level execution orchestration
- `hathor/nanocontracts/execution/block_executor.py` — executes NC txs within a block
- Understand ordering, dependency resolution, and rollback on failure

## Step 4: Understand storage
- `hathor/nanocontracts/storage/` — contract storage layer
- How contract fields/state are persisted and retrieved
- Storage key formats, serialization, and caching

## Step 5: Understand actions
Actions represent token movements in NC transactions:
- **Deposit** — tokens flow TO the contract (appears on output side)
- **Withdrawal** — tokens flow FROM the contract (appears on input side)
- **Grant/Acquire** — authority token operations
- Check `hathor/transaction/headers/nano_header.py` for the NanoHeader structure

## Step 6: Check inter-contract calls
- If the user asks about contracts calling other contracts, look for call/invoke mechanisms in the runner
- Check for context propagation and reentrancy protections

## Step 7: Explain
Present the architecture, execution flow, or specific mechanism relevant to the user's question.
