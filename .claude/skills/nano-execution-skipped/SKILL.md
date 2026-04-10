---
description: "Investigate why a nano contract transaction was skipped during execution, including skip conditions and seqnum handling"
---

# Why a Nano Contract TX Was Skipped

When the user asks why a nano contract transaction was skipped, follow these steps:

## Step 1: Read the skip logic
- `hathor/nanocontracts/execution/block_executor.py` — `BlockExecutor` contains the primary skip logic
- `hathor/nanocontracts/execution/consensus_block_executor.py` — consensus-level executor may have additional skip conditions

## Step 2: Understand skip conditions
A nano contract transaction is skipped (not executed) when:
1. **Voided by a previous failure** — if an earlier NC tx in the same block or chain failed, subsequent txs for the same contract may be skipped
2. **Seqnum gap** — if the expected seqnum doesn't match (because a previous tx failed), execution is skipped but seqnum is still consumed
3. **Contract state inconsistency** — the contract's state doesn't allow execution to proceed

## Step 3: Check how skipping differs from failure
- Skipped txs are different from failed txs: they don't execute at all, but their seqnum slot is still consumed
- Look for `NCTxExecutionSkipped` or similar markers in the code
- Check what metadata is set on skipped transactions

## Step 4: Trace the execution flow
Follow the block executor's loop over NC transactions in a block:
1. For each NC tx, check if it should be executed or skipped
2. If skipped, check what state is updated (seqnum counter, metadata)
3. If the user has a specific scenario, trace through with their parameters

## Step 5: Explain
Present the skip condition that was triggered, why it was triggered, and what the downstream effects are (e.g., subsequent txs for the same contract will also be skipped).
