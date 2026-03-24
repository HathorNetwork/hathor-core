---
description: "Investigate the consensus algorithm, voided transactions, best chain selection, reorgs, and accumulated weight in the DAG"
---

# Consensus Algorithm

When the user asks about consensus, voided transactions, best chain, or reorgs, follow these steps:

## Step 1: Read the consensus core
- `hathor/consensus/consensus.py` — main `Consensus` class, entry point for consensus updates
- `hathor/consensus/block_consensus.py` — block consensus (best chain selection, reorgs)
- `hathor/consensus/transaction_consensus.py` — transaction consensus (conflict resolution, voidance)

## Step 2: Understand voidance
A vertex becomes "voided" when:
- It conflicts with another vertex (double-spend) and loses
- It is in a side chain (not on the best block chain)
- Its parents/inputs are voided (voidance propagates)
Check `transaction_metadata.py` for the `voided_by` field and how it's updated.

## Step 3: Understand best chain selection
The best chain is determined by accumulated weight:
- Each block accumulates the weight of itself plus all transactions that confirm it
- The chain with highest accumulated weight wins
- Reorgs happen when a competing chain surpasses the current best chain

## Step 4: Check related files
- `hathor/transaction/transaction_metadata.py` — metadata fields: `voided_by`, `first_block`, `accumulated_weight`
- `hathor/indexes/` — indexes that track consensus state

## Step 5: Explain the specific scenario
If the user is asking about a specific scenario (e.g., why a tx was voided, how a reorg works), trace through the consensus code path step by step.
