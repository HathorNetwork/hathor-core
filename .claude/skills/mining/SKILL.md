---
description: "Investigate mining, stratum protocol, block templates, merge mining, PoW verification, and nonce handling"
---

# Mining, Stratum & Block Templates

When the user asks about mining, stratum, or block templates, follow these steps:

## Step 1: Read the mining module
- `hathor/mining/` — mining-related code
- Understand block template generation
- Check for CPU mining implementation (if any)

## Step 2: Read the stratum protocol
- `hathor/stratum/` — stratum protocol implementation for external miners
- Understand the stratum message flow (subscribe, authorize, notify, submit)
- Check job creation and solution validation

## Step 3: Read merge mining
- `hathor/merged_mining/` — merge mining (AuxPow) support
- How Hathor blocks can be merge-mined with Bitcoin or other chains
- `hathor/transaction/merge_mined_block.py` — merge-mined block structure

## Step 4: Understand PoW verification
- How proof-of-work is verified (hash below target)
- Nonce field and how it's used
- Weight/difficulty relationship to the target

## Step 5: Check block construction
- How transactions are selected from the mempool for inclusion
- Block size limits, fee prioritization
- How the coinbase/reward is constructed

## Step 6: Explain
Present the mining mechanism relevant to the user's question with specific code references.
