---
description: "Investigate DAG architecture, parent selection, weight/difficulty calculation, DAA algorithm, and graph traversal"
---

# DAG Architecture & Weight

When the user asks about the DAG structure, weight, difficulty, or parent selection, follow these steps:

## Step 1: Understand the DAG model
- Hathor uses a DAG (Directed Acyclic Graph) where both blocks and transactions are vertices
- Each vertex references parent vertices (blocks reference both block parents and transaction parents, transactions reference tx parents)
- Read `hathor/transaction/base_transaction.py` for the parent fields

## Step 2: Read the DAA (Difficulty Adjustment Algorithm)
- `hathor/daa.py` — DAA calculates mining difficulty
- Understand how weight/difficulty is adjusted based on block timestamps
- Check the target time between blocks and adjustment window

## Step 3: Understand weight
- Each vertex has a `weight` field representing the computational work
- Blocks have higher minimum weight than transactions
- Accumulated weight is used for consensus (best chain selection)

## Step 4: Check parent selection
- How are parents selected for new transactions and blocks?
- Transactions select tips from the mempool
- Blocks select the best block as parent
- Look for parent selection logic in vertex creation code

## Step 5: Check graph traversal utilities
- Look for BFS/DFS traversal utilities
- How are ancestors and descendants found?
- `hathor/consensus/` uses graph traversal extensively

## Step 6: Explain
Present the DAG mechanism or calculation relevant to the user's question with specific code references.
