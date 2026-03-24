---
description: "Investigate the storage layer, RocksDB backend, indexes, metadata, and how data is persisted and queried"
---

# Storage Layer & Indexes

When the user asks about storage, indexes, or data persistence, follow these steps:

## Step 1: Read the storage layer
- `hathor/transaction/storage/` — storage backends and interfaces
- Look for the base storage interface and RocksDB implementation
- Understand how vertices, metadata, and indexes are stored

## Step 2: Read the metadata
- `hathor/transaction/transaction_metadata.py` — `TransactionMetadata` holds per-vertex state
- Fields: `voided_by`, `first_block`, `accumulated_weight`, `validation`, etc.
- Metadata is stored separately from the vertex bytes

## Step 3: Read the indexes
- `hathor/indexes/` — various index implementations
- Key indexes:
  - **Address index** — maps addresses to transactions
  - **Token index** — maps token UIDs to transactions
  - **Height index** — maps block heights to blocks
  - **Timestamp index** — orders vertices by timestamp
  - **Mempool tips index** — tracks unconfirmed transaction tips
  - **NC history index** — nano contract transaction history

## Step 4: Understand index updates
- When are indexes updated? (on new vertex, on consensus change, on reorg)
- How do indexes handle reorgs and voidance changes?

## Step 5: Check performance considerations
- Caching layers, batch operations, write-ahead logs
- RocksDB column families and key design

## Step 6: Explain
Present the storage/index mechanism relevant to the user's question, with specific implementation details.
