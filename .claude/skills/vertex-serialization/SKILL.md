---
description: "Investigate vertex serialization/deserialization, binary format, struct layout, and vertex parsing in hathor-core"
---

# Vertex Serialization & Deserialization

When the user asks about how vertices (transactions, blocks) are serialized or deserialized, follow these steps:

## Step 1: Identify the vertex type
Determine which vertex type the user is asking about (Transaction, Block, TokenCreationTransaction, MergeMinedBlock, etc.). If unclear, start with the base transaction.

## Step 2: Read the parser and serialization code
Read these key files to understand the serialization pipeline:
- `hathor/transaction/vertex_parser/` — vertex parser module, handles deserialization from bytes
- `hathor/transaction/base_transaction.py` — `BaseTransaction` class with `get_struct()`, `get_fields_from_struct()`, and serialization methods
- `hathorlib/hathorlib/serialization/` — low-level serialization helpers (if present)
- Check for `serialize()` and `deserialize()` methods on the specific vertex type

## Step 3: Understand the binary format
The binary format generally follows this structure:
1. Version field (2 bytes) — identifies tx type via `TxVersion` enum
2. Token-related fields (for token-aware transactions)
3. Inputs array (count + serialized inputs)
4. Outputs array (count + serialized outputs)
5. Headers (nano header, fee header, etc. depending on version)
6. Graph fields (weight, timestamp, parents, nonce)
7. Metadata is stored separately, not in the serialized bytes

## Step 4: Check for version-specific serialization
Different `TxVersion` values have different serialization formats. Check:
- `hathor/transaction/transaction.py` — regular transactions
- `hathor/transaction/block.py` — blocks
- `hathor/transaction/token_creation_tx.py` — token creation
- `hathor/transaction/merge_mined_block.py` — merge-mined blocks
- `hathor/transaction/poa/poa_block.py` — PoA blocks

## Step 5: Explain findings
Present the serialization format with field offsets/sizes where relevant. If the user is debugging a parsing issue, help them identify which bytes correspond to which fields.
