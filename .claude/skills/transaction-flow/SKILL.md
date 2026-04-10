---
description: "Trace the full transaction lifecycle from creation through P2P propagation, verification, consensus, mempool, and block inclusion"
---

# Transaction Lifecycle (Creation to Inclusion)

When the user asks about the end-to-end transaction flow, follow these steps:

## Step 1: Understand the high-level flow
```
Creation → Serialization → P2P Propagation → VertexHandler → Verification → Consensus → Mempool → Block Inclusion
```

## Step 2: Read the vertex handler
- `hathor/vertex_handler/vertex_handler.py` — `VertexHandler` is the central entry point for processing new vertices
- Look for `on_new_vertex()` or the main processing method
- Understand the pipeline: receive → validate → store → update consensus → notify

## Step 3: Read the manager
- `hathor/manager.py` — `HathorManager` orchestrates the node's components
- Check how it connects vertex handler, storage, consensus, and P2P

## Step 4: Trace each stage
1. **Creation**: Transaction is built with inputs, outputs, and signed
2. **Serialization**: Converted to bytes for network transmission
3. **P2P**: Sent to peers, received by their protocol handlers
4. **VertexHandler**: `on_new_vertex()` processes the incoming vertex
5. **Verification**: Basic then full verification (see verification skill)
6. **Storage**: Vertex is persisted to storage
7. **Consensus**: Consensus algorithm determines if vertex is valid/voided
8. **Mempool**: If unconfirmed, enters mempool and mempool tips index
9. **Block inclusion**: Miner includes mempool txs in new block; `first_block` metadata is set

## Step 5: Check event emission
- Events are emitted at various stages (new vertex, confirmation, etc.)
- Check the pubsub system and event storage

## Step 6: Explain
Present the relevant stage(s) of the lifecycle based on the user's specific question, with references to the actual code paths.
