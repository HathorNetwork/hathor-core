---
description: "Diagnose why a vertex was rejected from the mempool, including acceptance criteria, validation params, and rejection reasons"
---

# Why a Vertex Was Refused from Mempool

When the user asks why a transaction or vertex was rejected from the mempool, follow these steps:

## Step 1: Read the vertex handler
- `hathor/vertex_handler/vertex_handler.py` — `VertexHandler` is the main entry point for accepting vertices into the node
- Look for the `on_new_vertex` method and its validation pipeline

## Step 2: Check acceptance criteria
The vertex handler applies several checks before accepting a vertex:
1. **Already exists** — vertex is already in storage
2. **Verification failure** — basic or full verification fails (see verification skill)
3. **Timestamp validation** — vertex timestamp must be within acceptable bounds
4. **Parents validation** — parents must exist and be valid
5. **Mempool-specific limits** — max mempool size, per-address limits, rate limiting
6. **Hardened validation params** — stricter params for mempool acceptance vs. sync

## Step 3: Check P2P mempool sync
- `hathor/p2p/sync_v2/mempool.py` — mempool sync protocol, may reject vertices during sync
- Check for peer-level rejection reasons

## Step 4: Check mempool tips index
- `hathor/indexes/mempool_tips_index.py` — tracks mempool tip transactions
- May provide clues about why a transaction can't enter the mempool

## Step 5: Check hardened vs. relaxed validation
The node may use different validation parameters for:
- Mempool acceptance (stricter) — e.g., tighter timestamp bounds
- Sync acceptance (relaxed) — accepts vertices that are already confirmed
Look for `HardenedVertex` or validation parameter differences.

## Step 6: Explain
Present the specific rejection reason, the check that failed, and any relevant thresholds or configuration values.
