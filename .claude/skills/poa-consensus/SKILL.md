---
description: "Investigate Proof of Authority consensus, PoA block production, signer rotation, and PoA-specific verification"
---

# Proof of Authority

When the user asks about PoA consensus, follow these steps:

## Step 1: Read the PoA transaction types
- `hathor/transaction/poa/` — PoA block and related transaction types
- `PoaBlock` structure, signer field, signature format

## Step 2: Read the PoA consensus
- `hathor/consensus/poa/` — PoA-specific consensus rules
- How PoA differs from PoW consensus
- Block validity rules under PoA

## Step 3: Read the PoA verifier
- `hathor/verification/poa_block_verifier.py` — PoA block verification
- Signer authorization checks
- Signature verification
- Timing rules for block production

## Step 4: Understand signer rotation
- How block producers are selected/rotated
- Signer set management (adding/removing signers)
- What happens when a signer misses their slot

## Step 5: Check PoA configuration
- How PoA is enabled (feature activation, network settings)
- PoA-specific settings and parameters
- Differences between PoA networks and PoW networks

## Step 6: Explain
Present the PoA mechanism relevant to the user's question with specific code references.
