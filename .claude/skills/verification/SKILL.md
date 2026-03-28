---
description: "Investigate the vertex verification pipeline, validation states, VerificationService, and why a transaction failed verification"
---

# Vertex Verification Pipeline

When the user asks about vertex verification, validation errors, or why a transaction failed, follow these steps:

## Step 1: Understand the verification architecture
Read these files to understand the verification system:
- `hathor/verification/verification_service.py` — `VerificationService` dispatches verification by vertex type
- `hathor/verification/vertex_verifier.py` — base `VertexVerifier` with common checks
- `hathor/verification/vertex_verifiers.py` — `VertexVerifiers` dataclass holding all type-specific verifiers
- `hathor/transaction/validation_state.py` — validation state machine (INITIAL → BASIC → FULL)

## Step 2: Identify the validation stage
Verification happens in two stages:
- **Basic verification** (`verify_basic`): structural checks — weight, parents, timestamps, POW, outputs, scripts syntax
- **Full verification** (`verify_full` / `verify`): semantic checks — input spending, double-spend detection, token balances, signatures

## Step 3: Find type-specific verifiers
Each vertex type has its own verifier class:
- `hathor/verification/transaction_verifier.py` — transactions
- `hathor/verification/block_verifier.py` — blocks
- `hathor/verification/merge_mined_block_verifier.py` — merge-mined blocks
- `hathor/verification/token_creation_transaction_verifier.py` — token creation
- `hathor/verification/poa_block_verifier.py` — PoA blocks

## Step 4: Check error types
Look at the exception hierarchy for verification errors:
- `hathor/transaction/exceptions.py` — all `TxValidationError` subclasses
- Each validation check raises a specific exception (e.g., `InvalidInputData`, `InsufficientFunds`, `DuplicatedParents`)

## Step 5: Trace the specific failure
If the user has a specific error, search for the exception class in the verifier code to find exactly which check failed and what conditions trigger it.

## Step 6: Explain
Present the verification flow relevant to the user's question, including the specific check, the condition that triggers it, and any relevant thresholds or constants.
