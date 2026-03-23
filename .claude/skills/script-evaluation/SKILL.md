---
description: "Investigate the script system, opcodes, P2PKH, multisig, timelocks, and script evaluation in hathor-core"
---

# Script System & Opcodes

When the user asks about scripts, opcodes, or signature verification, follow these steps:

## Step 1: Read the script system
- `hathor/transaction/scripts/` — script module with all script types and evaluation
- Look for the script evaluator/interpreter
- Understand the stack-based execution model

## Step 2: Understand script types
Common script types:
- **P2PKH** (Pay-to-Public-Key-Hash) — standard single-signature
- **Multisig** — requires M-of-N signatures
- **Timelock** — time-locked scripts (absolute and relative)
- Look for script type constants and parsing logic

## Step 3: Read opcode definitions
- Find the opcode enum/constants (OP_DUP, OP_HASH160, OP_CHECKSIG, etc.)
- Understand each opcode's stack effect
- Check for hathor-specific opcodes vs. standard Bitcoin-like opcodes

## Step 4: Understand script evaluation
- How input scripts (scriptSig) and output scripts (scriptPubKey) are combined and evaluated
- The evaluation stack and its operations
- Error handling during evaluation

## Step 5: Check signature verification
- How transaction signatures are created and verified
- Hash types and what data is signed
- `hathor/transaction/exceptions.py` — `ScriptError` hierarchy for script failures

## Step 6: Explain
Present the script mechanism, opcode behavior, or evaluation flow relevant to the user's question.
