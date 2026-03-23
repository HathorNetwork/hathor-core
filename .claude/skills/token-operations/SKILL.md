---
description: "Investigate token creation, mint/melt authority, token UID generation, FeeHeader, and fee token mechanics"
---

# Token Creation, Authority & Fee Tokens

When the user asks about token operations, follow these steps:

## Step 1: Read token creation
- `hathor/transaction/token_creation_tx.py` — `TokenCreationTransaction` creates new tokens
- Token UID is derived from the transaction hash
- Initial mint and melt authority outputs are created

## Step 2: Understand authority outputs
- Authority outputs control who can mint (create new) or melt (destroy) tokens
- Look for `TOKEN_MINT_MASK` and `TOKEN_MELT_MASK` constants
- Authority can be delegated by spending authority outputs

## Step 3: Read verification
- `hathor/verification/token_creation_transaction_verifier.py` — verifies token creation rules
- Check token name/symbol validation rules
- Check deposit requirements for token creation

## Step 4: Understand FeeHeader
- `hathor/transaction/headers/fee_header.py` — `FeeHeader` for fee-based tokens
- How fees are calculated and validated
- Integration with nano contracts (`get_fee_header().total_fee_amount()`)

## Step 5: Check token balance verification
- How input/output token balances are verified
- How token UIDs are tracked in inputs and outputs
- Multi-token transactions

## Step 6: Explain
Present the token operation mechanics relevant to the user's question, with specific code references.
