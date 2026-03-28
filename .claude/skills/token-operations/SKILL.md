---
description: "Investigate token creation, mint/melt authority, token UID generation, FeeHeader, and fee token mechanics"
---

# Token Creation, Authority & Fee Tokens

When the user asks about token operations, follow these steps:

## Step 1: Read token creation
Tokens can be created in two ways:
1. **Via `TokenCreationTransaction`** — `hathor/transaction/token_creation_tx.py`
2. **Via nano contracts** — blueprints can create tokens on-chain

There are two types of tokens:
- **Deposit-based tokens** — require an HTR deposit to create
- **Fee-based tokens** — use the FeeHeader mechanism

For transaction-based creation:
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
