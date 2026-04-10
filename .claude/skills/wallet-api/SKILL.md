---
description: "Investigate wallet operations, REST API resources, transaction building, balance queries, and address management"
---

# Wallet & API Resources

> **WARNING**: The wallet implementation in `hathor/wallet/` is NOT safe for production use. It should ONLY be used for testing purposes. Do not recommend it for production deployments.

When the user asks about wallet operations or the REST API, follow these steps:

## Step 1: Read the wallet module
- `hathor/wallet/` — wallet implementation (**test-only, not production-safe**)
- Understand address generation, UTXO tracking, and balance calculation
- Check key management and HD wallet support

## Step 2: Read the API resources
- `hathor/transaction/resources/` — REST API resource handlers
- Look for transaction-related endpoints (send, decode, push)
- Check for OpenAPI/Swagger documentation

## Step 3: Check transaction building
- How transactions are built from the wallet's perspective
- Input selection (coin selection algorithm)
- Change output generation
- Fee calculation

## Step 4: Check balance and history
- How wallet balance is calculated
- Address-based transaction history
- Token balance tracking

## Step 5: Check API authentication and permissions
- API key or authentication mechanisms
- Rate limiting
- Which endpoints require authentication

## Step 6: Explain
Present the wallet operation or API endpoint relevant to the user's question with specific code references and usage examples. Always note that the wallet is for testing only.
