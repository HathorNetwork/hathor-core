---
globs: ["hathor/verification/**/*.py"]
---

# Verification Pipeline

## Architecture

`VerificationService` dispatches to `VertexVerifiers` (a NamedTuple grouping per-type verifiers):

```python
class VertexVerifiers(NamedTuple):
    vertex: VertexVerifier
    block: BlockVerifier
    merge_mined_block: MergeMinedBlockVerifier
    poa_block: PoaBlockVerifier
    tx: TransactionVerifier
    token_creation_tx: TokenCreationTransactionVerifier
    nano_header: NanoHeaderVerifier
    on_chain_blueprint: OnChainBlueprintVerifier
```

## Two-Phase Verification
- **verify_basic**: structural checks (timestamps, weights, scripts) — no storage needed
- **verify** (full): semantic checks requiring storage (inputs, balances, consensus)

## Key Rules
- Verifiers **raise exceptions** on failure — never return bool
- Use `match/case` on `vertex.version` with `assert type(vertex) is X` for dispatch
- Use `__slots__` on verifier classes for performance
- `ValidationState`: INITIAL(0) → BASIC(1) → FULL(3), or INVALID(-1). Also CHECKPOINT(2) and CHECKPOINT_FULL(4).

## Adding a New Verifier
1. Create verifier class in `hathor/verification/` with `__slots__`
2. Add field to `VertexVerifiers` NamedTuple
3. Add `match/case` branch in `VerificationService.verify_basic()` and `verify()`
4. Wire up in `VertexVerifiers.create_defaults()`
