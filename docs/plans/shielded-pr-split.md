# PR Split Plan — Shielded Transactions (Python)

## Context

Branch `feat/ct-amount-token-privacy` is 34 commits ahead of `master` with ~16k insertions across hathor-core (Python), hathorlib (Python), the new Rust `hathor-ct-crypto` library, and supporting infra. This is too large to review in one shot.

**Goal**: split into a sequence of semantic PRs so the team can clearly distinguish refactors from behavioral changes, and so security-critical verification logic can be reviewed in isolation.

**Constraints from the team**:
- Dead code behind a feature flag is acceptable.
- The Rust crypto library ships **last**, after all Python work has landed.
- hathor-core and hathorlib changes are paired per PR (refactors together, features together).
- PR 3 (canonical header ordering) requires a chain-data scan to confirm no existing testnet/mainnet tx is invalidated; if any is, the rule must be gated behind a Feature Activation.

---

## Step 0 — Pre-flight cleanup (branch hygiene, not a PR)

Drop from the branch via interactive rebase:
- Already-merged upstream chores: `1a1c4cf3` #1643, `bdeba58b` #1642, `64f5c261` #1627, `d038dd26` #1660, `4e537aa8` #1630, `c09050e4`, `e30ed279`.
- hathorlib counterparts of the same chores:
  - `mainnet.yml` / `testnet.yml` `FAILED_FEE_TOKENS` / `FAILED_OPCODES_V2` renames.
  - `hathorlib/hathorlib/nanocontracts/rng.py` removal of `random()` (and `tests/test_rng.py`).
  - `hathorlib/hathorlib/nanocontracts/vertex_data.py` `weight: float → work: int`.
  - `hathorlib/hathorlib/utils/address.py` noqa tweak.

Local scratch files to `.gitignore` (not commit): `CLAUDE.md`, `SHIELDED-OUTPUTS-UTXO-INDEX-PLAN.md`, `_audit/`, `_audit2/`, `_audit3/`, `_designs/`.

**Side PR A** (independent of the stack — hathor-core only): twisted log formatting + typing — commits `1dfa60b4`, `3b8dbb66`, `6342e128`.

After cleanup the branch should contain only shielded-related changes plus any genuinely-new checkpoints that have not yet shipped upstream.

---

## PR 1 — chore: rename `verify_sum` → `verify_transparent_balance`

**Type**: pure mechanical rename. No behavior change.

**Why first**: the rename touches several files and would otherwise generate noise in PR 5 (the security-critical PR). Landing it independently lets reviewers approve at a glance.

**Scope (hathor-core only)**:
- `hathor/verification/transaction_verifier.py` — method rename.
- `hathor/verification/verification_service.py` — callsites.
- `hathor/transaction/resources/create_tx.py` — callsite.
- `hathor/nanocontracts/execution/block_executor.py` — callsite + helper rename `_verify_sum_after_execution` → `_verify_transparent_balance_after_execution`.
- Any existing test that calls `verify_sum` directly.

**Risk**: zero.

---

## PR 2 — refactor: `resolve_spent_output` plumbing (transparent-only behavior)

**Type**: pure refactor. Adds new API on `GenericVertex`; default behavior identical to existing direct list indexing. Migrates every callsite to the new API.

**Why**: today every callsite reads `spent_tx.outputs[txin.index]` directly. PR 5 needs each of these callsites to be shielded-aware. Doing the migration as a no-op refactor first means PR 5's diffs are minimal at each callsite — only the new behavior is added.

**New API on `GenericVertex`**:
- `shielded_outputs` property → returns `[]` by default.
- `is_shielded_output(index)` → returns `False` by default.
- `resolve_spent_output(index)` → returns `self.outputs[index]` (raises `IndexError` for out-of-bounds), shielded-aware in subclass overrides later.

**Callsites migrated**:
- `hathor/transaction/base_transaction.py` (to_json_extended, get_related_addresses)
- `hathor/transaction/scripts/execute.py`, `opcode.py`
- `hathor/verification/transaction_verifier.py` (verify_inputs, verify_script, _get_token_info_from_inputs paths)
- `hathor/indexes/utxo_index.py`
- `hathor/indexes/rocksdb_tokens_index.py`
- `hathor/transaction/resources/transaction.py`
- `hathor/transaction/transaction.py`
- `hathor/nanocontracts/vertex_data.py`

**hathorlib**: no equivalent today, no paired change.

**Risk**: low — same observable behavior, broader call surface but each migration is mechanical.

---

## PR 3 — feat: canonical header ordering + `get_header_id()`

**Type**: small behavioral addition. **Requires chain-data confirmation before merge.**

### Required pre-check

Run a one-off scan over mainnet and testnet full-node storage:
- For every tx with `len(headers) > 1`, verify header IDs are strictly ascending (`int.from_bytes(h.get_header_id(), 'big')`).
- If **all** existing txs already comply → ship the rule unconditionally.
- If **any** existing tx violates → gate the new check behind a new Feature Activation (e.g. `CANONICAL_HEADER_ORDER`) at a future activation height.

Internal note: on master, `hathor/dag_builder/vertex_exporter.py` always appends `nano_header` (0x10) before `fee_header` (0x11) — i.e. test/internal code already produces canonical order. The risk is whether wallets/external clients have ever produced the reverse order.

### Scope

hathor-core:
- `hathor/transaction/headers/base.py` — abstract `get_header_id()` classmethod.
- `hathor/transaction/headers/fee_header.py`, `nano_header.py` — implementations.
- `hathor/verification/vertex_verifier.py` — `_get_header_order` + canonical order check inside `verify_headers`.
- Tests covering both directions of the rule.

hathorlib:
- Equivalent `get_header_id()` on `hathorlib/hathorlib/headers/{base,fee_header,nano_header}.py`.

**Risk**: behavioral change. Mitigated by the pre-check above.

---

## PR 4 — feat(shielded): data model, headers, feature flag (gated OFF)

**Type**: feature scaffolding. New code only; no existing tx path is affected because `ENABLE_SHIELDED_TRANSACTIONS` defaults to `DISABLED` and the parser only registers the new headers when the flag is on.

### Scope (hathor-core)

- **NEW**:
  - `hathor/crypto/shielded/**` — Python wrappers around the (not-yet-shipped) Rust crypto bindings.
  - `hathor/transaction/shielded_tx_output.py` — `ShieldedOutput`, `AmountShieldedOutput`, `FullShieldedOutput`, `OutputMode`.
  - `hathor/transaction/headers/shielded_outputs_header.py`, `unshield_balance_header.py`.
- `hathor/transaction/headers/types.py` — new `SHIELDED_OUTPUTS_HEADER` (0x12), `UNSHIELD_BALANCE_HEADER` (0x13).
- `hathor/transaction/headers/__init__.py` — exports.
- `hathor/transaction/vertex_parser/_headers.py`, `_vertex_parser.py` — parse new headers when feature active.
- `hathor/conf/settings.py` — `ENABLE_SHIELDED_TRANSACTIONS: FeatureSetting = DISABLED`, `FEE_PER_AMOUNT_SHIELDED_OUTPUT`, `FEE_PER_FULL_SHIELDED_OUTPUT`.
- `hathor/feature_activation/feature.py` — new `SHIELDED_TRANSACTIONS` enum value.
- `hathor/feature_activation/utils.py` — extract `Features.get_settings()`; thread `shielded_transactions` through `Features`.
- `hathor/transaction/exceptions.py` — `InvalidShieldedOutputError`, `InvalidRangeProofError`, `InvalidSurjectionProofError`, `ShieldedAuthorityError`, `ShieldedBalanceMismatchError`, `ShieldedMintMeltForbiddenError`, `TrivialCommitmentError`.
- `hathor/transaction/transaction.py` — `has_shielded_outputs()`, `has_shielded_inputs()`, `is_shielded()`, `get_shielded_outputs_header()`, `shielded_outputs` property override, `has_unshield_balance_header()`, `get_unshield_balance_header()`, `excess_blinding_factor` property.
- `hathor/transaction/base_transaction.py` — default `has_shielded_outputs()` returns False; raise `get_maximum_number_of_headers()` to 3; `_shielded_output_to_json()` helper (not yet wired).
- `hathor/builder/builder.py` — `validate_shielded_crypto_available()` — only hard-fails when `ENABLE_SHIELDED_TRANSACTIONS != DISABLED`, so node starts fine without the Rust lib.
- `hathor/verification/vertex_verifier.py` — `_get_allowed_headers_by_vertex_version` admits new headers for `REGULAR_TRANSACTION` only when `params.features.shielded_transactions`.
- Unit tests: data model serialization, header round-trip parsing, feature flag gating. **No verification semantics tested here.**

### Scope (hathorlib)

- **Pure file rename** as the first commit in this PR (separate commit for clarity): `hathorlib/hathorlib/transaction.py` → `hathorlib/hathorlib/transaction/__init__.py`.
- **NEW**:
  - `hathorlib/hathorlib/headers/shielded_outputs_header.py`, `unshield_balance_header.py`.
  - `hathorlib/hathorlib/transaction/shielded_tx_output.py`.
- `hathorlib/hathorlib/headers/__init__.py`, `types.py` — exports + new IDs.
- `hathorlib/hathorlib/base_transaction.py` — raise max headers to 3; shielded script standardness check in `is_standard_tx`.
- `hathorlib/hathorlib/vertex_parser.py` — register new headers (hathorlib has no feature-flag layer; always-on is fine for a client lib).
- `hathorlib/hathorlib/serialization/bytes_deserializer.py`, `deserializer.py` — `replace_remaining()` helper required by raw-bytes shielded header deserialization.
- `hathorlib/hathorlib/conf/unittests.yml` — `ENABLE_SHIELDED_TRANSACTIONS: enabled`.
- `hathorlib/tests/test_basic.py` — header round-trip tests.

**Risk**: low. Feature flag off by default; new headers cannot be parsed until the flag is enabled. The hathorlib changes are always-on but harmless without nodes that produce shielded txs.

---

## PR 5 — feat(shielded): verification ⚠️ security-critical

**Type**: the behavioral heart of the feature. This is THE PR for deep security review.

**Dispatch model**: `_verify_tx` chooses `verify_transparent_balance` vs `verify_shielded_balance` based on `tx.is_shielded()`. Exactly one balance check runs per tx.

### Scope (hathor-core only)

- `hathor/verification/transaction_verifier.py`:
  - Extract `_check_token_permissions_and_deposits()` shared helper, with `is_shielded` parameter to skip amount-based mint/melt check on non-native tokens.
  - Add `is_shielded` parameter to `_check_token_permissions()`.
  - Add `verify_transparent_balance(..., shielded_fee=0)` (super-set of original `verify_sum`).
  - Add `verify_token_rules()` — used for shielded txs in place of `verify_transparent_balance`.
  - Add shielded-only methods: `verify_shielded_outputs`, `verify_shielded_outputs_with_storage`, `verify_commitments_valid`, `verify_authority_restriction`, `verify_range_proofs`, `verify_surjection_proofs`, `verify_shielded_balance`, `verify_trivial_commitment_protection`, `verify_no_undeclared_mint_melt`, `verify_shielded_fee`, `calculate_shielded_fee`, `_normalize_token_uid`, `_get_or_derive_asset_tag`. (PR 5 originally landed `verify_no_mint_melt`; the post-plan mint/melt-headers extension renamed it to `verify_no_undeclared_mint_melt`.)
- `hathor/verification/verification_service.py`:
  - `verify_basic` — early feature-gate check; new `_verify_basic_shielded_header` (no storage).
  - `verify` (storage-bound) — new `_verify_shielded_header` (surjection needs storage); reject shielded outputs in `TokenCreationTransaction`.
  - `_verify_tx` — balance dispatch split (transparent vs shielded).
- `hathor/transaction/transaction.py`:
  - `_get_token_info_from_inputs` — skip shielded inputs for transparent token accounting (amount hidden).
  - `_update_token_info_from_outputs` — seed `TokenInfo` for output tokens that were not in inputs, so unshielding (transparent output of a hidden-asset shielded input) is not rejected. Mint/melt safety still enforced downstream by `verify_no_undeclared_mint_melt` for shielded txs (renamed from `verify_no_mint_melt` by the post-plan mint/melt-headers extension) and the standard `ForbiddenMint`/`ForbiddenMelt` for transparent txs.
  - `to_json_extended` — include `tokens` array.
- `hathor/transaction/token_info.py` — `calculate_fee(settings, *, shielded_fee=0)` parameter.
- `hathor/consensus/consensus.py` — `_shielded_activation_rule` reorg handling for `SHIELDED_TRANSACTIONS`; add `FAILED_FEE_TOKENS` / `FAILED_OPCODES_V2` to the no-op feature list.
- Verification-focused tests:
  - `hathor_tests/tx/test_shielded_verification.py`
  - `hathor_tests/tx/test_shielded_security.py`
  - `hathor_tests/tx/test_shielded_audit_fixes.py`
  - `hathor_tests/tx/test_shielded_cons_fixes.py`
  - `hathor_tests/tx/test_shielded_post_audit_fixes.py`
  - `hathor_tests/tx/test_shielded_v3_audit_fixes.py`

**hathorlib**: no change — hathorlib does not run verification.

**Risk**: high. This is the critical PR. Reviewers should focus their attention here.

---

## PR 6 — feat(shielded): wallet support

**Type**: feature surface for a different stakeholder (wallet team).

### Scope (hathor-core only)

- `hathor/wallet/base_wallet.py` (~228 lines added) — ECDH-based shielded UTXO discovery and decryption.
- `hathor/wallet/resources/thin_wallet/address_balance.py`, `address_search.py` — surface shielded UTXOs in wallet APIs.
- `hathor_tests/wallet/test_shielded_wallet.py`.

**hathorlib**: no change.

**Risk**: medium — wallet correctness matters for users, but nothing here changes consensus.

---

## PR 7 — feat(shielded): indexes, sync, API, events, DAG builder

**Type**: integration work — everything else needed to run a node with the feature on.

Could be split further (7a indexes, 7b sync + migrations, 7c API + events, 7d DAG builder test helpers) if reviewers prefer. Listed as one PR by default.

### Scope (hathor-core only)

- `hathor/indexes/utxo_index.py`, `rocksdb_tokens_index.py` — skip shielded outputs (no public value/token to index).
- `hathor/p2p/sync_v2/transaction_streaming_client.py` — derive `Features` from the syncing block's feature activation state so permissive features (incl. `shielded_transactions`) gate `verify_basic` correctly during sync.
- `hathor/transaction/storage/transaction_storage.py` + `hathor/transaction/storage/migrations/reset_feature_state_cache.py` — migration hook.
- `hathor/transaction/resources/transaction.py` — serialize shielded outputs in `/transaction` API.
- `hathor/transaction/resources/create_tx.py` — callsite update.
- `hathor/event/model/event_data.py` — new `ShieldedTxOutput` event model + smart union with `TxOutput`.
- `hathor/dag_builder/vertex_exporter.py`, `default_filler.py`, `tokenizer.py` — DAG builder support for shielded syntax (test infrastructure).
- Tests:
  - `hathor_tests/tx/test_tokens_index_shielded.py`
  - `hathor_tests/event/test_event_data_shielded.py`
  - `hathor_tests/resources/transaction/test_tx_shielded.py`
  - `hathor_tests/dag_builder/test_shielded_dag_builder.py`
  - `hathor_tests/dag_builder/test_unshield_balance_dag_builder.py`
  - `hathor_tests/tx/test_shielded_tx.py`

**hathorlib**: no change.

**Risk**: low — every code path is feature-gated.

---

## PR 8 — Rust lib + build/CI wiring (`hathor-ct-crypto`)

**Type**: native dependency + supporting infrastructure. Ships **last**.

### Scope

- `hathor-ct-crypto/**` — full Rust crate (Pedersen commitments, range proofs, surjection proofs, ECDH, FFI for Python, NAPI for Node).
- `Dockerfile`, `Makefile` — Rust toolchain installation, `maturin develop` invocation.
- `.github/workflows/{lib,main}.yml` — CI updates.
- `pyproject.toml` — depend on the new crypto package.
- `hathor-ct-crypto/SHIELDED-OUTPUTS-CLIENT-GUIDE.md` — integration docs.

### Why last

- PRs 1–7 import `hathor.crypto.shielded` only inside paths gated by `ENABLE_SHIELDED_TRANSACTIONS`. With the flag off (default), the Rust lib is never invoked. CI and prod run fine without it.
- Once PR 8 lands, testnet operators can flip the flag and the feature becomes usable end-to-end.

**Risk**: build-system risk on CI; consensus risk only if the flag is enabled afterward.

---

## Review story (summary)

| PR | Type | Reviewer focus | Approx. risk |
|----|------|----------------|--------------|
| 1  | rename | mechanical | nil |
| 2  | refactor | mechanical | low |
| 3  | small behavioral | header ordering rule + chain scan result | low* |
| 4  | scaffolding (gated) | new types, new headers, feature flag wiring | low |
| 5  | **security-critical** | balance equation, proofs, dispatch | **high** |
| 6  | wallet feature (gated) | UTXO discovery, decryption | medium |
| 7  | integration (gated) | indexes, sync, API surface | low |
| 8  | native lib + build | Rust crate + CI/Docker | medium (build) |

*PR 3 risk is contingent on the chain-data scan result.

---

## Open items / decisions to confirm before execution

1. **PR 3 chain-data scan result** — does any existing testnet/mainnet tx with multiple headers violate canonical ordering? Need a one-off node-side scan script.
2. **Should PR 7 be split further?** Current single-PR shape is the simplest, but indexes/sync/API/DAG-builder are independent surfaces.
3. **Hathorlib release/versioning cadence** — when paired hathorlib changes ship, is a hathorlib version bump cut per PR or batched?

---

## Post-plan extensions (not in the original 1–8 sequence)

This plan was authored before the mint/melt-headers RFC, so follow-on PRs that extend the parent RFC's invariants live outside this sequence and are tracked on their own branches.

- **`feat/shielded-mint-melt`** — lifts parent RFC Rule 8 ("no mint/melt in shielded txs") via `MintHeader (0x14)` and `MeltHeader (0x15)` declaring per-token supply changes that enter the augmented homomorphic balance equation as unblinded scalars. Renames `verify_no_mint_melt` → `verify_no_undeclared_mint_melt`, lets `TokenCreationTransaction` carry shielded outputs of the new token, and extends the `rocksdb_tokens_index` to track the public supply delta. Gated by the parent `ENABLE_SHIELDED_TRANSACTIONS` flag — no separate feature flag.
