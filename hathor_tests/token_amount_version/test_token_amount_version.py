#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Scaffolding for the high-level test suite of the token amount version (a.k.a. "decimals" / V2) project.

This file is an EXHAUSTIVE, behavioral test PLAN, not an implementation. Every method documents the scenario it
should set up and the behavior it pins, then `raise NotImplementedError`. It is meant to be filtered and split
into the appropriate test modules during implementation. Each class will become its own file in
`hathor_tests/token_amount_version/`

Project summary (what these tests cover):
- A transaction's token amount version is derived from the LSB of its `signal_bits`
  (`TokenAmountVersion(signal_bits & 1 + 1)`: LSB 0 -> V1, LSB 1 -> V2). Blocks are always V1.
- V2 amounts are a second on-wire representation (length-prefixed varint) carrying more decimal places than V1.
  Amounts are compared/summed in a shared `normalized()` form, so V1 and V2 mix losslessly.
- The whole feature is gated by the `TOKEN_AMOUNT_V2` feature / `ENABLE_TOKEN_AMOUNT_V2` setting (off on all real
  networks; enabled in `unittests.yml`, so tests exercising the inactive path must override it to DISABLED).
- New Rust-backed amount types carry token amounts across the surface: `UnsignedAmount` (non-negative, the
  "token amount") and `SignedAmount` (signed, the "token balance"/delta).

Implementation notes (per class, when these are turned into real tests):
- Most balance/verification/consensus/reorg/index/dag-builder classes want `TestCase` + `DAGBuilder`
  (set `tx.token_amount_version = V2`, `TKx.token_amount_version = V2`, and decimal-string amounts like
  `out[0] = 1.23 HTR`). Toggle the feature with settings overrides / feature-activation criteria.
- Nano classes want `BlueprintTestCase` (and the existing `hathor_tests/nanocontracts/test_token_amount_version.py`
  already covers the runner cross-version matrix; the nano cases here intentionally overlap at the action/balance
  level per the request to include even covered behavior).
- Amount-model cases are pure-Python contract tests against `htr_lib.UnsignedAmount` / `SignedAmount`.

Test conventions:
- Use pytest primitives: `pytest.raises` (not `self.assertRaises`) and bare `assert` (not `self.assertEqual`,
  `self.assertIsNone`, etc.).
- If a test fails because of a bug in the production code (not a bug in the test), do NOT fix the production
  code as part of writing the test. Keep the assertion pinned to the correct, specified behavior, add a comment
  explaining the production defect that makes it fail, and leave the test failing. A failure of this kind is a
  signal to surface, not something to silence.

Implemented classes live in their own modules:
- `TestTokenAmountVersionDerivation` -> `test_derivation.py`
- `TestTokenAmountVersionVerification` -> `test_verification.py`
- `TestCrossVersionBalance` -> `test_cross_version_balance.py`
- `TestTokenCreationEconomicsV2` -> `test_token_creation_economics.py`
"""

from __future__ import annotations


class TestAuthoritiesV2:
    """Authority (mint/melt) outputs under V2: the value field is a bitmask read via `.raw()`, not an amount."""

    def test_authority_output_value_is_bitmask_not_amount_v2(self) -> None:
        """A V2 tx with a mint/melt authority output; assert the authority bits are read via `value.raw()` and the
        output does not contribute to the token's balance sum. Pins authority outputs are version-agnostic."""
        raise NotImplementedError

    def test_invalid_authority_bits_rejected_v2(self) -> None:
        """A V2 authority output whose `value.raw()` exceeds `ALL_AUTHORITIES` raises
        `InvalidToken('Invalid authorities in output ...')`. Pins the ceiling check uses `raw()` under V2."""
        raise NotImplementedError

    def test_authority_passthrough_does_not_affect_balance_v2(self) -> None:
        """A V2 tx passes a mint authority through (authority in -> authority out) with no value change; assert
        balance verification ignores authority outputs and the tx verifies."""
        raise NotImplementedError

    def test_hathor_authority_output_rejected_v2(self) -> None:
        """A V2 tx with an authority UTXO on native HTR (token_index 0) raises `InvalidToken('Cannot have authority
        UTXO for hathor tokens')`, regardless of version."""
        raise NotImplementedError


class TestFeeTokensV2:
    """Fee-based token (FBT) economics under V2."""

    def test_fee_token_creation_charges_normalized_fee_v2(self) -> None:
        """A V2 fee-based token-creation tx minting one output charges the per-output fee normalized to V2 (e.g.
        `0.01 HTR`); assert the tx verifies. Pins fee normalization under V2."""
        raise NotImplementedError

    def test_v1_and_v2_fee_encodings_yield_same_normalized_fee(self) -> None:
        """Two equivalent fee txs, one V1 (fee spelled `1`) and one V2 (fee spelled as the normalized equivalent),
        both representing `0.01 HTR`; assert both produce the same expected fee and verify. Confirms fee comparison
        is version-independent."""
        raise NotImplementedError

    def test_v2_fee_mismatch_rejected(self) -> None:
        """A V2 tx whose fee-header total differs from the expected fee raises `InputOutputMismatch('Fee amount is
        different than expected. (amount=..., expected=...)')`. Pins the fee-mismatch exception under V2."""
        raise NotImplementedError

    def test_v2_fee_paid_with_v1_htr_input(self) -> None:
        """A V2 tx pays its fee from a V1-created HTR utxo; assert the fee-header total normalizes against the V1
        input and verification passes. Mixing on the fee path."""
        raise NotImplementedError

    def test_fee_added_to_balance_normalized_v2(self) -> None:
        """A V2 tx with a fee header contributes the fee to the token's balance sum in normalized units; an
        off-by-one fee is rejected. Pins fee-into-balance accounting under V2."""
        raise NotImplementedError

    def test_fee_paid_with_deposit_token_costs_fee_divisor_per_unit_v2(self) -> None:
        """Paying an FBT fee with a deposit token requires `FEE_DIVISOR` deposit-token units per fee unit under V2;
        assert the matching fee-header entry is accepted. Pins the deposit-token-denominated fee."""
        raise NotImplementedError

    def test_fbt_cannot_pay_its_own_fee_v2(self) -> None:
        """A V2 tx attempting to pay an FBT fee in that same fee-based token fails full validation with the
        `token {uid} cannot be used to pay fees` message. Pins the FBT-as-payment prohibition under V2."""
        raise NotImplementedError


class TestNanoContractsTokenAmountVersion:
    """Nano contract actions, balances, runner verifications, and execution under V1 vs V2 token amounts."""

    def test_deposit_v1_token_updates_contract_balance(self) -> None:
        """A V1 nano tx deposits HTR into a contract; assert the contract balance increases to the expected
        `SignedAmount` and the token index total matches. Control for V1 deposit accounting."""
        raise NotImplementedError

    def test_deposit_v2_token_updates_contract_balance(self) -> None:
        """A V2 nano tx (V2 blueprint, LSB 1) deposits a V2-encoded amount; assert the resulting balance is the
        V2-tagged `SignedAmount` whose `.raw()` equals the action amount and that balance validation accepts it.
        Pins V2 deposit accounting end-to-end."""
        raise NotImplementedError

    def test_deposit_sub_cent_v2_amount(self) -> None:
        """Deposit a V2 amount not representable in V1 (smallest raw unit); assert the contract balance holds the
        exact sub-cent value. Pins that V2 enables amounts a V1 contract could not encode."""
        raise NotImplementedError

    def test_withdrawal_v1_token_updates_contract_balance(self) -> None:
        """A V1 withdrawal decreases the contract balance to the expected V1 `SignedAmount`; index total updated.
        Control for V1 withdrawal."""
        raise NotImplementedError

    def test_withdrawal_v2_token_updates_contract_balance(self) -> None:
        """A V2 withdrawal moves V2-encoded tokens out to a V2 output; assert the post-withdrawal balance equals
        deposit-minus-withdrawal as a V2 `SignedAmount`. Pins V2 withdrawal accounting."""
        raise NotImplementedError

    def test_withdrawal_exceeding_balance_raises_insufficient_funds_v2(self) -> None:
        """A V2 withdrawal larger than the contract balance drives the change tracker negative; assert
        `NCInsufficientFunds`. Pins the final-balance guard under V2."""
        raise NotImplementedError

    def test_mint_and_melt_inside_v2_contract(self) -> None:
        """A V2 contract with mint authority mints, then melts, tokens via syscalls; assert minted balance and the
        consumed/freed HTR are accounted as V2 amounts and balance validation reconciles."""
        raise NotImplementedError

    def test_create_contract_cross_version_raises_ncfail(self) -> None:
        """A V2-version runner creating a V1-registered blueprint (and the mirror) raises `NCFail('cannot call
        blueprints across token amount versions ...')`. Pins the create-time version guard. (overlaps existing
        nano test file). Use dag builder."""
        raise NotImplementedError

    def test_call_method_cross_version_raises_ncfail(self) -> None:
        """Calling a public or view method on a contract whose blueprint version differs from the tx's runtime
        version raises the same `NCFail`; same-version calls succeed. (overlaps existing nano test file). Use dag
        builder"""
        raise NotImplementedError

    def test_inter_contract_call_cross_version_raises_ncfail(self) -> None:
        """A V1 contract calling/depositing into a V2 contract (via get_contract/proxy/setup_new_contract) raises
        `NCFail` before any balance mutation; assert balances are unchanged. (overlaps existing nano test file). Use
        dag builder."""
        raise NotImplementedError

    def test_block_executor_runs_v2_nano_tx(self) -> None:
        """Propagate a block containing a V2 nano deposit; assert the executor builds the runner with V2, execution
        succeeds, and the stored contract balance is the expected V2 value. Pins the executor's version wiring."""
        raise NotImplementedError

    def test_v2_nano_tx_rejected_when_feature_inactive(self) -> None:
        """With `ENABLE_TOKEN_AMOUNT_V2` inactive, submitting a nano tx with LSB 1 raises `TxValidationError('invalid
        token amount version: V2')`. Pins the feature gate for nano vertices."""
        raise NotImplementedError

    def test_reorg_deactivating_feature_voids_v2_nano_tx(self) -> None:
        """A reorg that moves the best chain below activation voids a confirmed V2 nano tx. Pins the consensus
        reorg rule applied to nano txs."""
        raise NotImplementedError

    def test_token_created_v2_deposited_by_v1_tx_uses_tx_version(self) -> None:
        """A token minted by a V2 token-creation tx is later deposited by a V1 nano tx into a V1 contract; assert
        the deposit is interpreted in the depositing TX's version (token's own creation version is irrelevant to
        accounting) and no cross-version error is raised."""
        raise NotImplementedError


class TestFeatureActivationLifecycle:
    """The TOKEN_AMOUNT_V2 feature lifecycle and its end-to-end (manager-level) effect on V2 acceptance.
    use hathor_tests/nanocontracts/test_feature_activations.py as reference.
    """

    def test_setting_default_disabled_on_all_real_networks(self) -> None:
        """Build mainnet/testnet/production settings (no override) and assert `ENABLE_TOKEN_AMOUNT_V2` is DISABLED.
        Pins that V2 ships gated OFF everywhere real."""
        raise NotImplementedError

    def test_unittests_yml_enables_feature(self) -> None:
        """Assert the unittest settings set `ENABLE_TOKEN_AMOUNT_V2` to ENABLED. Pins the test-suite-wide default
        (so inactive-path tests must explicitly override it)."""
        raise NotImplementedError

    def test_disabled_setting_overrides_state_machine(self) -> None:
        """With the setting DISABLED, assert the feature reports inactive even for an ACTIVE block state, end-to-end:
        V2 txs are rejected at every height. Pins the DISABLED short-circuit."""
        raise NotImplementedError

    def test_features_carries_token_amount_version_field(self) -> None:
        """Assert `Features.from_vertex(block).token_amount_version` is V2 when the feature is active for that block
        and V1 otherwise, and that constructing `Features(...)` without the field raises (every call site must set
        it). Pins the new permissive feature field."""
        raise NotImplementedError

    def test_lifecycle_transitions_to_active(self) -> None:
        """With FEATURE_ACTIVATION criteria, mine through the boundaries and assert the feature state progresses
        DEFINED -> STARTED -> LOCKED_IN -> ACTIVE at the expected blocks. Mirrors other features' lifecycle tests."""
        raise NotImplementedError

    def test_v2_tx_rejected_before_activation_via_manager(self) -> None:
        """While the best block state is pre-ACTIVE, relay a V2 tx through the manager and assert it is rejected
        (wrapping `invalid token amount version: V2`), stays initial, and is not voided/stored. End-to-end reject."""
        raise NotImplementedError

    def test_v2_tx_accepted_after_activation_via_manager(self) -> None:
        """Once the best block reaches ACTIVE, relay/propagate the same V2 tx and assert it is valid, not voided,
        stored, and appears among mempool tips. End-to-end accept."""
        raise NotImplementedError

    def test_v1_tx_accepted_throughout_lifecycle(self) -> None:
        """Relay a V1 tx at DEFINED, STARTED, LOCKED_IN, and ACTIVE best-block states; assert it is accepted at
        every stage. Pins that the lifecycle never blocks V1 traffic."""
        raise NotImplementedError

    def test_relayed_v2_tx_accepted_exactly_when_best_block_active(self) -> None:
        """Propagate to the first ACTIVE best block and assert a relayed V2 tx is accepted, while one block earlier
        (best block LOCKED_IN) the same tx is rejected. Pins the exact activation boundary for the mempool path."""
        raise NotImplementedError


class TestReorgTokenAmountV2:
    """Consensus reorg handling: deactivating the feature invalidates V2 transactions (`_token_amount_v2_rule`).
    use hathor_tests/nanocontracts/test_feature_activations.py as reference"""

    def test_rule_active_is_noop(self) -> None:
        """Call `_token_amount_v2_rule(tx, is_active=True)` for a V1 and a V2 tx; assert both return True. Pins that
        an active feature never invalidates anything."""
        raise NotImplementedError

    def test_rule_inactive_rejects_v2_allows_v1(self) -> None:
        """Call the rule with `is_active=False`: a V2 tx returns False (removal-eligible), a V1 tx returns True.
        Pins selective removal of only V2 txs."""
        raise NotImplementedError

    def test_reorg_below_activation_removes_v2_tx(self) -> None:
        """Confirm a V2 tx while ACTIVE, then reorg to a heavier side chain whose new best block is below the
        activation height; assert the V2 tx becomes INVALID, is removed from storage, and is absent from the
        mempool tips. Direct analogue of other feature-reorg tests."""
        raise NotImplementedError

    def test_reorg_below_activation_keeps_v1_tx(self) -> None:
        """In the same deactivating reorg, a V1 tx present in the old chain/mempool remains valid and present after
        the reorg. Pins selectivity."""
        raise NotImplementedError

    def test_reorg_re_activation_re_allows_v2_tx(self) -> None:
        """After a deactivating reorg removes a V2 tx, extend the new chain back above activation, reset and re-relay
        the V2 tx, and assert it is re-accepted. Reorg direction = chain grows back above activation."""
        raise NotImplementedError

    def test_mempool_v2_tx_invalidated_on_deactivating_reorg(self) -> None:
        """An unconfirmed V2 tx in the mempool while ACTIVE is marked INVALID and removed after a reorg whose new
        best block is pre-activation; a V1 mempool tx survives. Pins mempool re-verification."""
        raise NotImplementedError


class TestSerializationV1V2:
    """On-wire encode/decode of output values and the version bit. Consensus-critical wire-format coverage."""

    def test_v1_wire_format_unchanged(self) -> None:
        """Round-trip a set of V1 output values spanning the 4-byte/8-byte boundary and assert byte-for-byte
        equality against fixed golden vectors. The backward-compatibility anchor: any drift in V1 encoding breaks
        consensus."""
        raise NotImplementedError

    def test_v2_output_value_round_trips(self) -> None:
        """Round-trip V2 output values across length-prefix boundaries (1, 0xff, 0x100, ..., near
        `get_max_output_value_v2()`); assert decode returns an equal V2 amount and the length byte equals the
        payload byte count. Pins the length-prefixed varint layout."""
        raise NotImplementedError

    def test_v2_decode_rejects_non_canonical_and_oversized(self) -> None:
        """Decoding a V2 payload with a leading zero byte raises `ValueError('non-canonical encoding ...')`; a length
        byte > 15 raises `ValueError('length is too big ...')`; an in-range length but over-max value raises
        `ValueError('value is too big ...')`. Pins the anti-malleability and bound guards."""
        raise NotImplementedError

    def test_v2_decode_truncated_raises_out_of_data(self) -> None:
        """Decoding a V2 output whose length byte over-promises the payload raises `OutOfDataError`, distinct from
        V1's `BadDataError`. Pins the truncation behavior and exact exception type."""
        raise NotImplementedError

    def test_full_v1_transaction_round_trip_byte_for_byte(self) -> None:
        """Build a V1 tx with several outputs, serialize, `create_from_struct`, and assert object equality,
        byte-identical re-serialization, and unchanged hash. The regression anchor that the parser refactor left V1
        vertices on the wire untouched."""
        raise NotImplementedError

    def test_full_v2_transaction_round_trip(self) -> None:
        """Build a V2 tx whose outputs are V2 amounts (small and near max), round-trip through `create_from_struct`,
        and assert equality, byte-identical re-serialization, `get_token_amount_version() == V2`, every output is
        V2, and `signal_bits` is preserved."""
        raise NotImplementedError

    def test_full_v2_token_creation_transaction_round_trip(self) -> None:
        """Same for a `TokenCreationTransaction` with V2 outputs; additionally assert token name/symbol/version and
        the mint/melt authority outputs survive. Pins V2 encoding composes with the token-info trailer."""
        raise NotImplementedError

    def test_deserialize_sets_signal_bits_before_decoding_outputs(self) -> None:
        """Regression guard: round-trip a V2 tx whose first output requires V2 decoding and assert it parses (it
        would raise on a V1 mis-decode if the parser read outputs before assigning `signal_bits`). Names the
        invariant that the version field precedes the outputs it governs."""
        raise NotImplementedError

    def test_authority_output_round_trips_using_raw_under_v2(self) -> None:
        """Round-trip V2 authority outputs (mint/melt/both) and assert `can_mint_token()`/`can_melt_token()` are
        preserved because the bitmask is read via `.raw()` (not the normalized value). Pins authority semantics
        over the V2 wire."""
        raise NotImplementedError

    def test_nano_and_fee_header_amounts_follow_tx_version(self) -> None:
        """Serialize/deserialize a tx carrying both a nano header (deposit/withdrawal actions) and a fee header,
        under V1 and under V2; assert all header amounts encode in the enclosing tx's version and round-trip. Pins
        header amount encoding parity with outputs."""
        raise NotImplementedError

    def test_version_bit_is_committed_in_sighash_and_hash(self) -> None:
        """Flip only the `signal_bits` LSB (and re-encode outputs into the matching variant) and assert both the
        sighash bytes and the vertex hash change. Pins that the token-amount version is committed data; outputs
        cannot be re-encoded under a different version without invalidating the signature/PoW."""
        raise NotImplementedError

    def test_v1_and_v2_bytes_are_not_self_describing(self) -> None:
        """Decode V1 bytes as V2 (and vice versa) and assert it either errors or misparses to a different value.
        Pins that the encodings are ambiguous out-of-band, justifying why the version MUST come from `signal_bits`."""
        raise NotImplementedError

    def test_malformed_v2_output_propagates_at_vertex_level(self) -> None:
        """Hand-craft a V2 tx whose first output is non-canonical/truncated and assert `create_from_struct`
        propagates the `ValueError`/`OutOfDataError` (the V2 path is not wrapped as `InvalidOutputValue` the way V1
        struct failures are). Pins the end-to-end error behavior and the wrapping asymmetry."""
        raise NotImplementedError


class TestIndexesTokenAmountV2:
    """Tokens-total and UTXO indexes under V2 amounts, plus the token_amount_v2 storage migration."""

    def test_utxo_index_amount_is_length_prefixed_varint(self) -> None:
        """Round-trip a UTXO index item and assert the key stores `amount.normalized()` as a length-prefixed varint
        (variable length), not a fixed 8-byte field, and parses back to the original normalized value. Pins the
        encoding the commit introduced."""
        raise NotImplementedError

    def test_utxo_index_v1_block_reward_exceeds_8_bytes_when_normalized(self) -> None:
        """A V1 block reward normalizes above 2**64 (needs 9 varint bytes); add it and query it back via the index.
        Regression guard that the old fixed 8-byte packing would truncate/raise — the load-bearing reason for the
        encoding change."""
        raise NotImplementedError

    def test_utxo_index_orders_amounts_across_varint_lengths(self) -> None:
        """Store UTXOs (same token+address) whose normalized amounts need 1, 2, 7, 9, and 15 bytes (mix of V1 and
        V2) and assert `iter_utxos` returns them in strictly descending numeric order. Pins that the varint
        preserves lexicographic == numeric ordering for range scans."""
        raise NotImplementedError

    def test_utxo_index_returns_normalized_v2_amount_for_v1_output(self) -> None:
        """Index a single V1 output and read it back; assert the returned item's amount is V2-tagged and equals the
        V1 value by normalized comparison. Pins that the index normalizes-to-V2 on read regardless of source
        version."""
        raise NotImplementedError

    def test_utxo_index_iter_utxos_mixed_v1_v2_same_token(self) -> None:
        """A token+address holds both V1 and V2 outputs; assert `iter_utxos` selects/merges them by normalized value
        for various target amounts. Pins mixed-version coexistence in one address book."""
        raise NotImplementedError

    def test_utxo_index_consistency_after_reorg_removing_v2(self) -> None:
        """Build a branch with V2 outputs, reorg it out with a heavier block, and assert the voided V2 outputs are
        removed from the UTXO index and re-confirming restores them. Pins index updates with V2 amounts."""
        raise NotImplementedError

    def test_utxo_index_rebuild_matches_live_with_v2(self) -> None:
        """Snapshot the UTXO index over a DAG with mixed V1/V2 outputs (incl. time/height locks), reinitialize the
        index from storage, and assert the rebuilt index is byte-identical. Pins deterministic re-derivation."""
        raise NotImplementedError

    def test_tokens_index_total_v1_stored_normalized(self) -> None:
        """Mint a V1 custom token; assert `get_token_info(uid).get_total()` equals the V1 amount, is reported as a
        V2-tagged amount, and its normalized value is scaled by the normalization factor. Pins V1 totals are stored
        normalized and reported as V2."""
        raise NotImplementedError

    def test_tokens_index_total_v2_raw_equals_normalized(self) -> None:
        """Mint a V2 custom token; assert `get_total()` equals the V2 amount with raw == normalized. Contrasts with
        the V1 case to pin the scaling difference at equal nominal mint."""
        raise NotImplementedError

    def test_tokens_index_tracks_mint_then_melt_v2(self) -> None:
        """For a V2 token, mint additional supply then melt some; assert `get_total()` tracks the running normalized
        sum exactly after each step, and authority UTXOs (no amount) are version-agnostic and excluded from total."""
        raise NotImplementedError

    def test_tokens_index_htr_total_accumulates_v1_block_rewards(self) -> None:
        """After N blocks, assert the HTR `get_total()` equals genesis total + the V1 block reward times N
        (normalized). Pins that always-V1 block rewards accumulate into the normalized HTR total."""
        raise NotImplementedError
