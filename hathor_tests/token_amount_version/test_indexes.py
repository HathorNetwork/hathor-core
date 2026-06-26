# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Tokens-total and UTXO indexes under V1 and V2 amounts.

The UTXO index keys the amount as `amount.normalized()` in a length-prefixed varint, so the byte width
follows the value's magnitude (1..15+ bytes) and lexicographic key order stays numeric order for range
scans; both V1 and V2 outputs read back as V2-tagged amounts compared on their shared normalized form. The
tokens index stores each token's total in normalized units and reports it as a V2 amount, so V1 totals come
back scaled by the normalization factor while V2 totals have raw == normalized; authority UTXOs carry a
bitmask, not an amount, and never contribute to a total.
"""

from __future__ import annotations

from dataclasses import replace

from htr_lib import SignedAmount, UnsignedAmount

from hathor.daa import DAAFactory, TestMode
from hathor.indexes.rocksdb_utxo_index import _key_from_index_item, _KeyNoLock, _parse_key
from hathor.indexes.utxo_index import UtxoIndexItem
from hathor.transaction import Block, Transaction, TxOutput
from hathor.transaction.scripts import parse_address_script
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.util import not_none
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.serialization import Serializer
from hathorlib.serialization.encoding.output_value import encode_length_prefix_varint

# Byte offset of the amount field inside a no-lock UTXO key: [tag:1][token_uid:32][address:25][amount...].
_NOLOCK_AMOUNT_OFFSET = 1 + 32 + 25


def _varint_byte_length(normalized: int) -> int:
    """Return the number of payload bytes the length-prefixed varint uses for `normalized`."""
    return (normalized.bit_length() + 7) // 8


def _encode_amount_field(normalized: int) -> bytes:
    """Return the exact key bytes the UTXO index writes for an amount: `[length][big-endian payload]`."""
    serializer = Serializer.build_bytes_serializer()
    encode_length_prefix_varint(serializer, normalized, strict=False)
    return bytes(serializer.finalize())


class TestIndexesTokenAmountV2(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        # `wallet_index` enables the tokens index; `utxo_index` enables the UTXO index.
        self.manager = self.create_peer('unittests', wallet_index=True, utxo_index=True)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.utxo_index = not_none(self.manager.tx_storage.indexes.utxo)
        self.tokens_index = not_none(self.manager.tx_storage.indexes.tokens)
        self.htr_uid = self._settings.HATHOR_TOKEN_UID

    @staticmethod
    def _output_address(output: TxOutput) -> str:
        """Return the base58 address a P2PKH output pays to."""
        script = parse_address_script(output.script)
        assert script is not None
        return script.address

    def _address_utxo_amounts(self, address: str) -> list[int]:
        """Return the normalized amounts the UTXO index holds for `address` (HTR), in descending order."""
        items = self.utxo_index.iter_utxos(
            address=address,
            token_uid=self.htr_uid,
            target_amount=UnsignedAmount.from_v2(2 ** 200),
        )
        return [item.amount.normalized() for item in items]

    def test_utxo_index_amount_is_length_prefixed_varint(self) -> None:
        """Round-trip a UTXO index item and assert the key stores `amount.normalized()` as a length-prefixed varint
        (variable length), not a fixed 8-byte field, and parses back to the original normalized value. Pins the
        encoding the commit introduced."""
        address = self.manager.wallet.get_unused_address()
        item = UtxoIndexItem(
            token_uid=self.htr_uid,
            tx_id=b'\x11' * 32,
            index=0,
            address=address,
            amount=UnsignedAmount.from_v2(0xc0ffee),
            timelock=None,
            heightlock=None,
        )
        key = bytes(_key_from_index_item(item))

        # The amount field is `[length][payload]`, its width tracking the value: 3 payload bytes here, length byte 3.
        amount_field = _encode_amount_field(0xc0ffee)
        assert amount_field == bytes([3, 0xc0, 0xff, 0xee])
        assert key[_NOLOCK_AMOUNT_OFFSET:_NOLOCK_AMOUNT_OFFSET + len(amount_field)] == amount_field

        # The width follows the value, so a 1-byte and a 9-byte amount occupy different-length key fields.
        small_key = bytes(_key_from_index_item(replace(item, amount=UnsignedAmount.from_v2(1))))
        big_key = bytes(_key_from_index_item(replace(item, amount=UnsignedAmount.from_v2(2 ** 64))))
        assert len(small_key) == _NOLOCK_AMOUNT_OFFSET + 2 + 32 + 1
        assert len(big_key) == _NOLOCK_AMOUNT_OFFSET + 10 + 32 + 1
        assert len(small_key) != len(big_key)

        parsed = _parse_key(key)
        assert isinstance(parsed, _KeyNoLock)
        assert parsed.amount == 0xc0ffee
        assert parsed.to_index_item().amount.normalized() == item.amount.normalized()

    def test_utxo_index_v1_block_reward_exceeds_8_bytes_when_normalized(self) -> None:
        """A V1 block reward normalizes above 2**64 (needs 9 varint bytes); add it and query it back via the index.
        Regression guard that the old fixed 8-byte packing would truncate/raise — the load-bearing reason for the
        encoding change."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..3]
        ''')
        artifacts.propagate_with(self.manager)
        b1 = artifacts.get_typed_vertex('b1', Block)
        reward = b1.outputs[0].value

        # A block reward is always V1, and one V1 reward unit (10**16 normalized) times 6400 exceeds 2**64.
        assert reward.is_v1()
        assert reward.normalized() > 2 ** 64
        assert _varint_byte_length(reward.normalized()) == 9

        address = self.manager.wallet.get_unused_address()
        item = UtxoIndexItem(
            token_uid=self.htr_uid,
            tx_id=b'\x22' * 32,
            index=0,
            address=address,
            amount=reward,
            timelock=None,
            heightlock=None,
        )
        self.utxo_index._add_utxo(item)

        # The key carries all 9 payload bytes (length prefix 9), so a value above 2**64 keys losslessly.
        key = bytes(_key_from_index_item(item))
        amount_field = _encode_amount_field(reward.normalized())
        assert amount_field[0] == 9
        assert key[_NOLOCK_AMOUNT_OFFSET:_NOLOCK_AMOUNT_OFFSET + len(amount_field)] == amount_field
        parsed = _parse_key(key)
        assert isinstance(parsed, _KeyNoLock)
        assert parsed.amount == reward.normalized()

        got = list(self.utxo_index.iter_utxos(
            address=address, token_uid=self.htr_uid, target_amount=UnsignedAmount.from_v1(1),
        ))
        assert len(got) == 1
        assert got[0].amount.is_v2()
        assert got[0].amount.normalized() == reward.normalized()

    def test_utxo_index_orders_amounts_across_varint_lengths(self) -> None:
        """Store UTXOs (same token+address) whose normalized amounts need 1, 2, 7, 9, and 15 bytes (mix of V1 and
        V2) and assert `iter_utxos` returns them in strictly descending numeric order. Pins that the varint
        preserves lexicographic == numeric ordering for range scans."""
        address = self.manager.wallet.get_unused_address()

        # Normalized widths: V2(1)->1, V2(256)->2, V1(1)->7, V1(6400)->9, V2(2**113)->15 bytes.
        amounts = [
            UnsignedAmount.from_v2(1),
            UnsignedAmount.from_v2(256),
            UnsignedAmount.from_v1(1),
            UnsignedAmount.from_v1(6400),
            UnsignedAmount.from_v2(2 ** 113),
        ]
        for i, amount in enumerate(amounts):
            self.utxo_index._add_utxo(UtxoIndexItem(
                token_uid=self.htr_uid,
                tx_id=bytes([i + 1]) * 32,
                index=0,
                address=address,
                amount=amount,
                timelock=None,
                heightlock=None,
            ))

        normalized = self._address_utxo_amounts(address)
        assert [_varint_byte_length(value) for value in normalized] == [15, 9, 7, 2, 1]
        assert all(normalized[i] > normalized[i + 1] for i in range(len(normalized) - 1))

    def test_utxo_index_returns_normalized_v2_amount_for_v1_output(self) -> None:
        """Index a single V1 output and read it back; assert the returned item's amount is V2-tagged and equals the
        V1 value by normalized comparison. Pins that the index normalizes-to-V2 on read regardless of source
        version."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            b1.out[0] <<< tx
            tx.out[0] = 1.00 HTR

            b11 < tx
            tx <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tx = artifacts.get_typed_vertex('tx', Transaction)
        assert tx.outputs[0].value.is_v1()

        address = self._output_address(tx.outputs[0])
        got = list(self.utxo_index.iter_utxos(
            address=address, token_uid=self.htr_uid, target_amount=UnsignedAmount.from_v1(1),
        ))
        assert len(got) == 1
        assert got[0].amount.is_v2()
        assert got[0].amount.normalized() == tx.outputs[0].value.normalized()

    def test_utxo_index_iter_utxos_mixed_v1_v2_same_token(self) -> None:
        """A token+address holds both V1 and V2 outputs; assert `iter_utxos` selects/merges them by normalized value
        for various target amounts. Pins mixed-version coexistence in one address book."""
        factor = UnsignedAmount.get_normalization_factor()
        address = self.manager.wallet.get_unused_address()

        # Interleave V1 cents (2, 1) with sub-/inter-cent V2 amounts (1.5, 0.5) that have no V1 encoding.
        specs = [
            (UnsignedAmount.from_v1(2), b'\xa1' * 32),
            (UnsignedAmount.from_v2(factor + factor // 2), b'\xb2' * 32),
            (UnsignedAmount.from_v1(1), b'\xa3' * 32),
            (UnsignedAmount.from_v2(factor // 2), b'\xc4' * 32),
        ]
        for amount, tx_id in specs:
            self.utxo_index._add_utxo(UtxoIndexItem(
                token_uid=self.htr_uid,
                tx_id=tx_id,
                index=0,
                address=address,
                amount=amount,
                timelock=None,
                heightlock=None,
            ))

        def query(target: UnsignedAmount) -> list[int]:
            return [item.amount.normalized() for item in self.utxo_index.iter_utxos(
                address=address, token_uid=self.htr_uid, target_amount=target,
            )]

        # A large target returns every UTXO, V1 and V2 interleaved by normalized value.
        assert query(UnsignedAmount.from_v2(2 ** 200)) == [2 * factor, factor + factor // 2, factor, factor // 2]
        # A one-cent target is served by the exact V1 cent, merging the sub-cent V2 below it.
        assert query(UnsignedAmount.from_v1(1)) == [factor, factor // 2]
        # A sub-cent target is served by exactly the sub-cent V2 UTXO.
        assert query(UnsignedAmount.from_v2(factor // 2)) == [factor // 2]

    def test_utxo_index_consistency_after_reorg_removing_v2(self) -> None:
        """Build a branch with V2 outputs, reorg it out with a heavier block, and assert the voided V2 outputs are
        removed from the UTXO index and re-confirming restores them. Pins index updates with V2 amounts."""
        settings = self._settings.model_copy(update={'REWARD_SPEND_MIN_BLOCKS': 1})
        daa_factory = DAAFactory(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa_factory(daa_factory)
        builder.enable_utxo_index()
        manager = self.create_peer_from_builder(builder)
        dag_builder = TestDAGBuilder.from_manager(manager)
        utxo_index = not_none(manager.tx_storage.indexes.utxo)

        # tx3 carries a V2 output and conflicts with tx2 (both spend tx1.out[0]); the heavier side chain a
        # confirms tx2 first, then a heavier b3 extension re-confirms tx3.
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..3]
            blockchain b1 a[2..3]
            b1 < dummy

            b1 < tx1 < tx2 < tx3 < b2
            tx3 <-- b2

            tx1.out[0] <<< tx2
            tx1.out[0] <<< tx3

            tx3.out[0] = 1.00 HTR
            tx3.token_amount_version = V2

            a2.weight = 10
            b2 < a2
            tx2 <-- a3

            a3 < b3
            b3.weight = 20
            tx3 <-- b3
        ''')
        tx3 = artifacts.get_typed_vertex('tx3', Transaction)
        assert tx3.outputs[0].value.is_v2()
        address = self._output_address(tx3.outputs[0])
        expected_normalized = tx3.outputs[0].value.normalized()

        def utxo_amounts() -> list[int]:
            return [item.amount.normalized() for item in utxo_index.iter_utxos(
                address=address, token_uid=settings.HATHOR_TOKEN_UID,
                target_amount=UnsignedAmount.from_v2(2 ** 200),
            )]

        def voided_by(vertex: Transaction) -> object:
            return manager.tx_storage.get_transaction(vertex.hash).get_metadata().voided_by

        # tx3 confirmed by b2: its V2 output is indexed.
        artifacts.propagate_with(manager, up_to='b2')
        assert voided_by(tx3) is None
        assert utxo_amounts() == [expected_normalized]

        # Side chain a reorgs b2 out and confirms tx2, voiding tx3: its V2 output is removed.
        artifacts.propagate_with(manager, up_to='a3')
        assert voided_by(tx3) == {tx3.hash}
        assert utxo_amounts() == []

        # A heavier b3 extension reorgs back and re-confirms tx3: its V2 output is restored.
        artifacts.propagate_with(manager, up_to='b3')
        assert voided_by(tx3) is None
        assert utxo_amounts() == [expected_normalized]

    def test_utxo_index_rebuild_matches_live_with_v2(self) -> None:
        """Snapshot the UTXO index over a DAG with mixed V1/V2 outputs (incl. time/height locks), reinitialize the
        index from storage, and assert the rebuilt index is byte-identical. Pins deterministic re-derivation."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..14]
            b10 < dummy

            b1.out[0] <<< tx1
            tx1.out[0] = 0.005 HTR
            tx1.out[1] = 0.995 HTR
            tx1.token_amount_version = V2

            b2.out[0] <<< tx2
            tx2.out[0] = 1.00 HTR

            b11 < tx1
            b12 < tx2
            tx1 <-- tx2 <-- b13
        ''')
        artifacts.propagate_with(self.manager)

        # Heightlocked block rewards plus V1 and sub-cent V2 tx outputs populate the index.
        live = list(self.utxo_index.get_all_internal())
        assert len(live) > 0

        # Clear and force a full re-derivation from storage, then compare the raw rocksdb keys byte-for-byte.
        tx_storage = self.manager.tx_storage
        self.utxo_index.force_clear()
        assert list(self.utxo_index.get_all_internal()) == []
        tx_storage.set_index_last_started_at(self.utxo_index.get_db_name(), 0)
        tx_storage._manually_initialize()

        rebuilt = list(self.utxo_index.get_all_internal())
        assert rebuilt == live

    def test_tokens_index_total_v1_stored_normalized(self) -> None:
        """Mint a V1 custom token; assert `get_token_info(uid).get_total()` equals the V1 amount, is reported as a
        V2-tagged amount, and its normalized value is scaled by the normalization factor. Pins V1 totals are stored
        normalized and reported as V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            tka.out[0] = 100 TKA

            b11 < tka
            tka <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)

        total = self.tokens_index.get_token_info(tka.hash).get_total()
        factor = UnsignedAmount.get_normalization_factor()
        assert total == UnsignedAmount.from_v1(100)
        assert total.is_v2()
        assert total.normalized() == 100 * factor
        assert total.raw() == total.normalized()

    def test_tokens_index_total_v2_raw_equals_normalized(self) -> None:
        """Mint a V2 custom token; assert `get_total()` equals the V2 amount with raw == normalized. Contrasts with
        the V1 case to pin the scaling difference at equal nominal mint."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            tkb.out[0] = 100 TKB
            tkb.token_amount_version = V2
            TKB.token_amount_version = V2

            b11 < tkb
            tkb <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tkb = artifacts.get_typed_vertex('TKB', TokenCreationTransaction)

        total = self.tokens_index.get_token_info(tkb.hash).get_total()
        assert total == UnsignedAmount.from_v2(100)
        assert total.is_v2()
        assert total.raw() == 100
        assert total.raw() == total.normalized()
        # Equal nominal mint (100) yields a smaller normalized total for V2 than for V1 (which scales by the factor).
        assert total.normalized() != UnsignedAmount.from_v1(100).normalized()

    def test_tokens_index_tracks_mint_then_melt_v2(self) -> None:
        """For a V2 token, mint additional supply then melt some; assert `get_total()` tracks the running normalized
        sum exactly after each step, and authority UTXOs (no amount) are version-agnostic and excluded from total."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy

            tkb.out[0] = 100 TKB
            tkb.token_amount_version = V2
            TKB.token_amount_version = V2

            b11 < tkb
            tkb <-- b12
        ''')
        artifacts.propagate_with(self.manager)
        tkb = artifacts.get_typed_vertex('TKB', TokenCreationTransaction)
        info = self.tokens_index.get_token_info(tkb.hash)

        # The creation tx carries mint and melt authority outputs, yet the total is exactly the minted amount:
        # authority UTXOs carry a bitmask, not an amount, so they never enter the total.
        assert info.can_mint()
        assert info.can_melt()
        assert info.get_total() == UnsignedAmount.from_v2(100)

        # Mint 50 more V2 units, then melt 30, and check the running normalized total after each step.
        mint_delta: SignedAmount = UnsignedAmount.from_v2(50).to_signed()
        self.tokens_index.add_to_total(tkb.hash, mint_delta)
        assert self.tokens_index.get_token_info(tkb.hash).get_total() == UnsignedAmount.from_v2(150)

        melt_delta: SignedAmount = -UnsignedAmount.from_v2(30).to_signed()
        self.tokens_index.add_to_total(tkb.hash, melt_delta)
        after_melt = self.tokens_index.get_token_info(tkb.hash).get_total()
        assert after_melt == UnsignedAmount.from_v2(120)
        assert after_melt.raw() == after_melt.normalized() == 120

    def test_tokens_index_htr_total_accumulates_v1_block_rewards(self) -> None:
        """After N blocks, assert the HTR `get_total()` equals genesis total + the V1 block reward times N
        (normalized). Pins that always-V1 block rewards accumulate into the normalized HTR total."""
        n_blocks = 12
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
        ''')
        artifacts.propagate_with(self.manager)

        blocks = artifacts.get_typed_vertices([f'b{i}' for i in range(1, n_blocks + 1)], Block)
        rewards = [block.outputs[0].value for block in blocks]
        # Every block reward is always encoded as V1.
        assert all(reward.is_v1() for reward in rewards)
        assert all(reward.raw() == rewards[0].raw() for reward in rewards)

        genesis_total = UnsignedAmount.from_v1(self._settings.GENESIS_TOKEN_ATOMIC_UNITS)
        expected = genesis_total.normalized() + n_blocks * rewards[0].normalized()

        htr_total = self.tokens_index.get_token_info(self.htr_uid).get_total()
        assert htr_total.normalized() == expected
