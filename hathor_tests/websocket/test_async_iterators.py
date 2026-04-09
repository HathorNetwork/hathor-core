from typing import AsyncIterator, TypeVar

from twisted.internet.defer import Deferred

from hathor.wallet import HDWallet
from hathor.websocket.exception import InvalidAddress, InvalidXPub
from hathor.websocket.iterators import (
    AddressItem,
    ManualAddressSequencer,
    VertexItem,
    aiter_xpub_addresses,
    gap_limit_search,
)
from hathor_tests.unittest import TestCase
from hathor_tests.utils import GENESIS_ADDRESS_B58

T = TypeVar('T')


async def async_islice(iterable: AsyncIterator[T], stop: int) -> AsyncIterator[T]:
    count = 0
    async for item in iterable:
        if count >= stop:
            break
        yield item
        count += 1


class AsyncIteratorsTestCase(TestCase):
    def setUp(self) -> None:
        super().setUp()

        self.manager = self.create_peer('mainnet', wallet_index=True)
        self.settings = self.manager._settings

        # Create wallet.
        wallet = HDWallet()
        wallet.unlock(self.manager.tx_storage)

        # Create xpub and list of addresses.
        self.xpub = wallet.get_xpub()
        self.xpub_addresses = [
            AddressItem(idx, wallet.get_address(wallet.get_key_at_index(idx)))
            for idx in range(20)
        ]

    async def test_xpub_sequencer_default_first_index(self) -> None:
        xpub = self.xpub
        expected_result = self.xpub_addresses

        sequencer = aiter_xpub_addresses(xpub)
        result = [item async for item in async_islice(aiter(sequencer), len(expected_result))]
        self.assertEqual(result, expected_result)

    async def test_xpub_sequencer_other_first_index(self) -> None:
        xpub = self.xpub
        first_index = 8
        expected_result = self.xpub_addresses[first_index:]

        sequencer = aiter_xpub_addresses(xpub, first_index=first_index)
        result = [item async for item in async_islice(aiter(sequencer), len(expected_result))]
        self.assertEqual(result, expected_result)

    async def test_xpub_sequencer_invalid(self) -> None:
        with self.assertRaises(InvalidXPub):
            async for _ in aiter_xpub_addresses('invalid xpub'):
                pass

    async def test_manual_invalid(self) -> None:
        address_iter = ManualAddressSequencer()
        with self.assertRaises(InvalidAddress):
            address_iter.add_addresses([AddressItem(0, 'a')], last=True)

    async def test_manual_last_true(self) -> None:
        expected_result = self.xpub_addresses

        iterable = ManualAddressSequencer()
        iterable.add_addresses(expected_result, last=True)

        result = [item async for item in iterable]
        self.assertEqual(result, expected_result)

    async def test_manual_two_tranches(self) -> None:
        expected_result = self.xpub_addresses

        iterable = ManualAddressSequencer()
        n = 8
        iterable.add_addresses(expected_result[:n], last=False)

        result = []
        is_running = False

        async def collect_results():
            nonlocal is_running
            nonlocal result
            is_running = True
            result = [item async for item in iterable]
            is_running = False

        self.reactor.callLater(0, lambda: Deferred.fromCoroutine(collect_results()))
        self.reactor.advance(5)
        self.assertTrue(is_running)

        self.reactor.callLater(0, lambda: iterable.add_addresses(expected_result[n:], last=True))
        self.reactor.advance(5)
        self.assertFalse(is_running)

        self.assertEqual(result, expected_result)

    async def test_gap_limit_xpub(self) -> None:
        xpub = self.xpub
        gap_limit = 8
        expected_result = self.xpub_addresses[:gap_limit]

        address_iter = aiter_xpub_addresses(xpub)
        search = gap_limit_search(self.manager, address_iter, gap_limit=gap_limit)

        result = [item async for item in search]
        self.assertEqual(result, expected_result)

    async def test_gap_limit_manual(self) -> None:
        genesis = self.manager.tx_storage.get_genesis(self.settings.GENESIS_BLOCK_HASH)
        genesis_address = GENESIS_ADDRESS_B58

        gap_limit = 8
        addresses: list[AddressItem] = [AddressItem(0, genesis_address)] + self.xpub_addresses
        expected_result: list[AddressItem | VertexItem] = list(addresses[:gap_limit + 1])
        expected_result.insert(1, VertexItem(genesis))

        address_iter = ManualAddressSequencer()
        # Adding more addresses than the gap limit.
        address_iter.add_addresses(addresses, last=True)
        search = gap_limit_search(self.manager, address_iter, gap_limit=gap_limit)

        result = [item async for item in search]
        self.assertEqual(result, expected_result)
