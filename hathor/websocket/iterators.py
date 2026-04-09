# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import deque
from collections.abc import AsyncIterable
from dataclasses import dataclass
from typing import AsyncIterator, Iterator, TypeAlias

from twisted.internet.defer import Deferred

from hathor.manager import HathorManager
from hathor.transaction import BaseTransaction
from hathor.types import AddressB58
from hathor.websocket.exception import InvalidAddress, InvalidXPub, LimitExceeded


@dataclass(frozen=True, slots=True)
class AddressItem:
    index: int
    address: AddressB58


@dataclass(frozen=True, slots=True)
class VertexItem:
    vertex: BaseTransaction


class ManualAddressSequencer(AsyncIterable[AddressItem]):
    """An async iterable that yields addresses from a list. More addresses
    can be added while the iterator is being consumed.
    """

    ADDRESS_SIZE: int = 34
    MAX_PENDING_ADDRESSES_SIZE: int = 5_000

    def __init__(self) -> None:
        self.max_pending_addresses_size: int = self.MAX_PENDING_ADDRESSES_SIZE
        self.pending_addresses: deque[AddressItem] = deque()
        self.await_items: Deferred | None = None

        # Flag to mark when all addresses have been received so the iterator
        # can stop yielding after the pending list of addresses is empty.
        self._stop = False

    def _resume_iter(self) -> None:
        """Resume yield addresses."""
        if self.await_items is None:
            return
        if not self.await_items.called:
            self.await_items.callback(None)

    def add_addresses(self, addresses: list[AddressItem], last: bool) -> None:
        """Add more addresses to be yielded. If `last` is true, the iterator
        will stop when the pending list of items gets empty."""
        if len(self.pending_addresses) + len(addresses) > self.max_pending_addresses_size:
            raise LimitExceeded

        # Validate addresses.
        for item in addresses:
            if len(item.address) != self.ADDRESS_SIZE:
                raise InvalidAddress(item)

        self.pending_addresses.extend(addresses)
        if last:
            self._stop = True
        self._resume_iter()

    def __aiter__(self) -> AsyncIterator[AddressItem]:
        """Return an async iterator."""
        return self._async_iter()

    async def _async_iter(self) -> AsyncIterator[AddressItem]:
        """Internal method that implements the async iterator."""
        while True:
            while self.pending_addresses:
                item = self.pending_addresses.popleft()
                yield item

            if self._stop:
                break

            self.await_items = Deferred()
            await self.await_items


def iter_xpub_addresses(xpub_str: str, *, first_index: int = 0) -> Iterator[AddressItem]:
    """An iterator that yields addresses derived from an xpub."""
    from pycoin.networks.registry import network_for_netcode

    from hathor.wallet.hd_wallet import _register_pycoin_networks
    _register_pycoin_networks()
    network = network_for_netcode('htr')

    xpub = network.parse.bip32(xpub_str)
    if xpub is None:
        raise InvalidXPub(xpub_str)

    idx = first_index
    while True:
        key = xpub.subkey(idx)
        yield AddressItem(idx, AddressB58(key.address()))
        idx += 1


async def aiter_xpub_addresses(xpub: str, *, first_index: int = 0) -> AsyncIterator[AddressItem]:
    """An async iterator that yields addresses derived from an xpub."""
    it = iter_xpub_addresses(xpub, first_index=first_index)
    for item in it:
        yield item


AddressSearch: TypeAlias = AsyncIterator[AddressItem | VertexItem]


async def gap_limit_search(
    manager: HathorManager,
    address_iter: AsyncIterable[AddressItem],
    gap_limit: int
) -> AddressSearch:
    """An async iterator that yields addresses and vertices, stopping when the gap limit is reached.
    """
    assert manager.tx_storage.indexes.addresses is not None
    addresses_index = manager.tx_storage.indexes.addresses
    empty_addresses_counter = 0
    async for item in address_iter:
        yield item  # AddressItem

        vertex_counter = 0
        for vertex_id in addresses_index.get_sorted_from_address(item.address):
            tx = manager.tx_storage.get_transaction(vertex_id)
            yield VertexItem(tx)
            vertex_counter += 1

        if vertex_counter == 0:
            empty_addresses_counter += 1
            if empty_addresses_counter >= gap_limit:
                break
        else:
            empty_addresses_counter = 0
