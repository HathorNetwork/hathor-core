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

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from structlog import get_logger
from twisted.internet.task import deferLater

from hathor.nanocontracts.storage.block_storage import ContractKey
from hathor.nanocontracts.storage.patricia_trie import NodeId
from hathor.nanocontracts.types import ContractId
from hathor.p2p.states import ReadyState
from hathor.transaction import Block

if TYPE_CHECKING:
    from hathor.p2p.manager import ConnectionsManager
    from hathor.reactor import ReactorProtocol as Reactor
    from hathor.transaction.storage import TransactionStorage
    from hathorlib.nanocontracts.storage.factory import NCStorageFactory

_GET_READY_DELAY_SECS: float = 1.0
_MAX_GET_READY_RETRIES: int = 5

logger = get_logger()


class NCSyncChecker:
    """Compares the local NC state trie root with a connected peer's for each processed block.

    This check is peer-independent: it picks any available connected peer to query,
    and runs once per block regardless of which sync path delivered it.
    """

    __slots__ = (
        '_log',
        '_reactor',
        '_tx_storage',
        '_p2p_manager',
        '_nc_storage_factory',
        '_start_height',
        '_found_incompatible',
    )

    def __init__(
        self,
        *,
        reactor: Reactor,
        tx_storage: TransactionStorage,
        p2p_manager: ConnectionsManager,
        nc_storage_factory: NCStorageFactory,
        start_height: int,
    ) -> None:
        self._log = logger.new()
        self._reactor = reactor
        self._tx_storage = tx_storage
        self._p2p_manager = p2p_manager
        self._nc_storage_factory = nc_storage_factory
        self._start_height = start_height
        self._found_incompatible: bool = False

    async def check_block(self, block: Block) -> None:
        """Compare our NC state trie root with a peer's for this block.

        If the roots differ, iterate the block's NC transactions to identify which contracts diverged.
        """
        if self._found_incompatible:
            # We only check the first incompatible block we find, then stop the full node.
            return

        if block.get_height() < self._start_height:
            # We're not interest in checking this height.
            return

        my_root_id = block.get_metadata().nc_block_root_id
        if my_root_id is None:
            # This block doesn't have nano state.
            return

        ready_state = await self._get_ready_state()
        peer_root_id = await ready_state.send_get_block_nc_root_id(block.hash)

        if self._found_incompatible:
            # Another concurrent check_block set this while we were awaiting.
            return

        if peer_root_id == my_root_id:
            ready_state.log.debug('compatible block state', block=block.hash_hex, height=block.get_height())
            return

        self._found_incompatible = True
        ready_state.log.error(
            'incompatible block state',
            block=block.hash_hex,
            my_root=my_root_id.hex(),
            peer_root=peer_root_id.hex(),
            height=block.get_height(),
        )

        block_storage = self._nc_storage_factory.get_block_storage(my_root_id)
        checked_contracts: set[ContractId] = set()

        # TODO: Future improvement - this is not the order of execution, which would be better.
        for tx in block.iter_transactions_in_this_block():
            if not tx.is_nano_contract():
                continue

            contract_id = tx.get_nano_header().get_contract_id()
            if contract_id in checked_contracts:
                continue

            checked_contracts.add(contract_id)

            try:
                my_contract_root = block_storage.get_contract_root_id(contract_id)
            except KeyError:
                # The contract might not exist in our block trie if the tx execution was skipped or failed.
                my_contract_root = None

            peer_contract_root = await self._get_peer_contract_root(ready_state, peer_root_id, contract_id)
            if my_contract_root != peer_contract_root:
                ready_state.log.error(
                    'incompatible contract state',
                    tx=tx.hash_hex,
                    contract_id=contract_id.hex(),
                    my_root=my_contract_root.hex() if my_contract_root else None,
                    peer_root=peer_contract_root.hex() if peer_contract_root else None,
                )
                continue

        ready_state.log.error('stopping node due to incompatible NC state')
        try:
            self._reactor.stop()
        except Exception:
            pass

    @staticmethod
    async def _get_peer_contract_root(
        state: ReadyState,
        peer_block_root_id: NodeId,
        contract_id: ContractId,
    ) -> bytes | None:
        """Walk the peer's block Patricia trie to find a specific contract's root_id.

        This method traverses from the trie root, following child nodes whose key is a prefix
        of the remaining suffix, until it finds the target key or determines it doesn't exist.
        It's analogous to `PatriciaTrie._find_nearest_node` but adapted for async and using JSON
        data instead of typed `Node`s.
        """
        raw_key = bytes(ContractKey(contract_id))
        target_key = raw_key.hex().encode('ascii')
        node_data: dict[str, Any] = await state.send_get_nc_db_node(peer_block_root_id)

        while True:
            current_key = bytes.fromhex(node_data['key'])
            if current_key == target_key:
                if content := node_data.get('content'):
                    return bytes.fromhex(content)
                return None

            if not target_key.startswith(current_key):
                return None

            suffix = target_key[len(current_key):]
            children = node_data.get('children', {})

            found = False
            for child_key_hex, child_id_hex in children.items():
                child_key = bytes.fromhex(child_key_hex)
                if suffix.startswith(child_key):
                    child_id = NodeId(bytes.fromhex(child_id_hex))
                    node_data = await state.send_get_nc_db_node(child_id)
                    found = True
                    break

            if not found:
                return None

    async def _get_ready_state(self, *, retries: int = 0) -> ReadyState:
        """Pick any connected peer in ReadyState that isn't busy with a pending NC check."""
        if retries > _MAX_GET_READY_RETRIES:
            msg = 'could not get ready peer'
            self._log.error(msg, retries=retries)
            raise Exception(msg)

        for conn in self._p2p_manager.iter_ready_connections():
            if not isinstance(conn.state, ReadyState):
                continue
            return conn.state

        # There are no ready connections available, wait and try again.
        await deferLater(self._reactor, _GET_READY_DELAY_SECS, lambda: None)
        return await self._get_ready_state(retries=retries + 1)
