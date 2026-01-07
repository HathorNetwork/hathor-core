#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING

from structlog import get_logger
from twisted.internet.interfaces import IDelayedCall
from twisted.internet.task import LoopingCall

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.pubsub import EventArguments, HathorEvents
from hathor.reactor import ReactorProtocol
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.consensus.poa import PoaSigner
    from hathor.manager import HathorManager
    from hathor.transaction import Block
    from hathor.transaction.poa import PoaBlock

logger = get_logger()

# Number of seconds used between each signer depending on its distance to the expected signer
_SIGNER_TURN_INTERVAL: int = 10


class PoaBlockProducer:
    """
    This class is analogous to mining classes, but for Proof-of-Authority networks.
    It waits for blocks to arrive, gets templates, and propagates new blocks accordingly.
    """
    __slots__ = (
        '_log',
        '_settings',
        '_poa_settings',
        '_reactor',
        '_manager',
        '_poa_signer',
        '_last_seen_best_block',
        '_delayed_call',
        '_start_producing_lc',
    )

    def __init__(self, *, settings: HathorSettings, reactor: ReactorProtocol, poa_signer: PoaSigner) -> None:
        assert isinstance(settings.CONSENSUS_ALGORITHM, PoaSettings)
        self._log = logger.new()
        self._settings = settings
        self._poa_settings = settings.CONSENSUS_ALGORITHM
        self._reactor = reactor
        self._manager: HathorManager | None = None
        self._poa_signer = poa_signer
        self._last_seen_best_block: Block | None = None
        self._delayed_call: IDelayedCall | None = None
        self._start_producing_lc: LoopingCall = LoopingCall(self._safe_start_producing)
        self._start_producing_lc.clock = self._reactor

    @property
    def manager(self) -> HathorManager:
        assert self._manager is not None
        return self._manager

    @manager.setter
    def manager(self, manager: HathorManager) -> None:
        self._manager = manager

    def start(self) -> None:
        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self._on_new_vertex)
        self._start_producing_lc.start(self._settings.AVG_TIME_BETWEEN_BLOCKS)

    def stop(self) -> None:
        self.manager.pubsub.unsubscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self._on_new_vertex)

        if self._delayed_call and self._delayed_call.active():
            self._delayed_call.cancel()

        if self._start_producing_lc.running:
            self._start_producing_lc.stop()

    def _get_signer_index(self, previous_block: Block) -> int | None:
        """Return our signer index considering the active signers."""
        height = previous_block.get_height() + 1
        public_key = self._poa_signer.get_public_key()
        public_key_bytes = get_public_key_bytes_compressed(public_key)
        active_signers = poa.get_active_signers(self._poa_settings, height)
        try:
            return active_signers.index(public_key_bytes)
        except ValueError:
            return None

    def _safe_start_producing(self) -> None:
        try:
            return self._unsafe_start_producing()
        except Exception:
            self._log.exception('error while trying to start block production')

    def _unsafe_start_producing(self) -> None:
        """Start producing new blocks."""
        if not self.manager.can_start_mining():
            # We're syncing, so we'll try again later
            self._log.warn('cannot start producing new blocks, node not synced')
            return

        self._log.info('started producing new blocks')
        self._schedule_block()

    def _on_new_vertex(self, event: HathorEvents, args: EventArguments) -> None:
        """Handle propagation of new blocks after a vertex is received."""
        assert event == HathorEvents.NETWORK_NEW_TX_ACCEPTED
        block = args.tx

        from hathor.transaction import Block
        if not isinstance(block, Block):
            return

        from hathor.transaction.poa import PoaBlock
        if isinstance(block, PoaBlock) and not block.weight == poa.BLOCK_WEIGHT_IN_TURN:
            self._log.info('received out of turn block', block=block.hash_hex, signer_id=block.signer_id)

        self._schedule_block()

    def _schedule_block(self) -> None:
        """Schedule propagation of a new block."""
        if not self.manager.can_start_mining():
            # We're syncing, so we'll try again later
            self._log.info('cannot produce new block, node not synced')
            return

        if self._start_producing_lc.running:
            self._start_producing_lc.stop()

        previous_block = self.manager.tx_storage.get_best_block()
        if previous_block == self._last_seen_best_block:
            return

        self._last_seen_best_block = previous_block
        signer_index = self._get_signer_index(previous_block)
        if signer_index is None:
            return

        now = self._reactor.seconds()
        expected_timestamp = self._expected_block_timestamp(previous_block, signer_index)
        propagation_delay = 0 if expected_timestamp < now else expected_timestamp - now

        if self._delayed_call and self._delayed_call.active():
            self._delayed_call.cancel()

        self._delayed_call = self._reactor.callLater(propagation_delay, self._produce_block, previous_block)

        self._log.debug(
            'scheduling block production',
            previous_block=previous_block.hash_hex,
            previous_block_height=previous_block.get_height(),
            delay=propagation_delay,
        )

    def _produce_block(self, previous_block: PoaBlock) -> None:
        """Create and propagate a new block."""
        from hathor.transaction.poa import PoaBlock
        block_templates = self.manager.get_block_templates(parent_block_hash=previous_block.hash)
        block = block_templates.generate_mining_block(self.manager.rng, cls=PoaBlock)
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)
        assert isinstance(block, PoaBlock)

        if block.get_height() <= self.manager.tx_storage.get_height_best_block():
            return

        signer_index = self._get_signer_index(previous_block)
        block.weight = poa.calculate_weight(self._poa_settings, block, not_none(signer_index))
        block._static_metadata = None
        block.init_static_metadata_from_storage(self._settings, self.manager.tx_storage)

        self._poa_signer.sign_block(block)
        block.update_hash()

        self._log.info(
            'produced new block',
            block=block.hash_hex,
            height=block.get_height(),
            weight=block.weight,
            parent=block.get_block_parent_hash().hex(),
            voided=bool(block.get_metadata().voided_by),
        )
        self.manager.on_new_tx(block, propagate_to_peers=True)

    def _expected_block_timestamp(self, previous_block: Block, signer_index: int) -> int:
        """Calculate the expected timestamp for a new block."""
        height = previous_block.get_height() + 1
        index_distance = poa.get_signer_index_distance(
            settings=self._poa_settings,
            signer_index=signer_index,
            height=height,
        )
        delay = _SIGNER_TURN_INTERVAL * index_distance
        if index_distance > 0:
            # if it's not our turn, we add a constant offset to the delay
            delay += self._settings.AVG_TIME_BETWEEN_BLOCKS
        return previous_block.timestamp + self._settings.AVG_TIME_BETWEEN_BLOCKS + delay
