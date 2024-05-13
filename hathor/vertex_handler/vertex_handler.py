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

import datetime

from structlog import get_logger
from twisted.internet.task import deferLater

from hathor.conf.settings import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.exception import HathorError, InvalidNewTransaction
from hathor.p2p.manager import ConnectionsManager
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol
from hathor.transaction import Block, Vertex
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.verification.verification_service import VerificationService
from hathor.wallet import BaseWallet

logger = get_logger()


class VertexHandler:
    __slots__ = (
        '_log',
        '_reactor',
        '_settings',
        '_tx_storage',
        '_verification_service',
        '_consensus',
        '_p2p_manager',
        '_pubsub',
        '_wallet',
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        verification_service: VerificationService,
        consensus: ConsensusAlgorithm,
        p2p_manager: ConnectionsManager,
        pubsub: PubSubManager,
        wallet: BaseWallet | None,
    ) -> None:
        self._log = logger.new()
        self._reactor = reactor
        self._settings = settings
        self._tx_storage = tx_storage
        self._verification_service = verification_service
        self._consensus = consensus
        self._p2p_manager = p2p_manager
        self._pubsub = pubsub
        self._wallet = wallet

    def on_new_vertex(
        self,
        vertex: Vertex,
        *,
        quiet: bool = False,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
        reject_locked_reward: bool = True,
        is_sync_v2: bool = False,
    ) -> bool:
        """Method for adding vertices (transactions or blocks) that steps the validation state machine, synchronously.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        :param fails_silently: if False will raise an exception when tx cannot be added
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        """
        if is_sync_v2:
            assert vertex.storage is None, 'sync-v2 should never set a storage in the vertex'

        is_pre_valid = self._pre_validate_vertex(vertex, fails_silently=fails_silently)
        if not is_pre_valid:
            return False

        is_valid = self._validate_vertex(
            vertex,
            fails_silently=fails_silently,
            reject_locked_reward=reject_locked_reward
        )
        if not is_valid:
            return False

        self._save_and_run_consensus(vertex)
        self._post_consensus(
            vertex,
            quiet=quiet,
            propagate_to_peers=propagate_to_peers,
            reject_locked_reward=reject_locked_reward
        )

        return True

    async def on_new_vertex_async(
        self,
        vertex: Vertex,
        *,
        quiet: bool = False,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
        reject_locked_reward: bool = True,
    ) -> bool:
        """Method for adding vertices (transactions or blocks) that steps the validation state machine, asynchronously.
        This is exactly the same method as `on_new_vertex()`, except it calls async verification.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        :param fails_silently: if False will raise an exception when tx cannot be added
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        """
        is_pre_valid = self._pre_validate_vertex(vertex, fails_silently=fails_silently)
        if not is_pre_valid:
            return False

        is_valid = await self._validate_vertex_async(
            vertex,
            fails_silently=fails_silently,
            reject_locked_reward=reject_locked_reward
        )
        if not is_valid:
            return False

        self._save_and_run_consensus(vertex)
        self._post_consensus(
            vertex,
            quiet=quiet,
            propagate_to_peers=propagate_to_peers,
            reject_locked_reward=reject_locked_reward
        )

        return True

    def _pre_validate_vertex(self, vertex: Vertex, *, fails_silently: bool) -> bool:
        assert self._tx_storage.is_only_valid_allowed()
        already_exists = False
        if self._tx_storage.transaction_exists(vertex.hash):
            self._tx_storage.compare_bytes_with_local_tx(vertex)
            already_exists = True

        if vertex.timestamp - self._reactor.seconds() > self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED:
            if not fails_silently:
                raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                    vertex.hash_hex, vertex.timestamp))
            self._log.warn('on_new_tx(): Ignoring transaction in the future', tx=vertex.hash_hex,
                           future_timestamp=vertex.timestamp)
            return False

        vertex.storage = self._tx_storage

        try:
            metadata = vertex.get_metadata()
        except TransactionDoesNotExist:
            if not fails_silently:
                raise InvalidNewTransaction('cannot get metadata')
            self._log.warn('on_new_tx(): cannot get metadata', tx=vertex.hash_hex)
            return False

        if already_exists and metadata.validation.is_fully_connected():
            if not fails_silently:
                raise InvalidNewTransaction('Transaction already exists {}'.format(vertex.hash_hex))
            self._log.warn('on_new_tx(): Transaction already exists', tx=vertex.hash_hex)
            return False

        if metadata.validation.is_invalid():
            if not fails_silently:
                raise InvalidNewTransaction('previously marked as invalid')
            self._log.warn('on_new_tx(): previously marked as invalid', tx=vertex.hash_hex)
            return False

        return True

    def _validate_vertex(self, vertex: Vertex, *, fails_silently: bool, reject_locked_reward: bool) -> bool:
        metadata = vertex.get_metadata()

        if not metadata.validation.is_fully_connected():
            try:
                self._verification_service.validate_full(vertex, reject_locked_reward=reject_locked_reward)
            except HathorError as e:
                if not fails_silently:
                    raise InvalidNewTransaction(f'full validation failed: {str(e)}') from e
                self._log.warn('on_new_tx(): full validation failed', tx=vertex.hash_hex, exc_info=True)
                return False

        return True

    async def _validate_vertex_async(
        self,
        vertex: Vertex,
        *,
        fails_silently: bool,
        reject_locked_reward: bool,
    ) -> bool:
        # TODO: This method simply calls synchronous verification, but it also releases the reactor loop. This is
        #  temporary, and soon this method will be changed to call verification on a separate process.
        await deferLater(self._reactor, 0, lambda: None)
        return self._validate_vertex(vertex, fails_silently=fails_silently, reject_locked_reward=reject_locked_reward)

    def _save_and_run_consensus(self, vertex: Vertex) -> None:
        # The method below adds the tx as a child of the parents
        # This needs to be called right before the save because we were adding the children
        # in the tx parents even if the tx was invalid (failing the verifications above)
        # then I would have a children that was not in the storage
        vertex.update_initial_metadata(save=False)
        self._tx_storage.save_transaction(vertex)
        self._tx_storage.add_to_indexes(vertex)
        self._consensus.update(vertex)

    def _post_consensus(
        self,
        vertex: Vertex,
        *,
        quiet: bool,
        propagate_to_peers: bool,
        reject_locked_reward: bool,
    ) -> None:
        """ Handle operations that need to happen once the tx becomes fully validated.

        This might happen immediately after we receive the tx, if we have all dependencies
        already. Or it might happen later.
        """
        assert self._tx_storage.indexes is not None
        assert self._verification_service.validate_full(
            vertex,
            skip_block_weight_verification=True,
            reject_locked_reward=reject_locked_reward
        )
        self._tx_storage.indexes.update(vertex)
        if self._tx_storage.indexes.mempool_tips:
            self._tx_storage.indexes.mempool_tips.update(vertex)  # XXX: move to indexes.update

        # Publish to pubsub manager the new tx accepted, now that it's full validated
        self._pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=vertex)

        if self._tx_storage.indexes.mempool_tips:
            self._tx_storage.indexes.mempool_tips.update(vertex)

        if self._wallet:
            # TODO Remove it and use pubsub instead.
            self._wallet.on_new_tx(vertex)

        self._log_new_object(vertex, 'new {}', quiet=quiet)
        self._log_feature_states(vertex)

        if propagate_to_peers:
            # Propagate to our peers.
            self._p2p_manager.send_tx_to_peers(vertex)

    def _log_new_object(self, tx: Vertex, message_fmt: str, *, quiet: bool) -> None:
        """ A shortcut for logging additional information for block/txs.
        """
        metadata = tx.get_metadata()
        now = datetime.datetime.fromtimestamp(self._reactor.seconds())
        kwargs = {
            'tx': tx,
            'ts_date': datetime.datetime.fromtimestamp(tx.timestamp),
            'time_from_now': tx.get_time_from_now(now),
            'validation': metadata.validation.name,
        }
        if tx.is_block:
            message = message_fmt.format('block')
            if isinstance(tx, Block):
                kwargs['height'] = tx.get_height()
        else:
            message = message_fmt.format('tx')
        if not quiet:
            log_func = self._log.info
        else:
            log_func = self._log.debug
        log_func(message, **kwargs)

    def _log_feature_states(self, vertex: Vertex) -> None:
        """Log features states for a block. Used as part of the Feature Activation Phased Testing."""
        if not isinstance(vertex, Block):
            return

        feature_infos = vertex.static_metadata.get_feature_infos(self._settings)
        state_by_feature = {
            feature.value: feature_info.state.value
            for feature, feature_info in feature_infos.items()
        }

        self._log.info(
            'New block accepted with feature activation states',
            block_hash=vertex.hash_hex,
            block_height=vertex.get_height(),
            features_states=state_by_feature
        )
        self._log_active_features(vertex)

    def _log_active_features(self, block: Block) -> None:
        """Log ACTIVE features for a block. Used as part of the Feature Activation Phased Testing."""
        if not self._settings.NETWORK_NAME == 'mainnet':
            # We're currently only performing phased testing on mainnet, so we won't log in other networks.
            return

        for feature in self._settings.FEATURE_ACTIVATION.features:
            if block.static_metadata.is_feature_active(feature):
                self._log.info(
                    'Feature is ACTIVE for block',
                    feature=feature.value,
                    block_hash=block.hash_hex,
                    block_height=block.get_height()
                )
