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
from dataclasses import dataclass

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.exception import HathorError, InvalidNewTransaction
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.p2p.manager import ConnectionsManager
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol
from hathor.transaction import BaseTransaction, Block
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import not_none
from hathor.verification.parallel_verifier import ParallelVerifier
from hathor.verification.verification_service import VerificationService
from hathor.wallet import BaseWallet

logger = get_logger()


@dataclass(kw_only=True, slots=True, frozen=True)
class _NewVertex:
    vertex: BaseTransaction
    quiet: bool
    fails_silently: bool
    propagate_to_peers: bool
    reject_locked_reward: bool


class VertexHandler:
    __slots__ = (
        '_log',
        '_reactor',
        '_settings',
        '_tx_storage',
        '_verification_service',
        '_consensus',
        '_p2p_manager',
        '_feature_service',
        '_pubsub',
        '_wallet',
        '_verifier',
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
        feature_service: FeatureService,
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
        self._feature_service = feature_service
        self._pubsub = pubsub
        self._wallet = wallet
        self._verifier = ParallelVerifier(
            verification_service=self._verification_service,
            tx_storage=tx_storage,
            daa=not_none(DifficultyAdjustmentAlgorithm.singleton)
        )

    def on_new_vertex(
        self,
        vertex: BaseTransaction,
        *,
        quiet: bool = False,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
        reject_locked_reward: bool = True,
    ) -> bool:
        """ New method for adding transactions or blocks that steps the validation state machine.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        :param fails_silently: if False will raise an exception when tx cannot be added
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        """
        new_vertex = _NewVertex(
            vertex=vertex,
            quiet=quiet,
            fails_silently=fails_silently,
            propagate_to_peers=propagate_to_peers,
            reject_locked_reward=reject_locked_reward,
        )
        is_pre_valid = self._pre_validate_vertex(new_vertex)
        if not is_pre_valid:
            return False

        is_valid = self._validate_vertex(new_vertex)
        if not is_valid:
            return False

        self._save_and_run_consensus(vertex)
        self._post_consensus(new_vertex)

        return True

    async def on_new_vertex_async(
        self,
        vertex: BaseTransaction,
        *,
        quiet: bool = False,
        fails_silently: bool = True,
        propagate_to_peers: bool = True,
        reject_locked_reward: bool = True,
    ) -> bool:
        """ New method for adding transactions or blocks that steps the validation state machine.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        :param fails_silently: if False will raise an exception when tx cannot be added
        :param propagate_to_peers: if True will relay the tx to other peers if it is accepted
        """
        new_vertex = _NewVertex(
            vertex=vertex,
            quiet=quiet,
            fails_silently=fails_silently,
            propagate_to_peers=propagate_to_peers,
            reject_locked_reward=reject_locked_reward,
        )
        is_pre_valid = self._pre_validate_vertex(new_vertex)
        if not is_pre_valid:
            return False

        is_valid = await self._validate_vertex_async(new_vertex)
        if not is_valid:
            return False

        self._save_and_run_consensus(new_vertex.vertex)
        self._post_consensus(new_vertex)

        return True

    def _pre_validate_vertex(self, new_vertex: _NewVertex) -> bool:
        assert self._tx_storage.is_only_valid_allowed()
        already_exists = False
        vertex = new_vertex.vertex
        if self._tx_storage.transaction_exists(vertex.hash):
            self._tx_storage.compare_bytes_with_local_tx(vertex)
            already_exists = True

        if vertex.timestamp - self._reactor.seconds() > self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED:
            if not new_vertex.fails_silently:
                raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                    vertex.hash_hex, vertex.timestamp))
            self._log.warn('on_new_tx(): Ignoring transaction in the future', tx=vertex.hash_hex,
                           future_timestamp=vertex.timestamp)
            return False

        vertex.storage = self._tx_storage

        if already_exists:
            try:
                metadata = vertex.get_metadata()
            except TransactionDoesNotExist:
                if not new_vertex.fails_silently:
                    raise InvalidNewTransaction('cannot get metadata')
                self._log.warn('on_new_tx(): cannot get metadata', tx=vertex.hash_hex)
                return False

            if metadata.validation.is_fully_connected():
                if not new_vertex.fails_silently:
                    raise InvalidNewTransaction('Transaction already exists {}'.format(vertex.hash_hex))
                self._log.warn('on_new_tx(): Transaction already exists', tx=vertex.hash_hex)
                return False

            if metadata.validation.is_invalid():
                if not new_vertex.fails_silently:
                    raise InvalidNewTransaction('previously marked as invalid')
                self._log.warn('on_new_tx(): previously marked as invalid', tx=vertex.hash_hex)
                return False

        return True

    def _validate_vertex(self, new_vertex: _NewVertex) -> bool:
        vertex = new_vertex.vertex
        metadata = vertex.get_metadata()

        if not metadata.validation.is_fully_connected():
            try:
                self._verification_service.validate_full(vertex, reject_locked_reward=new_vertex.reject_locked_reward)
            except HathorError as e:
                if not new_vertex.fails_silently:
                    raise InvalidNewTransaction('full validation failed') from e
                self._log.warn('on_new_tx(): full validation failed', tx=vertex.hash_hex, exc_info=True)
                return False

        return True

    async def _validate_vertex_async(self, new_vertex: _NewVertex) -> bool:
        vertex = new_vertex.vertex
        try:
            metadata = vertex.get_metadata()
        except TransactionDoesNotExist:
            metadata = None

        if not metadata or not metadata.validation.is_fully_connected():
            try:
                await self._verifier.validate_full(vertex, reject_locked_reward=new_vertex.reject_locked_reward)
            except HathorError as e:
                if not new_vertex.fails_silently:
                    raise InvalidNewTransaction('full validation failed') from e
                self._log.warn('on_new_tx(): full validation failed', tx=vertex.hash_hex, exc_info=True)
                return False

        return True

    def _save_and_run_consensus(self, vertex: BaseTransaction) -> None:
        # The method below adds the tx as a child of the parents
        # This needs to be called right before the save because we were adding the children
        # in the tx parents even if the tx was invalid (failing the verifications above)
        # then I would have a children that was not in the storage
        vertex.update_initial_metadata(save=False)
        self._tx_storage.save_transaction(vertex)
        self._tx_storage.add_to_indexes(vertex)
        self._consensus.update(vertex)

    def _post_consensus(self, new_vertex: _NewVertex) -> None:
        """ Handle operations that need to happen once the tx becomes fully validated.

        This might happen immediately after we receive the tx, if we have all dependencies
        already. Or it might happen later.
        """
        vertex = new_vertex.vertex
        assert self._tx_storage.indexes is not None
        assert self._verification_service.validate_full(
            vertex,
            skip_block_weight_verification=True,
            reject_locked_reward=new_vertex.reject_locked_reward
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

        self._log_new_object(vertex, 'new {}', quiet=new_vertex.quiet)
        self._log_feature_states(vertex)

        if new_vertex.propagate_to_peers:
            # Propagate to our peers.
            self._p2p_manager.send_tx_to_peers(vertex)

    def _log_new_object(self, tx: BaseTransaction, message_fmt: str, *, quiet: bool) -> None:
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

    def _log_feature_states(self, vertex: BaseTransaction) -> None:
        """Log features states for a block. Used as part of the Feature Activation Phased Testing."""
        if not isinstance(vertex, Block):
            return

        feature_descriptions = self._feature_service.get_feature_info(block=vertex)
        state_by_feature = {
            feature.value: description.state.value
            for feature, description in feature_descriptions.items()
        }

        self._log.info(
            'New block accepted with feature activation states',
            block_hash=vertex.hash_hex,
            block_height=vertex.get_height(),
            features_states=state_by_feature
        )

        features = [Feature.NOP_FEATURE_1, Feature.NOP_FEATURE_2]
        for feature in features:
            self._log_if_feature_is_active(vertex, feature)

    def _log_if_feature_is_active(self, block: Block, feature: Feature) -> None:
        """Log if a feature is ACTIVE for a block. Used as part of the Feature Activation Phased Testing."""
        if self._feature_service.is_feature_active(block=block, feature=feature):
            self._log.info(
                'Feature is ACTIVE for block',
                feature=feature.value,
                block_hash=block.hash_hex,
                block_height=block.get_height()
            )
