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

from hathor.conf.settings import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.exception import HathorError, InvalidNewTransaction
from hathor.p2p.manager import ConnectionsManager
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol
from hathor.transaction import BaseTransaction, Block
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
        '_log_vertex_bytes',
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
        log_vertex_bytes: bool = False,
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
        self._log_vertex_bytes = log_vertex_bytes

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

    def _validate_vertex(
        self,
        vertex: BaseTransaction,
        *,
        fails_silently: bool,
        reject_locked_reward: bool,
    ) -> bool:
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

        if not metadata.validation.is_fully_connected():
            try:
                self._verification_service.validate_full(vertex, reject_locked_reward=reject_locked_reward)
            except HathorError as e:
                if not fails_silently:
                    raise InvalidNewTransaction(f'full validation failed: {str(e)}') from e
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

    def _post_consensus(
        self,
        vertex: BaseTransaction,
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
            reject_locked_reward=reject_locked_reward,
            init_static_metadata=False,
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

        if propagate_to_peers:
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
        if self._log_vertex_bytes:
            kwargs['bytes'] = bytes(tx).hex()
        if tx.is_block:
            message = message_fmt.format('block')
            if isinstance(tx, Block):
                feature_infos = tx.static_metadata.get_feature_infos(self._settings)
                feature_states = {
                    feature.value: info.state.value
                    for feature, info in feature_infos.items()
                }
                kwargs['_height'] = tx.get_height()
                kwargs['feature_states'] = feature_states
        else:
            message = message_fmt.format('tx')
        if not quiet:
            log_func = self._log.info
        else:
            log_func = self._log.debug
        log_func(message, **kwargs)
