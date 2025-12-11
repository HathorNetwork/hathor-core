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
from typing import Any, Generator

from structlog import get_logger
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater

from hathor.conf.settings import HathorSettings
from hathor.consensus import ConsensusAlgorithm
from hathor.exception import HathorError, InvalidNewTransaction
from hathor.execution_manager import ExecutionManager
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.nanocontracts.utils import is_nano_active
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import HathorEvents, PubSubManager
from hathor.reactor import ReactorProtocol
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.verification.verification_params import VerificationParams
from hathor.verification.verification_service import VerificationService
from hathor.wallet import BaseWallet

logger = get_logger()
cpu = get_cpu_profiler()


class VertexHandler:
    __slots__ = (
        '_log',
        '_reactor',
        '_settings',
        '_tx_storage',
        '_verification_service',
        '_consensus',
        '_feature_service',
        '_pubsub',
        '_execution_manager',
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
        feature_service: FeatureService,
        pubsub: PubSubManager,
        execution_manager: ExecutionManager,
        wallet: BaseWallet | None,
        log_vertex_bytes: bool = False,
    ) -> None:
        self._log = logger.new()
        self._reactor = reactor
        self._settings = settings
        self._tx_storage = tx_storage
        self._verification_service = verification_service
        self._consensus = consensus
        self._feature_service = feature_service
        self._pubsub = pubsub
        self._execution_manager = execution_manager
        self._wallet = wallet
        self._log_vertex_bytes = log_vertex_bytes

    @cpu.profiler('on_new_block')
    @inlineCallbacks
    def on_new_block(self, block: Block, *, deps: list[Transaction]) -> Generator[Any, Any, bool]:
        """Called by block sync."""
        parent_block_hash = block.get_block_parent_hash()
        parent_block = self._tx_storage.get_block(parent_block_hash)
        parent_meta = parent_block.get_metadata()

        enable_checkdatasig_count = self._feature_service.is_feature_active(
            vertex=parent_block,
            feature=Feature.COUNT_CHECKDATASIG_OP,
        )

        enable_nano = is_nano_active(
            settings=self._settings, block=parent_block, feature_service=self._feature_service
        )

        if parent_meta.nc_block_root_id is None:
            # This case only happens for the genesis and during sync of a voided chain.
            assert parent_block.is_genesis or parent_meta.voided_by

        params = VerificationParams(
            enable_checkdatasig_count=enable_checkdatasig_count,
            enable_nano=enable_nano,
            nc_block_root_id=parent_meta.nc_block_root_id,
        )

        for tx in deps:
            if not self._tx_storage.transaction_exists(tx.hash):
                if not self._old_on_new_vertex(tx, params):
                    return False
                yield deferLater(self._reactor, 0, lambda: None)

        if not self._tx_storage.transaction_exists(block.hash):
            if not self._old_on_new_vertex(block, params):
                return False

        return True

    @cpu.profiler('on_new_mempool_transaction')
    def on_new_mempool_transaction(self, tx: Transaction) -> bool:
        """Called by mempool sync."""
        best_block = self._tx_storage.get_best_block()
        enable_nano = is_nano_active(settings=self._settings, block=best_block, feature_service=self._feature_service)
        params = VerificationParams.default_for_mempool(
            enable_nano=enable_nano,
            best_block=best_block,
        )
        return self._old_on_new_vertex(tx, params)

    @cpu.profiler('on_new_relayed_vertex')
    def on_new_relayed_vertex(
        self,
        vertex: BaseTransaction,
        *,
        quiet: bool = False,
        reject_locked_reward: bool = True,
    ) -> bool:
        """Called for unsolicited vertex received, usually due to real time relay."""
        best_block = self._tx_storage.get_best_block()
        best_block_meta = best_block.get_metadata()
        enable_nano = is_nano_active(settings=self._settings, block=best_block, feature_service=self._feature_service)
        if best_block_meta.nc_block_root_id is None:
            assert best_block.is_genesis
        # XXX: checkdatasig enabled for relayed vertices
        params = VerificationParams(
            enable_checkdatasig_count=True,
            reject_locked_reward=reject_locked_reward,
            enable_nano=enable_nano,
            nc_block_root_id=best_block_meta.nc_block_root_id,
        )
        return self._old_on_new_vertex(vertex, params, quiet=quiet)

    @cpu.profiler('_old_on_new_vertex')
    def _old_on_new_vertex(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
        *,
        quiet: bool = False,
    ) -> bool:
        """ New method for adding transactions or blocks that steps the validation state machine.

        :param vertex: transaction to be added
        :param quiet: if True will not log when a new tx is accepted
        """
        is_valid = self._validate_vertex(vertex, params)

        if not is_valid:
            return False

        try:
            self._consensus.unsafe_update(vertex)
            self._post_consensus(vertex, params, quiet=quiet)
        except BaseException:
            self._log.error('unexpected exception in on_new_vertex()', vertex=vertex)
            meta = vertex.get_metadata()
            meta.add_voided_by(self._settings.CONSENSUS_FAIL_ID)
            self._tx_storage.save_transaction(vertex, only_metadata=True)
            self._execution_manager.crash_and_exit(reason=f'on_new_vertex() failed for tx {vertex.hash_hex}')

        return True

    def _validate_vertex(self, vertex: BaseTransaction, params: VerificationParams) -> bool:
        assert self._tx_storage.is_only_valid_allowed()
        already_exists = False
        if self._tx_storage.transaction_exists(vertex.hash):
            self._tx_storage.compare_bytes_with_local_tx(vertex)
            already_exists = True

        if vertex.timestamp - self._reactor.seconds() > self._settings.MAX_FUTURE_TIMESTAMP_ALLOWED:
            raise InvalidNewTransaction('Ignoring transaction in the future {} (timestamp={})'.format(
                vertex.hash_hex, vertex.timestamp))

        vertex.storage = self._tx_storage

        try:
            metadata = vertex.get_metadata()
        except TransactionDoesNotExist:
            raise InvalidNewTransaction('cannot get metadata')

        if already_exists and metadata.validation.is_fully_connected():
            raise InvalidNewTransaction('Transaction already exists {}'.format(vertex.hash_hex))

        if metadata.validation.is_invalid():
            raise InvalidNewTransaction('previously marked as invalid')

        if not metadata.validation.is_fully_connected():
            try:
                self._verification_service.validate_full(vertex, params)
            except HathorError as e:
                raise InvalidNewTransaction(f'full validation failed: {str(e)}') from e

        return True

    def _post_consensus(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
        *,
        quiet: bool,
    ) -> None:
        """ Handle operations that need to happen once the tx becomes fully validated.

        This might happen immediately after we receive the tx, if we have all dependencies
        already. Or it might happen later.
        """
        meta = vertex.get_metadata()
        assert meta.validation.is_fully_connected()

        # Publish to pubsub manager the new tx accepted, now that it's full validated
        self._pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=vertex)

        if self._wallet:
            # TODO Remove it and use pubsub instead.
            self._wallet.on_new_tx(vertex)

        self._log_new_object(vertex, 'new {}', quiet=quiet)

    def _log_new_object(self, tx: BaseTransaction, message_fmt: str, *, quiet: bool) -> None:
        """ A shortcut for logging additional information for block/txs.
        """
        metadata = tx.get_metadata()
        now = datetime.datetime.fromtimestamp(self._reactor.seconds())
        feature_states = self._feature_service.get_feature_states(vertex=tx)
        kwargs = {
            'tx': tx,
            'ts_date': datetime.datetime.fromtimestamp(tx.timestamp),
            'time_from_now': tx.get_time_from_now(now),
            'validation': metadata.validation.name,
            'feature_states': {
                feature.value: state.value
                for feature, state in feature_states.items()
            }
        }
        if self._log_vertex_bytes:
            kwargs['bytes'] = bytes(tx).hex()
        if isinstance(tx, Block):
            if not metadata.voided_by:
                message = message_fmt.format('block')
            else:
                message = message_fmt.format('voided block')
            kwargs['_height'] = tx.get_height()
            kwargs['_score'] = tx.get_metadata().score
        else:
            if not metadata.voided_by:
                message = message_fmt.format('tx')
            else:
                message = message_fmt.format('voided tx')
        if not quiet:
            log_func = self._log.info
        else:
            log_func = self._log.debug

        if tx.name:
            kwargs['__name'] = tx.name
        log_func(message, **kwargs)
