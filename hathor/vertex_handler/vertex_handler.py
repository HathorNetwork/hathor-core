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
from dataclasses import replace
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
        parent_block_hash = block.get_block_parent_hash()
        parent_block = self._tx_storage.get_block(parent_block_hash)

        enable_checkdatasig_count = self._feature_service.is_feature_active(
            vertex=parent_block,
            feature=Feature.COUNT_CHECKDATASIG_OP
        )
        params = VerificationParams(enable_checkdatasig_count=enable_checkdatasig_count)

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
        params = VerificationParams.default_for_mempool()
        return self._old_on_new_vertex(tx, params)

    @cpu.profiler('on_new_relayed_vertex')
    def on_new_relayed_vertex(
        self,
        vertex: BaseTransaction,
        *,
        quiet: bool = False,
    ) -> bool:
        # XXX: checkdatasig enabled for relayed vertices
        params = VerificationParams.default_for_mempool()
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
            self._unsafe_save_and_run_consensus(vertex)
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

    def _unsafe_save_and_run_consensus(self, vertex: BaseTransaction) -> None:
        """
        This method is considered unsafe because the caller is responsible for crashing the full node
        if this method throws any exception.
        """
        # The method below adds the tx as a child of the parents
        # This needs to be called right before the save because we were adding the children
        # in the tx parents even if the tx was invalid (failing the verifications above)
        # then I would have a children that was not in the storage
        vertex.update_initial_metadata(save=False)
        self._tx_storage.save_transaction(vertex)
        self._tx_storage.add_to_indexes(vertex)
        self._consensus.unsafe_update(vertex)

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
        # XXX: during post consensus we don't need to verify weights again, so we can disable it
        params = replace(params, skip_block_weight_verification=True)
        assert self._tx_storage.indexes is not None
        assert self._verification_service.validate_full(
            vertex,
            params,
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
