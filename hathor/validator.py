from abc import ABC, abstractmethod

from math import log

from twisted.logger import Logger

from hathor import protos
from hathor.grpc_util import StubConnect, convert_grpc_exceptions, convert_hathor_exceptions
from hathor.constants import TOKENS_PER_BLOCK, DECIMAL_PLACES, MIN_WEIGHT
from hathor.transaction import tx_or_block_from_proto
from hathor.transaction.exceptions import TxValidationError
from hathor.transaction import sum_weights
from hathor.remote_clock import RemoteClockServicer, RemoteClockFactory
from hathor.mp_util import Process, Queue


class IValidator(ABC):
    @abstractmethod
    def validate_new_tx(self, tx):
        raise NotImplementedError

    @abstractmethod
    def minimum_tx_weight(self, tx):
        """ Returns the minimum weight for the param tx

        The minimum is calculated by the following function:

        w = log(size, 2) + log(amount, 2) + 0.5

        :param tx: tx to calculate the minimum weight
        :type tx: :py:class:`hathor.transaction.transaction.Transaction`

        :return: minimum weight for the tx
        :rtype: float
        """
        raise NotImplementedError

    @abstractmethod
    def calculate_block_difficulty(self, block):
        """ Calculate block difficulty according to the ascendents of `block`.

        The new difficulty is calculated so that the average time between blocks will be
        `self.avg_time_between_blocks`. If the measured time between blocks is smaller than the target,
        the weight increases. If it is higher than the target, the weight decreases.

        The new difficulty cannot be smaller than `self.min_block_weight`.
        """
        raise NotImplementedError


class Validator(IValidator):
    log = Logger()

    def __init__(self, tx_storage, *, clock, test_mode=False):
        self.clock = clock
        self.tx_storage = tx_storage

        self.avg_time_between_blocks = 64  # in seconds  # XXX: move to hathor.constants?
        self.min_block_weight = MIN_WEIGHT
        self.tokens_issued_per_block = TOKENS_PER_BLOCK * (10**DECIMAL_PLACES)
        self.max_future_timestamp_allowed = 3600  # in seconds  # XXX: move to hathor.constants?

        # Multiplier coefficient to adjust the minimum weight of a normal tx to 18
        self.min_tx_weight_coefficient = 1.6

        # When manager is in test mode we exclude some verifications
        self.test_mode = test_mode

    def validate_new_tx(self, tx):
        if tx.is_genesis:
            return True

        if tx.timestamp - self.clock.seconds() > self.max_future_timestamp_allowed:
            self.log.debug('validate_new_tx(): Ignoring transaction in the future {}'.format(tx.hash.hex()))
            return False

        try:
            tx.verify()
        except TxValidationError as e:
            self.log.debug('validate_new_tx(): Error verifying transaction {} tx={}'.format(repr(e), tx.hash.hex()))
            return False

        if tx.is_block:
            # Validate minimum block difficulty
            block_weight = self.calculate_block_difficulty(tx)
            if tx.weight < block_weight:
                self.log.debug('Invalid new block {}: weight ({}) is smaller than the minimum weight ({})'.format(
                    tx.hash.hex(), tx.weight, block_weight)
                )
                return False
            if tx.sum_outputs != self.tokens_issued_per_block:
                self.log.info(
                    'Invalid number of issued tokens tag=invalid_issued_tokens'
                    ' tx.hash={tx.hash_hex} issued={tx.sum_outputs} allowed={allowed}',
                    tx=tx,
                    allowed=self.tokens_issued_per_block,
                )
        else:
            # Validate minimum tx difficulty
            min_tx_weight = self.minimum_tx_weight(tx)
            if tx.weight < min_tx_weight:
                self.log.debug('Invalid new tx {}: weight ({}) is smaller than the minimum weight ({})'.format(
                    tx.hash.hex(), tx.weight, min_tx_weight)
                )
                return False

        return True

    def minimum_tx_weight(self, tx):
        # In test mode we don't validate the minimum weight for tx
        # We do this to allow generating many txs for testing
        if self.test_mode:
            return 1

        if tx.is_genesis:
            return MIN_WEIGHT

        tx_size = len(tx.get_struct())

        # We need to remove the decimal places because it is in the amount
        # If you want to transfer 20 hathors, the amount will be 2000, that's why we reduce the log of decimal places
        weight = (self.min_tx_weight_coefficient*log(tx_size, 2) + log(tx.sum_outputs, 2) -
                  log(10**DECIMAL_PLACES, 2) + 0.5)

        # Make sure the calculated weight is bigger than the minimum
        assert weight > MIN_WEIGHT
        return weight

    def calculate_block_difficulty(self, block):
        if block.is_genesis:
            return 10

        it = self.tx_storage.iter_bfs_ascendent_blocks(block, max_depth=10)
        blocks = list(it)
        blocks.sort(key=lambda tx: tx.timestamp)

        if blocks[-1].is_genesis:
            return 10

        dt = blocks[-1].timestamp - blocks[0].timestamp

        if dt <= 0:
            dt = 1  # Strange situation, so, let's just increase difficulty.

        logH = 0
        for blk in blocks:
            logH = sum_weights(logH, blk.weight)

        weight = logH - log(dt, 2) + log(self.avg_time_between_blocks, 2)

        if weight < self.min_block_weight:
            weight = self.min_block_weight

        return weight


class RemoteValidatorFactory:
    def __init__(self, validator_port):
        self._validator_port = validator_port
        self._remote_clock_factory = None

    def __call__(self):
        remote_validator = RemoteValidator()
        remote_validator.connect_to(self._validator_port)
        if self._remote_clock_factory is not None:
            remote_validator.clock = self._remote_clock_factory()
        else:
            remote_validator.clock = None
        return remote_validator


class RemoteValidator(IValidator, StubConnect):
    @classmethod
    def get_stub_class(cls):
        return protos.ValidatorStub

    @convert_grpc_exceptions
    def validate_new_tx(self, tx):
        self._check_connection()
        request = protos.ValidateNewTxRequest(tx=tx.to_proto())
        result = self._stub.ValidateNewTx(request)
        return result.is_valid

    @convert_grpc_exceptions
    def minimum_tx_weight(self, tx):
        self._check_connection()
        request = protos.MinimumTxWeightRequest(tx=tx.to_proto())
        result = self._stub.MinimumTxWeight(request)
        return result.weight

    @convert_grpc_exceptions
    def calculate_block_difficulty(self, block):
        self._check_connection()
        request = protos.CalculateBlockDifficultyRequest(block=block.to_proto())
        result = self._stub.CalculateBlockDifficulty(request)
        return result.weight


class ValidatorServicer(protos.HathorManagerServicer):
    def __init__(self, validator):
        self.validator = validator

    @convert_hathor_exceptions
    def ValidateNewTx(self, request, context):
        tx = tx_or_block_from_proto(request.tx, storage=self.validator.tx_storage)
        is_valid = self.validator.validate_new_tx(tx)
        return protos.ValidateNewTxResponse(is_valid=is_valid)

    @convert_hathor_exceptions
    def MinimumTxWeight(self, request, context):
        tx = tx_or_block_from_proto(request.tx, storage=self.validator.tx_storage)
        weight = self.validator.minimum_tx_weight(tx)
        return protos.MinimumTxWeightResponse(weight=weight)

    @convert_hathor_exceptions
    def CalculateBlockDifficulty(self, request, context):
        block = tx_or_block_from_proto(request.block, storage=self.validator.tx_storage)
        weight = self.validator.calculate_block_difficulty(block)
        return protos.CalculateBlockDifficultyResponse(weight=weight)


class ValidatorSubprocess(Process):
    def __init__(self, remote_tx_storage_factory, clock=None, test_mode=False):
        # TODO: docstring
        Process.__init__(self)
        # this queue is used by the subprocess to inform which port was selected
        self._port_q = Queue(1)
        # this queue is used to inform the subprocess it can end
        self._exit_q = Queue(1)
        self._remote_tx_storage_factory = remote_tx_storage_factory
        self.clock = clock
        self._test_mode = test_mode

    def start(self):
        super().start()
        self._port = self._port_q.get()
        self.remote_validator_factory = RemoteValidatorFactory(self._port)
        if self.clock:
            self.remote_validator_factory._remote_clock_factory = RemoteClockFactory(self._port)

    def stop(self):
        self._exit_q.put_nowait(None)
        self.join()
        # self.terminate()

    def run(self):
        """internal method for Process interface, DO NOT run directly!!"""
        from concurrent import futures

        import grpc
        from twisted.internet import reactor

        from hathor import protos

        clock = self.clock or reactor

        grpc_server = grpc.server(futures.ThreadPoolExecutor())
        port = grpc_server.add_insecure_port('127.0.0.1:0')
        grpc_server.start()
        self._port_q.put(port)

        tx_storage = self._remote_tx_storage_factory()
        validator = Validator(tx_storage, clock=clock, test_mode=self._test_mode)

        validator_servicer = ValidatorServicer(validator)
        protos.add_ValidatorServicer_to_server(validator_servicer, grpc_server)

        if self.clock:
            clock_servicer = RemoteClockServicer(self.clock)
            protos.add_ClockServicer_to_server(clock_servicer, grpc_server)

        self._exit_q.get()
        grpc_server.stop(0)


class ValidatorSubprocessMock:
    def __init__(self, remote_tx_storage_factory, clock=None, test_mode=False):
        self._remote_tx_storage_factory = remote_tx_storage_factory
        self.clock = clock
        self._test_mode = test_mode

    def start(self):
        from concurrent import futures

        import grpc
        from twisted.internet import reactor
        from twisted.internet.task import Clock

        from hathor import protos

        clock = self.clock or reactor

        self.grpc_server = grpc.server(futures.ThreadPoolExecutor())
        port = self.grpc_server.add_insecure_port('127.0.0.1:0')
        self.grpc_server.start()

        self.remote_validator_factory = RemoteValidatorFactory(port)
        if self.clock:
            self.remote_validator_factory._remote_clock_factory = RemoteClockFactory(port)

        tx_storage = self._remote_tx_storage_factory()
        validator = Validator(tx_storage, clock=clock, test_mode=self._test_mode)

        validator_servicer = ValidatorServicer(validator)
        protos.add_ValidatorServicer_to_server(validator_servicer, self.grpc_server)

        if self.clock:
            # XXX: use a fresh Clock to discard advances because the same clock from the manager is used
            clock_servicer = RemoteClockServicer(Clock())
            protos.add_ClockServicer_to_server(clock_servicer, self.grpc_server)

    def stop(self):
        self.grpc_server.stop(0)
