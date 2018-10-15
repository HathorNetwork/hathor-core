# encoding: utf-8

from hathor.transaction.exceptions import PowError, InputOutputMismatch, TooManyInputs, \
                                          TooManyOutputs, BlockHeightError, ParentDoesNotExist, \
                                          TimestampError
from hathor.transaction.scripts import P2PKH

from enum import Enum
from math import log
import time
import struct
import hashlib
import base64

MAX_NONCE = 2 ** 32
MAX_NUM_INPUTS = MAX_NUM_OUTPUTS = 256

_INPUT_SIZE_BYTES = 32  # 256 bits

# Version (H), weight (f), timestamp (I), height (Q), inputs len (H), outputs len (H) and
# parents len (H).
# H = unsigned short (2 bytes), f = float(4), I = unsigned int (4), Q = unsigned long long int (64)
_TRANSACTION_FORMAT_STRING = '!HdIQHHH'  # Update code below if this changes.


def sum_weights(w1, w2):
    a = max(w1, w2)
    b = min(w1, w2)
    if b == 0:
        # Zero is a special acc_weight.
        # We could use float('-inf'), but it is not serializable.
        return a
    return a + log(1 + 2**(b-a), 2)


class TxConflictState(Enum):
    NO_CONFLICT = 'no-conflict'
    CONFLICT_WINNER = 'conflict-winner'
    CONFLICT_VOIDED = 'conflict-voided'


class BaseTransaction:
    """Hathor base transaction"""

    class GenesisDagConnectivity(Enum):
        UNKNOWN = -1
        DISCONNECTED = 0
        CONNECTED = 1

    def __init__(self, nonce=0, timestamp=None, version=1, weight=0, height=0,
                 inputs=None, outputs=None, parents=None, hash=None, storage=None, is_block=True):
        """
            Nonce: nonce used for the proof-of-work
            Timestamp: moment of creation
            Version: version when it was created
            Weight: different for transactions and blocks
            Outputs: all outputs that are being created
            Parents: transactions you are confirming (2 transactions and 1 block - in case of a block only)
        """
        self.nonce = nonce
        self.timestamp = timestamp or int(time.time())
        self.version = version
        self.weight = weight
        self.height = height  # TODO(epnichols): Is there any useful meaning here for non-block transactions?
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.parents = parents or []
        self.storage = storage
        self.hash = hash      # Stored as bytes.
        self.is_block = is_block

        # Locally we keep track of whether this tx is connected back to a genesis tx.
        self.genesis_dag_connectivity = self.GenesisDagConnectivity.UNKNOWN

    def __repr__(self):
        class_name = type(self).__name__
        return ('%s(nonce=%d, timestamp=%s, version=%s, weight=%f, height=%d, inputs=%s, outputs=%s, parents=%s, '
                'hash=%s, storage=%s)' %
                (class_name, self.nonce, self.timestamp, self.version, self.weight, self.height,
                 repr(self.inputs), repr(self.outputs), repr(self.parents), self.hash, repr(self.storage)))

    def __str__(self):
        class_name = 'Block' if self.is_block else 'Transaction'
        return ('%s(nonce=%d, timestamp=%s, version=%s, weight=%f, height=%d, hash=%s)' % (class_name, self.nonce,
                self.timestamp, self.version, self.weight, self.height, self.hash))

    @classmethod
    def create_from_struct(cls, struct_bytes, storage=None):
        """ Create a transaction from its bytes.

        :param struct_bytes: Bytes of a serialized transaction
        :type struct_bytes: bytes

        :return: A transaction or a block, depending on the class `cls`
        :rtype: Union[Transaction, Block]
        """
        def unpack(fmt, buf):
            size = struct.calcsize(fmt)
            return struct.unpack(fmt, buf[:size]), buf[size:]

        def unpack_len(n, buf):
            return buf[:n], buf[n:]

        buf = struct_bytes

        tx = cls()
        (tx.version, tx.weight, tx.timestamp, tx.height, inputs_len, outputs_len, parents_len), buf = (
            unpack(_TRANSACTION_FORMAT_STRING, buf))

        for _ in range(parents_len):
            parent, buf = unpack_len(32, buf)  # 256bits
            tx.parents.append(parent)

        for _ in range(inputs_len):
            input_tx_id, buf = unpack_len(_INPUT_SIZE_BYTES, buf)  # 256bits
            (input_index, data_len), buf = unpack('!BH', buf)
            input_data, buf = unpack_len(data_len, buf)
            txin = Input(input_tx_id, input_index, input_data)
            tx.inputs.append(txin)

        for _ in range(outputs_len):
            (value, script_len), buf = unpack('!IH', buf)
            script, buf = unpack_len(script_len, buf)
            txout = Output(value, script)
            tx.outputs.append(txout)

        (tx.nonce,), buf = unpack('!I', buf)

        if len(buf) > 0:
            raise ValueError('Invalid sequence of bytes')

        tx.hash = tx.calculate_hash()
        tx.storage = storage
        return tx

    def __eq__(self, other):
        """Two transactions are equal when their hash matches

        :raises NotImplement: when one of the transactions do not have a calculated hash
        """
        if self.hash and other.hash:
            return self.hash == other.hash
        return False

    def __bytes__(self):
        """Returns a byte representation of the transaction

        :rtype: bytes
        """
        return self.get_struct()

    @property
    def hash_hex(self):
        """Return the current stored hash in hex string format"""
        return self.hash.hex()

    @property
    def sum_outputs(self):
        """Sum of the value of the outputs"""
        return sum([output.value for output in self.outputs])

    def get_target(self):
        """Target to be achieved in the mining process"""
        return 2 ** (256 - self.weight) - 1

    @property
    def is_genesis(self):
        """ Check whether this transaction is a genesis transaction

        :rtype: bool
        """
        from hathor.transaction.genesis import genesis_transactions
        for genesis in genesis_transactions(self.storage):
            if self == genesis:
                return True
        return False

    def mark_inputs_as_used(self):
        """ Mark all its inputs as used
        """
        for txin in self.inputs:
            self.mark_input_as_used(txin)

    def mark_input_as_used(self, txin):
        """ Mark a given input as used
        """
        spent_tx = self.storage.get_transaction_by_hash_bytes(txin.tx_id)
        spent_meta = spent_tx.get_metadata()
        spent_by = spent_meta.spent_outputs[txin.index]  # Set[bytes(hash)]
        spent_by.add(self.hash)
        self.storage.save_metadata(spent_meta)

        if len(spent_by) > 1:
            # Conflicting transaction.
            meta_list = []
            winner_set = set()
            max_acc_weight = 0
            for h in spent_by:
                from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist
                try:
                    meta = self.storage.get_metadata_by_hash_bytes(h)
                except TransactionMetadataDoesNotExist:
                    from hathor.transaction.transaction_metadata import TransactionMetadata
                    meta = TransactionMetadata(hash=h)
                meta_list.append(meta)

                if meta.accumulated_weight == max_acc_weight:
                    winner_set.add(meta.hash)
                elif meta.accumulated_weight > max_acc_weight:
                    max_acc_weight = meta.accumulated_weight
                    winner_set = set([meta.hash])

            if len(winner_set) > 1:
                winner_set = set()

            for meta in meta_list:
                tx = self.storage.get_transaction_by_hash_bytes(meta.hash)
                assert tx.hash == meta.hash
                if tx.hash in winner_set:
                    tx.mark_as_winner()
                else:
                    tx.mark_as_voided()

    def mark_as_voided(self):
        """ Mark a transaction as voided when it has a conflict and its aggregated weight
        is NOT the greatest one.
        """
        meta = self.get_metadata()
        meta.conflict = TxConflictState.CONFLICT_VOIDED
        self.storage.save_metadata(meta)
        self.storage._del_from_cache(self)

    def mark_as_winner(self):
        """ Mark a transaction as winner when it has a conflict and its aggregated weight
        is the greatest one.
        """
        meta = self.get_metadata()
        meta.conflict = TxConflictState.CONFLICT_WINNER
        self.storage.save_metadata(meta)
        # TODO Add back to tip cache when it is a tip
        # self.storage._add_to_cache(self)

    def compute_genesis_dag_connectivity(self, storage, storage_sync, use_memoized_negative_results=True):
        """Computes the connectivity state from this tx bach to the genesis transactions.

        Returns True if this transaction has a complete path of confirmations back to the genesis transactions.
        If only one parent has a path back to the genesis DAG, we return False, since there is more work to do
        do get the graph connected.

        storage is the main storage object for this node, storing validated transactions. We assume
           "storage" to only have valid transactions that connect back to a genesis transaction.
        storage_sync is the *temp* storage object for this node, using while downloading data to synchronize.

        Results are memoized in self.genesis_dag_connectivity, so this only has to be calculated once per tx
        unless new info is added to the DAG. N.B. Memoization only works if storage_sync is in-memory.

        To recompute, re-memoize, and ignore previously-memoized results, set use_memoized_negative_results=False.
        This only recomputes results that were UNKNOWN or DISCONNECTED; we assume CONNECTED doesn't change; otherwise
        we would have to recompute conenctivity for every tx in the entire graph.
        """
        if (self.genesis_dag_connectivity == self.GenesisDagConnectivity.CONNECTED) or self.is_genesis:
            return True

        # Ensure that both parents are connected to the genesis DAG.
        # TODO(epnichols): Is this overkill? Only one path is needed to establish a connection, but if we're in a
        # state where one parent doesn't have a path back, we shouldn't yet consider this node really connected.
        connected = True  # Assume connected.
        for parent_hash_bytes in self.parents:
            # Find the parent.
            if storage.transaction_exists_by_hash_bytes(parent_hash_bytes):
                # If the parent is in the main storage, it's valid.
                continue
            if not storage_sync.transaction_exists_by_hash_bytes(parent_hash_bytes):
                # We can't even find the parent in temp storage. So our state is "disconnected" for now.
                connected = False
                break

            # The parent is in storage_sync. Get the data.
            parent = storage_sync.get_transaction_by_hash_bytes(parent_hash_bytes)

            # Now check the parent connectivity, using memoized results.
            # TODO: assumes that our temp storage_sync is in-memory; otherwise memoization data will be lost.
            parent_connected = parent.compute_genesis_dag_connectivity(storage, storage_sync, True)
            if parent_connected:
                continue
            if use_memoized_negative_results:
                connected = False
                break

            # Recompute for unknown/disconnected parents
            assert not use_memoized_negative_results  # Assert here to clarify code logic.

            parent_connected = parent.compute_genesis_dag_connectivity(storage, storage_sync, False)
            if not parent_connected:
                connected = False
                break

        # Done with recursion on parents.
        # Memoize results and return.
        self.genesis_dag_connectivity = (
            self.GenesisDagConnectivity.CONNECTED if connected else self.GenesisDagConnectivity.DISCONNECTED)
        return connected

    def calculate_weight(self):
        raise NotImplementedError

    def get_struct_without_nonce(self):
        """Return a partial serialization of the transaction, without including the nonce field

        :return: Partial serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = struct.pack(
            _TRANSACTION_FORMAT_STRING,
            self.version,
            self.weight,
            self.timestamp,
            self.height,
            len(self.inputs),
            len(self.outputs),
            len(self.parents)
        )

        for parent in self.parents:
            struct_bytes += parent

        for input_tx in self.inputs:
            struct_bytes += input_tx.tx_id
            struct_bytes += bytes([input_tx.index])  # 1 byte

            # data length
            struct_bytes += int_to_bytes(len(input_tx.data), 2)
            struct_bytes += input_tx.data

        for output_tx in self.outputs:
            struct_bytes += int_to_bytes(output_tx.value, 4)

            # script length
            struct_bytes += int_to_bytes(len(output_tx.script), 2)
            struct_bytes += output_tx.script

        return struct_bytes

    def get_struct(self):
        """Return the complete serialization of the transaction

        :rtype: bytes
        """
        struct_bytes = self.get_struct_without_nonce()
        struct_bytes += int_to_bytes(self.nonce, 4)
        return struct_bytes

    def verify(self):
        raise NotImplementedError

    def verify_parents(self):
        """All parents must exist and their timestamps must be smaller than ours.

        :raises TimestampError: when our timestamp is less or equal than our parent's timestamp
        :raises ParentDoesNotExist: when at least one of our parents does not exist
        """
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        for parent_hash in self.parents:
            try:
                parent = self.storage.get_transaction_by_hash_bytes(parent_hash)
                if self.timestamp <= parent.timestamp:
                    raise TimestampError('tx={} timestamp={}, parent={} timestamp={}'.format(
                        self.hash.hex(),
                        self.timestamp,
                        parent.hash.hex(),
                        parent.timestamp,
                    ))
            except TransactionDoesNotExist:
                raise ParentDoesNotExist('tx={} parent={}'.format(self.hash.hex(), parent_hash))

    def verify_pow(self):
        """Verify proof-of-work and that the weight is correct

        :raises PowError: when the hash is equal or greater than the target
        """
        # if abs(self.calculate_weight() - self.weight) > 1e-6:
        #     raise WeightError
        if int(self.hash.hex(), 16) >= self.get_target():
            raise PowError('Transaction has invalid data')

    def resolve(self):
        """Run a CPU mining looking for the nonce that solves the proof-of-work

        The `self.weight` must be set before calling this method.

        :return: True if a solution was found
        :rtype: bool
        """
        hash_bytes = self.start_mining()
        if hash_bytes:
            self.hash = hash_bytes
            return True
        else:
            return False

    def calculate_hash1(self):
        """Return the sha256 of the transaction without including the `nonce`

        :return: A partial hash of the transaction
        :rtype: :py:class:`_hashlib.HASH`
        """
        calculate_hash1 = hashlib.sha256()
        calculate_hash1.update(self.get_struct_without_nonce())
        return calculate_hash1

    def calculate_hash2(self, part1):
        """Return the hash of the transaction, starting from a partial hash

        The hash of the transactions is the `sha256(sha256(bytes(tx))`.

        :param part1: A partial hash of the transaction, usually from `calculate_hash1`
        :type part1: :py:class:`_hashlib.HASH`

        :return: The transaction hash
        :rtype: bytes
        """
        part1.update(self.nonce.to_bytes(4, byteorder='big', signed=False))
        return hashlib.sha256(part1.digest()).digest()

    def calculate_hash(self):
        """Return the full hash of the transaction

        It is the same as calling `self.calculate_hash2(self.calculate_hash1())`.

        :return: The hash transaction
        :rtype: bytes
        """
        part1 = self.calculate_hash1()
        return self.calculate_hash2(part1)

    def update_hash(self):
        """ Update the hash of the transaction.
        """
        self.hash = self.calculate_hash()

    def start_mining(self, start=0, end=MAX_NONCE, sleep_seconds=0):
        """Starts mining until it solves the problem, i.e., finds the nonce that satisfies the conditions

        :param start: beginning of the search interval
        :type start: int

        :param end: end of the search interval
        :type end: int

        :param sleep_seconds: the number of seconds it will sleep after each attempt
        :type sleep_seconds: float

        :return The hash of the solved PoW or None when it is not found
        :type Union[bytes, None]
        """
        pow_part1 = self.calculate_hash1()
        target = self.get_target()
        self.nonce = start
        last_time = time.time()
        while self.nonce < end:
            now = time.time()
            if now - last_time > 2:
                self.timestamp = int(now)
                pow_part1 = self.calculate_hash1()
                last_time = now
                self.nonce = start

            result = self.calculate_hash2(pow_part1.copy())
            if int(result.hex(), 16) < target:
                return result
            self.nonce += 1
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
        return None

    def get_metadata(self):
        """Return this tx's metadata.

        It first looks in our cache (tx._metadata) and then tries the tx storage. If it doesn't
        exist, returns a new TransactionMetadata object.

        :rtype: :py:class:`hathor.transaction.TransactionMetadata`
        """
        # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
        metadata = getattr(self, '_metadata', None)
        if not metadata:
            from hathor.transaction.storage.exceptions import TransactionMetadataDoesNotExist
            try:
                metadata = self.storage.get_metadata_by_hash_bytes(self.hash)
            except TransactionMetadataDoesNotExist:
                from hathor.transaction.transaction_metadata import TransactionMetadata
                metadata = TransactionMetadata(hash=self.hash)
            self._metadata = metadata
        return metadata

    def update_accumulated_weight(self, increment):
        """Increments the tx aggregated weight with the given value

        :type increment: float
        """
        metadata = self.get_metadata()
        metadata.accumulated_weight = sum_weights(metadata.accumulated_weight, increment)
        self.storage.save_metadata(metadata)

    def to_json(self, decode_script=False):
        data = {}
        data['hash'] = self.hash.hex()
        data['nonce'] = self.nonce
        data['timestamp'] = self.timestamp
        data['version'] = self.version
        data['weight'] = self.weight
        data['height'] = self.height

        data['parents'] = []
        for parent in self.parents:
            data['parents'].append(parent.hex())

        data['inputs'] = []
        # Blocks don't have inputs
        # TODO(epnichols): Refactor so that blocks/transactions know how to serialize themselves? Then we could do
        #                  something like data['inputs'] = tx.serialize_inputs()
        #                                 data['outputs'] = tx.serialize_outputs()
        #                  without needing the if statement here.
        if not self.is_block:
            for input_self in self.inputs:
                data_input = {}
                data_input['tx_id'] = input_self.tx_id.hex()
                data_input['index'] = input_self.index
                data_input['data'] = base64.b64encode(input_self.data).decode('utf-8')
                data['inputs'].append(data_input)

        data['outputs'] = []
        for output in self.outputs:
            data_output = {}
            # TODO use base58 and ripemd160
            data_output['value'] = output.value
            data_output['script'] = base64.b64encode(output.script).decode('utf-8')
            if decode_script:
                data_output['decoded'] = output.to_human_readable()
            data['outputs'].append(data_output)

        return data

    def validate_tx_error(self):
        """ Verify if tx is valid and return success and possible error message

            :return: Success if tx is valid and possible error message, if not
            :rtype: tuple[bool, str]
        """
        success = True
        message = ''
        try:
            self.verify()
        except (
            PowError,
            InputOutputMismatch,
            TooManyOutputs,
            TooManyInputs,
            BlockHeightError
        ) as e:
            success = False
            message = str(e)
        return success, message


class Input:
    def __init__(self, tx_id, index, data):
        """
            tx_id: hash of the transaction that contains the output of this input
            index: index of the output you are spending from transaction tx_id (1 byte)
            data: data to solve output script
        """
        assert isinstance(tx_id, bytes), 'Value is %s, type %s' % (str(tx_id), type(tx_id))
        assert isinstance(index, int),  'Value is %s, type %s' % (str(index), type(index))
        assert isinstance(data, bytes), 'Value is %s, type %s' % (str(data), type(data))

        self.tx_id = tx_id                  # bytes
        self.index = index                  # int
        self.data = data                    # bytes


class Output:
    def __init__(self, value, script):
        """
            value: amount spent (4 bytes)
            script: script in bytes
        """
        assert isinstance(value, int), 'Value is %s, type %s' % (str(value), type(value))
        assert isinstance(script, bytes), 'Value is %s, type %s' % (str(script), type(script))

        self.value = value                  # int
        self.script = script                # bytes

    def to_human_readable(self):
        """Checks what kind of script this is and returns it in human readable form

        We only have P2PKH for now.
        """
        p2pkh = P2PKH.verify_script(self.script)
        ret = {}
        if p2pkh:
            ret = p2pkh.to_human_readable()
        return ret


def int_to_bytes(number, size, signed=False):
    return number.to_bytes(size, byteorder='big', signed=signed)
