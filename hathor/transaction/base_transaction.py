import datetime
import struct
import hashlib
from hathor.transaction.storage import genesis_transactions, default_transaction_storage
from hathor.transaction.exceptions import PowError, WeightError

MAX_NONCE = 2 ** 32
MAX_NUM_INPUTS = MAX_NUM_OUTPUTS = 256


class BaseTransaction:
    """Hathor base transaction"""

    def __init__(self, nonce=0, timestamp=None, version=1,
                 weight=0, inputs=None, outputs=None, parents=None, hash=None, storage=None, is_block=True):
        """
            Nonce: nonce used for the proof-of-work
            Timestamp: moment of creation
            Version: version when it was created
            Weight: different for transactions and blocks
            Outputs: all outputs that are being created
            Parents: transactions you are confirming (2 transactions and 1 block - in case of a block only)
        """
        self.nonce = nonce
        self.timestamp = timestamp or int(datetime.datetime.now().timestamp())
        self.version = version
        self.weight = weight
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.parents = parents or []
        self.storage = storage or default_transaction_storage()
        self.hash = hash
        self.is_block = is_block

    @classmethod
    def create_from_struct(cls, struct_bytes):
        def unpack(fmt, buf):
            size = struct.calcsize(fmt)
            return struct.unpack(fmt, buf[:size]), buf[size:]

        def unpack_len(n, buf):
            return buf[:n], buf[n:]

        buf = struct_bytes

        tx = cls()
        (tx.version, tx.weight, tx.timestamp, inputs_len, outputs_len, parents_len), buf = unpack('!HfIHHH', buf)

        for _ in range(parents_len):
            parent, buf = unpack_len(32, buf)  # 256bits
            tx.parents.append(parent)

        for _ in range(inputs_len):
            txin = Input()
            txin.tx_id, buf = unpack_len(32, buf)  # 256bits
            (txin.index, data_len), buf = unpack('!BH', buf)
            tx.data, buf = unpack_len(data_len, buf)
            tx.inputs.append(txin)

        for _ in range(outputs_len):
            txout = Output()
            (txout.value, script_len), buf = unpack('!IH', buf)
            tx.script = unpack_len(script_len, buf)
            tx.ouputs.append(txout)

        (tx.nonce,), buf = unpack('!I', buf)

        if len(buf) > 0:
            raise ValueError('Invalid sequence of bytes')

        tx.hash = tx.calculate_hash()
        return tx

    def __eq__(self, other):
        """Override the default Equals behavior"""
        return self.hash == other.hash

    @property
    def sum_outputs(self):
        """Sum of the value of the outputs"""
        return sum([output.value for output in self.outputs])

    @property
    def target(self):
        """Target to be achieved in the mining process"""
        return 2 ** (256 - self.weight) - 1

    @property
    def is_genesis(self):
        for genesis in genesis_transactions():
            if self == genesis:
                return True
        return False

    def calculate_weight(self):
        raise NotImplementedError

    def get_struct_without_nonce(self):
        """Return the struct of the transaction without the nonce field"""
        # First part is version (H), weight (f), timestamp (I), inputs len (H), outputs len (H) and parents len (H)
        struct_bytes = struct.pack(
            '!HfIHHH',
            self.version,
            self.weight,
            self.timestamp,
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
        """Return the full struct of the transaction (with the nonce)"""
        struct_bytes = self.get_struct_without_nonce()
        struct_bytes += int_to_bytes(self.nonce, 4)
        return struct_bytes

    def verify(self):
        raise NotImplementedError

    def verify_pow(self):
        """Verify proof-of-work and that the weight is correct"""
        if self.calculate_weight() != self.weight:
            raise WeightError
        if int(self.hash.hex(), 16) >= self.target:
            raise PowError

    def resolve(self):
        """Start mining to achieve the target"""
        hash_bytes = self.mining()
        if hash_bytes:
            self.hash = hash_bytes
            return True
        else:
            return False

    def calculate_hash1(self):
        """Returns the fixed part of the hash"""
        calculate_hash1 = hashlib.sha256()
        calculate_hash1.update(self.get_struct_without_nonce())
        return calculate_hash1

    def calculate_hash2(self, part1):
        """Returns the full hash of the hash from first part"""
        part1.update(self.nonce.to_bytes(4, byteorder='big', signed=False))
        return hashlib.sha256(part1.digest()).digest()

    def calculate_hash(self):
        """Returns the full hash of the hash"""
        part1 = self.calculate_hash1()
        return self.calculate_hash2(part1)

    def mining(self):
        """Starts mining until it solves the problem (finds the nonce that satisfies the conditions)"""
        self.weight = self.calculate_weight()
        pow_part1 = self.calculate_hash1()
        target = self.target
        while self.nonce < MAX_NONCE:
            result = self.calculate_hash2(pow_part1.copy())

            if int(result.hex(), 16) < target:
                return result
            self.nonce += 1
        return None


class Input:
    def __init__(self, tx_id, index, data):
        """
            tx_id: hash of the transaction that contains the output of this input
            index: index of the output you are spending from transaction tx_id (1 byte)
            data: data to solve output script
        """
        self.tx_id = tx_id                  # bytes
        self.index = index                  # int
        self.data = data                    # bytes


class Output:
    def __init__(self, value, script):
        """
            value: amount spent (4 bytes)
            script: script in bytes
        """
        self.value = value                  # int
        self.script = script                # bytes


def int_to_bytes(number, size, signed=False):
    return number.to_bytes(size, byteorder='big', signed=signed)
