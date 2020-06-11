import struct
from typing import Dict, List, NamedTuple, Sequence, Tuple, Union


class BitcoinRawTransaction(NamedTuple):
    hash: bytes
    txid: bytes
    data: bytes

    @classmethod
    def from_dict(cls, data: Dict) -> 'BitcoinRawTransaction':
        return cls(bytes.fromhex(data['hash']), bytes.fromhex(data['txid']), bytes.fromhex(data['data']))

    def __bytes__(self) -> bytes:
        return self.data


class BitcoinBlockHeader(NamedTuple):
    version: int  # Block version information (note, this is signed)
    prev_block: bytes  # The hash value of the previous block this particular block references
    merkle_root: bytes  # The reference to a Merkle tree collection which is a hash of all transactions on this block
    timestamp: int  # A timestamp recording when this block was created (Will overflow in 2106[2])
    bits: bytes  # The calculated difficulty target being used for this block
    nonce: int = 0  # The nonce used to generate this block… to allow variations of the header and compute many hashes

    def __bytes__(self) -> bytes:
        """ Convert to byte representation of the header.

        | Size | Field       | Type     |
        |------|-------------|----------|
        | 4    | version     | int32_t  |
        | 32   | prev_block  | char[32] |
        | 32   | merkle_root | char[32] |
        | 4    | timestamp   | uint32_t |
        | 4    | bits        | uint32_t |
        | 4    | nonce       | uint32_t |

        References:

        - https://en.bitcoin.it/wiki/Block_hashing_algorithm
        - https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers
        """
        return b''.join([
            encode_uint32(self.version),
            encode_revbytes(self.prev_block),
            encode_revbytes(self.merkle_root),
            encode_uint32(self.timestamp),
            encode_revbytes(self.bits),
            encode_uint32(self.nonce),
        ])

    @classmethod
    def from_dict(cls, params: Dict) -> 'BitcoinBlockHeader':
        r""" Convert from dict of the properties returned from Bitcoin RPC.

        Examples:

        >>> bh = BitcoinBlockHeader.from_dict({
        ...     'hash': '00000000000000dde9c207dad944f56cb9456e7a8ea5b6cb2f77d9b7be7fa14e',
        ...     'confirmations': 27,
        ...     'height': 1518605,
        ...     'version': 545259520,
        ...     'versionHex': '20800000',
        ...     'merkleroot': '8927d337549640aaafdaa0dcbdb9c09972533a66bfb287aba3eb9c1be5b523ba',
        ...     'time': 1558960609,
        ...     'mediantime': 1558957676,
        ...     'nonce': 175544256,
        ...     'bits': '1a013e45',
        ...     'difficulty': 13494542.63853603,
        ...     'chainwork': '000000000000000000000000000000000000000000000115b2f49564a33f73b9',
        ...     'nTx': 17,
        ...     'previousblockhash': '00000000000000819567c00d364803c608f50d3baa50f6fb6ced4acee1f38ef4',
        ...     'nextblockhash': '000000000000011c7bf865dccaa725e620bf3e940b7ccc9497e93e776e44c635'
        ... })
        >>> bytes(bh).hex()
        '00008020f48ef3e1ce4aed6cfbf650aa3b0df508c60348360dc067958100000000000000ba23b5e51b9ceba3ab87b2bf663a537299c0b9bddca0daafaa40965437d32789e1d9eb5c453e011ac097760a'

        Additional parameters are ignored.
        """
        return cls(params['version'], bytes.fromhex(params['previousblockhash']), bytes.fromhex(params['merkleroot']),
                   params['time'], bytes.fromhex(params['bits']), params['nonce'])

    @classmethod
    def decode(cls, encoded: bytes) -> 'BitcoinBlockHeader':
        """ Decode block, reverse of bytes(...).

        Examples:
        >>> bytes(BitcoinBlockHeader.decode(bytes.fromhex(
        ...     '00008020f48ef3e1ce4aed6cfbf650aa3b0df508c60348360dc0679581000000'
        ...     '00000000ba23b5e51b9ceba3ab87b2bf663a537299c0b9bddca0daafaa409654'
        ...     '37d32789e1d9eb5c453e011ac097760a'))).hex()
        '00008020f48ef3e1ce4aed6cfbf650aa3b0df508c60348360dc067958100000000000000ba23b5e51b9ceba3ab87b2bf663a537299c0b9bddca0daafaa40965437d32789e1d9eb5c453e011ac097760a'
        """
        i = bytearray(encoded)
        return cls(
            read_uint32(i),
            read_nrevbytes(i, 32),
            read_nrevbytes(i, 32),
            read_uint32(i),
            read_nrevbytes(i, 4),
            read_uint32(i)
        )

    @property
    def hash(self) -> bytes:
        """ Calculated hash from header info."""
        return sha256d_hash(bytes(self))


def _merkle_concat(left: bytes, right: bytes) -> bytes:
    """ Concatenate two byte sequences in the way that works without altering the hashing function.
    """
    return bytes(reversed(left)) + bytes(reversed(right))


def build_merkle_path_for_coinbase(merkle_leaves: List[bytes]) -> List[bytes]:
    """ Return the merkle path (unidirectional since it's a list) to the coinbase (not included) from hash leaves.

    >>> tx_list = [bytes.fromhex(tx) for tx in [
    ...     #'32a31fb3f8596e5de0a40a53748839d15e0a1a1d264da5b7dacec9209a59fd2a',
    ...     '45c5dcbe62075d366b87fa375fb919c7a8ede24eba0a3a094df491aef55184ca',
    ...     '170938fa8cd0d26e796d0b407eaa2d40db8a8c0cb660f68bc0df2cc65ffc3990',
    ...     'd0d6241f43a27980da30ce66250bea94d852b77f5413a8e031a5bb545e4be80e',
    ...     '171a04ce755796d033e159bea5c9316555bfee4af21ee1e04723581a293f72b6',
    ...     '4bb6f7b0ecb48430d123849f254f59e9f113c2f47bbf883e3729541c92ac9267',
    ...     'dbcf66ea7f3c5158df7a9495fb4fae099118ff33df0656ecf5d4aef5ad8d22fb',
    ...     'efe24291c27f4602f70f2433548f11e7ac74c8eb7e23d18b21d9c14882400224',
    ...     '6a93578dcd8d580c6d23f627d54d34b3698631bffdf95463f9700f87b2ed8d36',
    ...     '1981dd6950d3674f216d2e2fbbd09d7becd58ddbf33e3c646524088ae1a32542',
    ...     '80d54e4f14b39d98965d9354d34a9663490477b04961c665cb9d9953006bf949',
    ...     'de4fb58f8574e2395c074765acd78d862cfc21fbcc2402f026c4c4bc1aa11369',
    ...     'b3e7d54ccb77ab183f43faf25993a8798e0358c4d67b34989f65d395fbf7866a',
    ...     '3ede276d334f763617ef8f45cc58219eb369df2ed9cf32be86f1c88b94af676e',
    ...     'b244488bd9bd57fb33ea1c3872d510b64abdce2245e17a6607653e0b17628c7a',
    ...     'efb48aaeb133cca84af2d2fb9c13399db1f9f1fdb85b4210a936c545cd3124e7',
    ...     '232aaff768a2653db16fbe84504ff7d59396eb08663d2f5dda1d1587ce297df8'
    ... ]]
    >>> [i.hex() for i in build_merkle_path_for_coinbase(tx_list)]
    ['45c5dcbe62075d366b87fa375fb919c7a8ede24eba0a3a094df491aef55184ca', \
'6caec8ea3732c953fa195320bb26d2e9f630be5edf384a48e42e26ae7198f844', \
'188c78ef10ce002f2fc3cf8f445d4d1aa12d5f3ce32420e565c9d3cc4d64d8a2', \
'67ce1464dc89e67dd30acf8adf74c7ec37fa9f14040b7ecd9127391af1b25f2a', \
'ee017b11d10898f3b19194f43d9b5b9cf443b8e992797e49f4edd603fee060c7']
    """
    return _build_merkle_path_for_coinbase([b''] + merkle_leaves)


def _build_merkle_path_for_coinbase(merkle_leaves: List[bytes], _partial_path: List[bytes] = []) -> List[bytes]:
    """ Internal implementation of `build_merkle_path_for_coinbase`, assumes first `merkle_leave` is the coinbase.
    """
    merkle_leaves = merkle_leaves[:]  # copy to preserve original
    _partial_path = _partial_path[:]  # copy to preserve original
    len_merkle_leaves = len(merkle_leaves)
    if len_merkle_leaves == 0:
        return []
    # FIXME: maybe breaks if initial merkle_leaves has len 1?
    if len_merkle_leaves <= 1:
        return _partial_path
    if len_merkle_leaves % 2:
        merkle_leaves.append(merkle_leaves[-1])
        len_merkle_leaves += 1
    _partial_path.append(merkle_leaves[1])  # to trace the coinbase (1st tx) we always get its pair (2nd tx)
    iter_leaves = iter(merkle_leaves[:])
    return _build_merkle_path_for_coinbase(
        [sha256d_hash(_merkle_concat(l, r)) for l, r in zip(iter_leaves, iter_leaves)],
        _partial_path=_partial_path
    )


def build_merkle_root(merkle_leaves: List[bytes]) -> bytes:
    """ Return the merkle root hash from hash leaves.

    >>> build_merkle_root([bytes.fromhex(tx) for tx in [
    ...     '32a31fb3f8596e5de0a40a53748839d15e0a1a1d264da5b7dacec9209a59fd2a',
    ...     '45c5dcbe62075d366b87fa375fb919c7a8ede24eba0a3a094df491aef55184ca',
    ...     '170938fa8cd0d26e796d0b407eaa2d40db8a8c0cb660f68bc0df2cc65ffc3990',
    ...     'd0d6241f43a27980da30ce66250bea94d852b77f5413a8e031a5bb545e4be80e',
    ...     '171a04ce755796d033e159bea5c9316555bfee4af21ee1e04723581a293f72b6',
    ...     '4bb6f7b0ecb48430d123849f254f59e9f113c2f47bbf883e3729541c92ac9267',
    ...     'dbcf66ea7f3c5158df7a9495fb4fae099118ff33df0656ecf5d4aef5ad8d22fb',
    ...     'efe24291c27f4602f70f2433548f11e7ac74c8eb7e23d18b21d9c14882400224',
    ...     '6a93578dcd8d580c6d23f627d54d34b3698631bffdf95463f9700f87b2ed8d36',
    ...     '1981dd6950d3674f216d2e2fbbd09d7becd58ddbf33e3c646524088ae1a32542',
    ...     '80d54e4f14b39d98965d9354d34a9663490477b04961c665cb9d9953006bf949',
    ...     'de4fb58f8574e2395c074765acd78d862cfc21fbcc2402f026c4c4bc1aa11369',
    ...     'b3e7d54ccb77ab183f43faf25993a8798e0358c4d67b34989f65d395fbf7866a',
    ...     '3ede276d334f763617ef8f45cc58219eb369df2ed9cf32be86f1c88b94af676e',
    ...     'b244488bd9bd57fb33ea1c3872d510b64abdce2245e17a6607653e0b17628c7a',
    ...     'efb48aaeb133cca84af2d2fb9c13399db1f9f1fdb85b4210a936c545cd3124e7',
    ...     '232aaff768a2653db16fbe84504ff7d59396eb08663d2f5dda1d1587ce297df8'
    ... ]]).hex()
    '8927d337549640aaafdaa0dcbdb9c09972533a66bfb287aba3eb9c1be5b523ba'
    """
    len_merkle_leaves = len(merkle_leaves)
    assert len_merkle_leaves > 0
    if len_merkle_leaves <= 1:
        return merkle_leaves[0]
    if len_merkle_leaves % 2:
        merkle_leaves.append(merkle_leaves[-1])
        len_merkle_leaves += 1
    iter_leaves = iter(merkle_leaves)
    return build_merkle_root([sha256d_hash(_merkle_concat(l, r)) for l, r in zip(iter_leaves, iter_leaves)])


def build_merkle_root_from_path(merkle_path: List[bytes]) -> bytes:
    """ Return the merkle root hash from a given unidirectional (all right) merkle path.

    Useful for computing merkle root given the merkle path to the coinbase (including the coinbase tx).

    >>> build_merkle_root_from_path([bytes.fromhex(tx) for tx in [
    ...     '32a31fb3f8596e5de0a40a53748839d15e0a1a1d264da5b7dacec9209a59fd2a',
    ...     '45c5dcbe62075d366b87fa375fb919c7a8ede24eba0a3a094df491aef55184ca',
    ...     '6caec8ea3732c953fa195320bb26d2e9f630be5edf384a48e42e26ae7198f844',
    ...     '188c78ef10ce002f2fc3cf8f445d4d1aa12d5f3ce32420e565c9d3cc4d64d8a2',
    ...     '67ce1464dc89e67dd30acf8adf74c7ec37fa9f14040b7ecd9127391af1b25f2a',
    ...     'ee017b11d10898f3b19194f43d9b5b9cf443b8e992797e49f4edd603fee060c7'
    ... ]]).hex()
    '8927d337549640aaafdaa0dcbdb9c09972533a66bfb287aba3eb9c1be5b523ba'

    Example from cpu-miner (tx hashes are reversed):

    >>> bytes(reversed(build_merkle_root_from_path([bytes(reversed(bytes.fromhex(tx))) for tx in [
    ...     '240ac8a678139b0df3984aaff62571e0c9bd7f4c32fbc2720332902619d7beb5',
    ...     'dcf3763488560085aa77b99a988917a7849f7fea2bff894efe3a5e9d9f70c9fe',
    ...     'a3b2ce71fdf67801b596d9e352e3a4f8a3e6dc84bfe752c387479fab67fe7c21',
    ...     '7473649a92f93558aa53cedf927a625fcbec8c1ffa5eea0074c8c2db57a04a34',
    ...     'bf300fa3af6ce187fcf96a990a0e00c276ccf324141d278704a6ecfd9e366183',
    ...     'e7d28e53c5982de2948dce75b2d3c9c01281950ba57c08c140b3d10398af1ec4',
    ...     'e4a0d64bc740d24c476560753032e255555a33b6ca42e4137ff16ee7b3339f85',
    ...     '674ff1f7ba4b7c03637be3088414e5d4b5212461891f0f22ece0222235686eee'
    ... ]]))).hex()
    '9fedb4e40f8532eac81338b479049a2e6bcee68d78b56767d43ebf1020ef8a68'
    """
    merkle_path = merkle_path[:]  # copy to preserve original
    assert len(merkle_path) >= 1
    while len(merkle_path) > 1:
        a = merkle_path.pop(0)
        b = merkle_path.pop(0)
        c = sha256d_hash(_merkle_concat(a, b))
        merkle_path.insert(0, c)
    return merkle_path[0]


class BitcoinOutPoint(NamedTuple):
    hash: bytes  # The hash of the referenced transaction.
    idx: int  # The index of the specific output in the transaction. The first output is 0, etc.

    def __bytes__(self) -> bytes:
        """ Convert to byte representation of the header.

        | Size | Field | Type     |
        |------|-------|----------|
        | 32   | hash  | char[32] |
        | 4    | index | uint32_t |

        References:

        - https://en.bitcoin.it/wiki/Block_hashing_algorithm
        - https://en.bitcoin.it/wiki/Protocol_documentation#tx
        """
        return self.hash + struct.pack('<I', self.idx)

    @classmethod
    def null(cls) -> 'BitcoinOutPoint':
        return cls(b'\00' * 32, 0xffff_ffff)

    def is_null(self) -> bool:
        return self.idx == 0xffff_ffff and \
               self.hash == b'\00' * 32


SEQUENCE_FINAL = 0xffff_ffff


class BitcoinTransactionInput(NamedTuple):
    previous_output: BitcoinOutPoint  # The previous output transaction reference, as an OutPoint structure
    script_sig: bytes  # Computational Script for confirming transaction authorization
    # Transaction version as defined by the sender. Intended for "replacement" of transactions when information is
    # updated before inclusion into a block.
    sequence: int = SEQUENCE_FINAL  # default value disables nLockTime
    script_witness: List[bytes] = []

    def __bytes__(self) -> bytes:
        """ Convert to byte representation of the header.

        | Size | Field            | Type     |
        |------|------------------|----------|
        | 36   | previous_output  | outpoint |
        | 1+   | script length    | var_int  |
        | ?    | signature script | uchar[]  |
        | 4    | sequence         | uint32_t |

        References:

        - https://en.bitcoin.it/wiki/Block_hashing_algorithm
        - https://en.bitcoin.it/wiki/Protocol_documentation#tx
        """
        return bytes(self.previous_output) + encode_bytearray(self.script_sig) + encode_uint32(self.sequence)

    @classmethod
    def coinbase(cls, script_sig: bytes) -> 'BitcoinTransactionInput':
        """ Create a blank coinbase input, without the block height.
        """
        return cls(BitcoinOutPoint.null(), script_sig)

    def is_final(self) -> bool:
        """ A final transaction has the final sequence, and cannot be altered anymore.
        """
        return self.sequence == SEQUENCE_FINAL

    def has_witness(self) -> bool:
        """ Whether this input has a witness (segwit).
        """
        return bool(self.script_witness)

    @classmethod
    def from_dict(cls, params: Dict) -> 'BitcoinTransactionInput':
        r""" Convert from dict of the properties returned from Bitcoin RPC.

        Examples:

        >>> BitcoinTransactionInput.from_dict({
        ...     'coinbase': '03a32c1700040c54ed5c0499e680160cb3f98f5cb4510100000000000a636b706f6f6c072f74727466782f',
        ...     'sequence': 4294967295
        ... })
        BitcoinTransactionInput(...)

        >>> BitcoinTransactionInput.from_dict({
        ...     'txid': '8554a444b95335b721c15a908b796a37d02eb907820720664cd3905c9b4b3a24',
        ...     'vout': 8,
        ...     'scriptSig': {
        ...       'asm': '001491b17e590c10a2f17491082472851842b910ade7',
        ...       'hex': '16001491b17e590c10a2f17491082472851842b910ade7'
        ...     },
        ...     'txinwitness': [
        ...       '304402204e02939f891d669a7882fd2804b560b441192cd877a9bc2b4f2c4dcd10de8946'
        ...       '0220169b96eaec64c8066f9057ae170cc0f9e79aab50ed6b9eeb0e6f94703e83a4a301',
        ...       '03453b25c90a58f12eddb1581dfe5fc6a4150bf2bcfa979f7deb82ad972e916819'
        ...     ],
        ...     'sequence': 4294967294
        ... })
        BitcoinTransactionInput(...)
        """

        if 'coinbase' in params:
            if __debug__ and 'sequence' in params:
                assert params['sequence'] == SEQUENCE_FINAL
            return cls.coinbase(bytes.fromhex(params['coinbase']))
        return cls(
            BitcoinOutPoint(bytes(reversed(bytes.fromhex(params['txid']))), params['vout']),
            bytes.fromhex(params['scriptSig']['hex']), params['sequence'],
            list(map(bytes.fromhex, params.get('txinwitness', []))))


class BitcoinTransactionOutput(NamedTuple):
    value: int = 0xffff_ffff_ffff_ffff  # Transaction Value
    script_pubkey: bytes = b''  # Usually contains the public key as a Bitcoin script to claim this output.

    def __bytes__(self) -> bytes:
        """ Convert to byte representation of the header.

        | Size | Field            | Type    |
        |------|------------------|---------|
        | 8    | value            | int64_t |
        | 1+   | pk_script length | var_int |
        | ?    | pk_script        | uchar[] |

        References:

        - https://en.bitcoin.it/wiki/Block_hashing_algorithm
        - https://en.bitcoin.it/wiki/Protocol_documentation#tx
        """
        return struct.pack('<Q', self.value) + encode_bytearray(self.script_pubkey)

    @classmethod
    def from_dict(cls, params: Dict) -> 'BitcoinTransactionOutput':
        r""" Convert from dict of the properties returned from Bitcoin RPC.

        Examples:

        >>> BitcoinTransactionOutput.from_dict({
        ...     "value": 0.40113268,
        ...     "n": 0,
        ...     "scriptPubKey": {
        ...       "asm": "OP_HASH160 6b5233d5b41019fbf5132690b85731e043176de9 OP_EQUAL",
        ...       "hex": "a9146b5233d5b41019fbf5132690b85731e043176de987",
        ...       "reqSigs": 1,
        ...       "type": "scripthash",
        ...       "addresses": [
        ...         "2N32gmLa2S2GaDMXTcd5hV3Ecxe7MA8nvET"
        ...       ]
        ...     }
        ... })
        BitcoinTransactionOutput(...)

        >>> BitcoinTransactionOutput.from_dict({
        ...     "value": 0,
        ...     "n": 1,
        ...     "scriptPubKey": {
        ...       "asm": "OP_RETURN aa21a9ed654f17b2262667067ec3b97a66b53131b1509f353767275adba14cc4aeb3c2ba",
        ...       "hex": "6a24aa21a9ed654f17b2262667067ec3b97a66b53131b1509f353767275adba14cc4aeb3c2ba",
        ...       "type": "nulldata"
        ...     }
        ... })
        BitcoinTransactionOutput(...)

        """
        return cls(int(params['value'] * 100_000_000), bytes.fromhex(params['scriptPubKey']['hex']))


class BitcoinTransaction(NamedTuple):
    version: int = 1  # Transaction data format version (note, this is signed)
    include_witness: bool = True  # Whether to include the witness flag (0001)
    inputs: List[BitcoinTransactionInput] = []  # A list of 1 or more transaction inputs or sources for coins
    outputs: List[BitcoinTransactionOutput] = []  # A list of 1 or more transaction outputs or destinations for coins
    lock_time: int = 0  # The block number or timestamp at which this transaction is unlocked

    def __bytes__(self) -> bytes:
        """ Convert to byte representation of the header.

        | Size   | Field        | Type                       |
        |--------|--------------|----------------------------|
        | 4      | version      | int32_t                    |
        | 0 or 2 | flag         | optional uint8_t[2] = 0001 |
        | 1+     | tx_in count  | var_int                    |
        | 41+    | tx_in        | tx_in[]                    |
        | 1+     | tx_out count | var_int                    |
        | 9+     | tx_out       | tx_out[]                   |
        | 0+     | tx_witnesses | tx_witness[]               |
        | 4      | lock_time    | uint32_t                   |

        References:

        - https://en.bitcoin.it/wiki/Block_hashing_algorithm
        - https://en.bitcoin.it/wiki/Protocol_documentation#tx
        """
        return self._to_bytes()

    def _to_bytes(self, skip_segwit: bool = False) -> bytes:
        """ Implementation of __bytes__ with option to skip segwit (used on txid).
        """
        data = bytearray(struct.pack('<i', self.version))
        include_witness = self.has_witness() or self.include_witness
        if skip_segwit:
            include_witness = False
        if include_witness:
            data.extend(b'\00\01')
        data.extend(encode_list(list(map(bytes, self.inputs))))
        data.extend(encode_list(list(map(bytes, self.outputs))))
        if include_witness:
            data.extend(b''.join(map(encode_bytearray_list, self.tx_witnesses)))
        data.extend(struct.pack('<I', self.lock_time))
        return bytes(data)

    def to_raw(self) -> BitcoinRawTransaction:
        """ Convert this transaction into a raw transaction that holds hash, txid and serialized data bytes.
        """
        return BitcoinRawTransaction(self.hash, self.txid, bytes(self))

    @property
    def tx_witnesses(self) -> List[List[bytes]]:
        """ List of witnesses list: each input yields a list.
        """
        return [i.script_witness or [b'\00' * 32] for i in self.inputs]

    @property
    def hash(self) -> bytes:
        """ The hash of the transaction.
        """
        return sha256d_hash(bytes(self))

    @property
    def txid(self) -> bytes:
        """ The transaction identifier as defined by BIP-141. If there are no witnesses it is the same as the hash.
        """
        return sha256d_hash(self._to_bytes(skip_segwit=True))

    @classmethod
    def from_dict(cls, params: Dict) -> 'BitcoinTransaction':
        r""" Convert from dict of the properties returned from Bitcoin RPC.

        Examples:

        >>> tx = BitcoinTransaction.from_dict({
        ...     'txid': '00e651a8551a891a5f21d8f5d3843848500626327cf32b3a4c1c4d2cfac01eff',
        ...     'hash': 'bbd1485b32ba24541ea78414b80a633fbf2de281bf052453253648562437ecf1',
        ...     'version': 1,
        ...     'size': 209,
        ...     'vsize': 182,
        ...     'weight': 728,
        ...     'locktime': 0,
        ...     'vin': [
        ...       {
        ...         'coinbase': '03a32c1700040c54ed5c0499e680160cb3f98f5cb4510100000000000a636b70'
        ...                     '6f6f6c072f74727466782f',
        ...         'sequence': 4294967295
        ...       }
        ...     ],
        ...     'vout': [
        ...       {
        ...         'value': 0.40113268,
        ...         'n': 0,
        ...         'scriptPubKey': {
        ...           'asm': 'OP_HASH160 6b5233d5b41019fbf5132690b85731e043176de9 OP_EQUAL',
        ...           'hex': 'a9146b5233d5b41019fbf5132690b85731e043176de987',
        ...           'reqSigs': 1,
        ...           'type': 'scripthash',
        ...           'addresses': [
        ...             '2N32gmLa2S2GaDMXTcd5hV3Ecxe7MA8nvET'
        ...           ]
        ...         }
        ...       },
        ...       {
        ...         'value': 0,
        ...         'n': 1,
        ...         'scriptPubKey': {
        ...           'asm': 'OP_RETURN aa21a9ed654f17b2262667067ec3b97a66b53131b1509f353767275adba14cc4aeb3c2ba',
        ...           'hex': '6a24aa21a9ed654f17b2262667067ec3b97a66b53131b1509f353767275adba14cc4aeb3c2ba',
        ...           'type': 'nulldata'
        ...         }
        ...       }
        ...     ],
        ...     'hex': '0100000000010100000000000000000000000000000000000000000000000000'
        ...            '00000000000000ffffffff2b03a32c1700040c54ed5c0499e680160cb3f98f5c'
        ...            'b4510100000000000a636b706f6f6c072f74727466782fffffffff0274146402'
        ...            '0000000017a9146b5233d5b41019fbf5132690b85731e043176de98700000000'
        ...            '00000000266a24aa21a9ed654f17b2262667067ec3b97a66b53131b1509f3537'
        ...            '67275adba14cc4aeb3c2ba012000000000000000000000000000000000000000'
        ...            '0000000000000000000000000000000000',
        ...     'blockhash': '000000000000004711b056e1769a6b44b0cf2c21df6f789a73ef4ebaa6a32c80',
        ...     'confirmations': 2,
        ...     'time': 1559057420,
        ...     'blocktime': 1559057420
        ... })
        >>> bytes(tx).hex()
        '010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2b03a32c1700040c54ed5c0499e680160cb3f98f5cb4510100000000000a636b706f6f6c072f74727466782fffffffff02741464020000000017a9146b5233d5b41019fbf5132690b85731e043176de9870000000000000000266a24aa21a9ed654f17b2262667067ec3b97a66b53131b1509f353767275adba14cc4aeb3c2ba0120000000000000000000000000000000000000000000000000000000000000000000000000'
        >>> tx.txid.hex()
        '00e651a8551a891a5f21d8f5d3843848500626327cf32b3a4c1c4d2cfac01eff'
        >>> tx.hash.hex()
        'bbd1485b32ba24541ea78414b80a633fbf2de281bf052453253648562437ecf1'

        >>> tx = BitcoinTransaction.from_dict({
        ...     'txid': '171a04ce755796d033e159bea5c9316555bfee4af21ee1e04723581a293f72b6',
        ...     'hash': '61fa32c01d42d7fb18337832873dd9cea93d6be11591cb799700e94da1e7154b',
        ...     'version': 1,
        ...     'size': 489,
        ...     'vsize': 246,
        ...     'weight': 981,
        ...     'locktime': 0,
        ...     'vin': [
        ...       {
        ...         'txid': '9e642432e502b51e6ded66db2731a8dfa5ae10a7b6a73acb6edd2a39484e1237',
        ...         'vout': 0,
        ...         'scriptSig': {
        ...           'asm': '',
        ...           'hex': ''
        ...         },
        ...         'txinwitness': [
        ...           '3045022100d4bac8d97c99420c86cb76c5b9c16e9c9011c64f85f4c22ae8df91101a073c2'
        ...           '4022078846cbb393759104254bb2604b3674f2510397316bc5ac1732e9a885307d7a001',
        ...           '029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c'
        ...         ],
        ...         'sequence': 4294967295
        ...       },
        ...       {
        ...         'txid': 'd70e8709b0b9c8dda48508ca07715e35502b6d324265cfc05c740ffb24525cce',
        ...         'vout': 1,
        ...         'scriptSig': {
        ...           'asm': '',
        ...           'hex': ''
        ...         },
        ...         'txinwitness': [
        ...           '3045022100925f72894543dd7b6f591f516d932efe3c45249ce85aa4541a5014085a20ae4'
        ...           '80220457f10ce4f1f22930e8254af56ea058549a59b1bedbc20805017289843d115c401',
        ...           '029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c'
        ...         ],
        ...         'sequence': 4294967295
        ...       },
        ...       {
        ...         'txid': '4a9ae025a3d1f780caebee833edbfd7ee8374338ff7ed075b586a7031c274ef1',
        ...         'vout': 1,
        ...         'scriptSig': {
        ...           'asm': '',
        ...           'hex': ''
        ...         },
        ...         'txinwitness': [
        ...           '30440220780f8b0e0cc2e139f63d58418b19f833f1da31cc1e3153cd2614c92d6c5e7af3'
        ...           '02205244d95a7d6f09f7c940ea6290062671f3488fb46b70d0761aaeabeb6ac283a301',
        ...           '029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c'
        ...         ],
        ...         'sequence': 4294967295
        ...       }
        ...     ],
        ...     'vout': [
        ...       {
        ...         'value': 0.00135384,
        ...         'n': 0,
        ...         'scriptPubKey': {
        ...           'asm': '0 165f607fe9db2f2cc683c48f4060b9a046f314d3',
        ...           'hex': '0014165f607fe9db2f2cc683c48f4060b9a046f314d3',
        ...           'reqSigs': 1,
        ...           'type': 'witness_v0_keyhash',
        ...           'addresses': [
        ...             'tb1qze0kqllfmvhje35rcj85qc9e5pr0x9xnteg00u'
        ...           ]
        ...         }
        ...       }
        ...     ],
        ...     'hex': '0100000000010337124e48392add6ecb3aa7b6a710aea5dfa83127db66ed6d1e'
        ...            'b502e53224649e0000000000ffffffffce5c5224fb0f745cc0cf6542326d2b50'
        ...            '355e7107ca0885a4ddc8b9b009870ed70100000000fffffffff14e271c03a786'
        ...            'b575d07eff384337e87efddb3e83eeebca80f7d1a325e09a4a0100000000ffff'
        ...            'ffff01d810020000000000160014165f607fe9db2f2cc683c48f4060b9a046f3'
        ...            '14d302483045022100d4bac8d97c99420c86cb76c5b9c16e9c9011c64f85f4c2'
        ...            '2ae8df91101a073c24022078846cbb393759104254bb2604b3674f2510397316'
        ...            'bc5ac1732e9a885307d7a00121029f73a015fab9d2bbbb10368b11745b3b6302'
        ...            '383916fd7b17c0580c14590cb89c02483045022100925f72894543dd7b6f591f'
        ...            '516d932efe3c45249ce85aa4541a5014085a20ae480220457f10ce4f1f22930e'
        ...            '8254af56ea058549a59b1bedbc20805017289843d115c40121029f73a015fab9'
        ...            'd2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c024730440220'
        ...            '780f8b0e0cc2e139f63d58418b19f833f1da31cc1e3153cd2614c92d6c5e7af3'
        ...            '02205244d95a7d6f09f7c940ea6290062671f3488fb46b70d0761aaeabeb6ac2'
        ...            '83a30121029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c'
        ...            '14590cb89c00000000',
        ...     'blockhash': '00000000000000dde9c207dad944f56cb9456e7a8ea5b6cb2f77d9b7be7fa14e',
        ...     'confirmations': 223,
        ...     'time': 1558960609,
        ...     'blocktime': 1558960609
        ... })
        >>> bytes(tx).hex()
        '0100000000010337124e48392add6ecb3aa7b6a710aea5dfa83127db66ed6d1eb502e53224649e0000000000ffffffffce5c5224fb0f745cc0cf6542326d2b50355e7107ca0885a4ddc8b9b009870ed70100000000fffffffff14e271c03a786b575d07eff384337e87efddb3e83eeebca80f7d1a325e09a4a0100000000ffffffff01d810020000000000160014165f607fe9db2f2cc683c48f4060b9a046f314d302483045022100d4bac8d97c99420c86cb76c5b9c16e9c9011c64f85f4c22ae8df91101a073c24022078846cbb393759104254bb2604b3674f2510397316bc5ac1732e9a885307d7a00121029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c02483045022100925f72894543dd7b6f591f516d932efe3c45249ce85aa4541a5014085a20ae480220457f10ce4f1f22930e8254af56ea058549a59b1bedbc20805017289843d115c40121029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c024730440220780f8b0e0cc2e139f63d58418b19f833f1da31cc1e3153cd2614c92d6c5e7af302205244d95a7d6f09f7c940ea6290062671f3488fb46b70d0761aaeabeb6ac283a30121029f73a015fab9d2bbbb10368b11745b3b6302383916fd7b17c0580c14590cb89c00000000'
        >>> tx.txid.hex()
        '171a04ce755796d033e159bea5c9316555bfee4af21ee1e04723581a293f72b6'
        >>> tx.hash.hex()
        '61fa32c01d42d7fb18337832873dd9cea93d6be11591cb799700e94da1e7154b'

        >>> tx = BitcoinTransaction.from_dict({
        ...     'data': '0100000001f9002b8cc8aa9184e57367ad7cfb2f29899d29695202f34fcc17f7'
        ...             '6090296e48000000006b48304502210098cc550f1b487358352df20d1a0aa81b'
        ...             'f33de002519a4d1d69edc3fe36cfb799022038c54aa9f4d899328f3ec873a459'
        ...             '120e3bbeb063d6ff9ba5a30b3b2d9ced75310121020c079e1545a927a2993dc5'
        ...             'f81efc53b3ee7f946afd5a1991ac81440c4aadd2e6ffffffff01407910000000'
        ...             '00001976a914a361f2c9f91e49f7fe6cdbb76ac52fbb08dde41788ac00000000',
        ...     'txid': '000f2b0ad4f3e5b871b449837ffa8cbd62d90031cbd1656b21c584b948367351',
        ...     'hash': '000f2b0ad4f3e5b871b449837ffa8cbd62d90031cbd1656b21c584b948367351',
        ...     'depends': [],
        ...     'fee': 6206646,
        ...     'sigops': 4,
        ...     'weight': 768
        ... })
        >>> bytes(tx).hex()
        '0100000001f9002b8cc8aa9184e57367ad7cfb2f29899d29695202f34fcc17f76090296e48000000006b48304502210098cc550f1b487358352df20d1a0aa81bf33de002519a4d1d69edc3fe36cfb799022038c54aa9f4d899328f3ec873a459120e3bbeb063d6ff9ba5a30b3b2d9ced75310121020c079e1545a927a2993dc5f81efc53b3ee7f946afd5a1991ac81440c4aadd2e6ffffffff0140791000000000001976a914a361f2c9f91e49f7fe6cdbb76ac52fbb08dde41788ac00000000'
        >>> tx.txid.hex()
        '000f2b0ad4f3e5b871b449837ffa8cbd62d90031cbd1656b21c584b948367351'
        >>> tx.hash.hex()
        '000f2b0ad4f3e5b871b449837ffa8cbd62d90031cbd1656b21c584b948367351'
        """
        if 'data' in params:
            return cls.decode(bytes.fromhex(params['data']))
        return cls(
            params['version'],
            True,  # TODO: is it always the case?
            list(map(BitcoinTransactionInput.from_dict, params['vin'])),
            list(map(BitcoinTransactionOutput.from_dict, params['vout'])),
            params['locktime'],
        )

    @classmethod
    def decode(cls, encoded: bytes) -> 'BitcoinTransaction':
        """ Decode transaction, reverse of bytes(...).

        Examples:

        >>> bytes(BitcoinTransaction.decode(bytes.fromhex(
        ...     '0100000001f9002b8cc8aa9184e57367ad7cfb2f29899d29695202f34fcc17f7'
        ...     '6090296e48000000006b48304502210098cc550f1b487358352df20d1a0aa81b'
        ...     'f33de002519a4d1d69edc3fe36cfb799022038c54aa9f4d899328f3ec873a459'
        ...     '120e3bbeb063d6ff9ba5a30b3b2d9ced75310121020c079e1545a927a2993dc5'
        ...     'f81efc53b3ee7f946afd5a1991ac81440c4aadd2e6ffffffff01407910000000'
        ...     '00001976a914a361f2c9f91e49f7fe6cdbb76ac52fbb08dde41788ac00000000'
        ... ))).hex()
        '0100000001f9002b8cc8aa9184e57367ad7cfb2f29899d29695202f34fcc17f76090296e48000000006b48304502210098cc550f1b487358352df20d1a0aa81bf33de002519a4d1d69edc3fe36cfb799022038c54aa9f4d899328f3ec873a459120e3bbeb063d6ff9ba5a30b3b2d9ced75310121020c079e1545a927a2993dc5f81efc53b3ee7f946afd5a1991ac81440c4aadd2e6ffffffff0140791000000000001976a914a361f2c9f91e49f7fe6cdbb76ac52fbb08dde41788ac00000000'
        >>> bytes(BitcoinTransaction.decode(bytes.fromhex(
        ...     '02000000000101ab1e15a6816dc33bbcdc81ea97a89b5beaf564ecd3d03d69ca'
        ...     '5e3aed5c240cb10100000017160014fb2b0b81452bc77600667856cb57b76d76'
        ...     'd7c409ffffffff020000000000000000256a23535701966512ea19e958c9644e'
        ...     'f61d3aa0a3f5a259770d0f5e790e3aabb51bbc83d36414f262000000000017a9'
        ...     '14eb03de286e847950f63e59b374560e69372654cd8702473044022073de5314'
        ...     'e6e66cf94712430361b7e159b6f3580115a5da42161e487f7000d9de02207282'
        ...     '9af0284367a7da83c15915c937e81a2966dc9ace67fb60b6d9b52c4891560121'
        ...     '028414165c66a08425b57e63cb98e898c15d91d1d089cf848c17f208f24d89d2'
        ...     'df00000000'))).hex()
        '02000000000101ab1e15a6816dc33bbcdc81ea97a89b5beaf564ecd3d03d69ca5e3aed5c240cb10100000017160014fb2b0b81452bc77600667856cb57b76d76d7c409ffffffff020000000000000000256a23535701966512ea19e958c9644ef61d3aa0a3f5a259770d0f5e790e3aabb51bbc83d36414f262000000000017a914eb03de286e847950f63e59b374560e69372654cd8702473044022073de5314e6e66cf94712430361b7e159b6f3580115a5da42161e487f7000d9de022072829af0284367a7da83c15915c937e81a2966dc9ace67fb60b6d9b52c4891560121028414165c66a08425b57e63cb98e898c15d91d1d089cf848c17f208f24d89d2df00000000'
        """
        i = bytearray(encoded)
        version = read_int32(i)
        include_witness = read_segwit_flag(i)
        inputs = read_inputs(i, include_witness)
        outputs = read_outputs(i)
        lock_time = read_uint32(i)
        assert len(i) == 0, 'Extra bytes found'
        return cls(version, include_witness, inputs, outputs, lock_time)

    def is_coinbase(self) -> bool:
        """ Whether this transaction is a valid coinbase transaction.
        """
        return len(self.inputs) == 1 and self.inputs[0].previous_output.is_null()

    def has_witness(self) -> bool:
        """ Whether there are any witnesses on any input.
        """
        return any(i.has_witness() for i in self.inputs)


class BitcoinBlock(NamedTuple):
    header: BitcoinBlockHeader
    transactions: Sequence[Union[BitcoinRawTransaction, BitcoinTransaction]]

    def __bytes__(self) -> bytes:
        return bytes(self.header) + encode_list([bytes(t) for t in self.transactions])


def sha256d_hash(data: bytes) -> bytes:
    """ Double SHA-256 hash, bytes to bytes."""
    import hashlib
    return encode_revbytes(hashlib.sha256(hashlib.sha256(data).digest()).digest())


def encode_varint(number: int) -> bytes:
    """ Variable length integer encoding.
    """
    if number < 0xfd:
        return struct.pack('<B', number)
    elif number <= 0xffff:
        return b'\xfd' + struct.pack('<H', number)
    elif number <= 0xffff_ffff:
        return b'\xfe' + struct.pack('<I', number)
    else:
        return b'\xff' + struct.pack('<Q', number)


def encode_uint32(number: int) -> bytes:
    """ Encode unsigned 32-bit integer.
    """
    return struct.pack('<I', number)


def encode_revbytes(array: bytes) -> bytes:
    """ Return bytes in reverse order.
    """
    return bytes(reversed(array))


def encode_bytearray(array: bytes) -> bytes:
    """ Variable length bytes/bytearray encoding.
    """
    return encode_varint(len(array)) + array


def encode_list(buffer: Sequence[bytes]) -> bytes:
    """ Variable length list encoding, each element must support __bytes__ method.
    """
    return encode_varint(len(buffer)) + b''.join(buffer)


def encode_bytearray_list(buffer: List[bytes]) -> bytes:
    """ Variable length list encoding of bytes
    """
    return encode_varint(len(buffer)) + b''.join(map(encode_bytearray, buffer))


def read_int32(buffer: bytearray) -> int:
    """ Read a signed 32-bit integer, read bytes are consumed.
    """
    res, = struct.unpack('<i', buffer[:4])
    del buffer[:4]
    return res


def read_uint32(buffer: bytearray) -> int:
    """ Read an unsigned 32-bit integer, read bytes are consumed.
    """
    res, = struct.unpack('<I', buffer[:4])
    del buffer[:4]
    return res


def read_segwit_flag(buffer: bytearray) -> bool:
    """ Parse the segwit flag of the block header, read bytes are consumed.
    """
    peek, = struct.unpack('<c', buffer[:1])
    if peek == b'\00':
        i, = struct.unpack('<c', buffer[1:2])
        assert i == b'\01'
        del buffer[:2]
        return True
    return False


def read_varint(buffer: bytearray) -> int:
    """ Parse a varint, read bytes are consumed.
    """
    i, = struct.unpack('<B', buffer[:1])
    if i < 0xfd:
        del buffer[:1]
        res = i
    elif i < 0xfe:
        res, = struct.unpack('<H', buffer[1:3])
        del buffer[:3]
    elif i < 0xff:
        res, = struct.unpack('<I', buffer[1:5])
        del buffer[:5]
    else:
        res, = struct.unpack('<Q', buffer[1:9])
        del buffer[:9]
    return res


def read_outpoint(buffer: bytearray) -> BitcoinOutPoint:
    """ Parse an outpoint, read bytes are consumed.
    """
    tx_hash = bytes(buffer[:32])
    idx, = struct.unpack('<I', buffer[32:36])
    del buffer[:36]
    return BitcoinOutPoint(tx_hash, idx)


def read_nbytes(buffer: bytearray, length: int) -> bytes:
    """ Read the given number of bytes, read bytes are consumed.
    """
    array = bytes(buffer[:length])
    del buffer[:length]
    return array


def read_bytes(buffer: bytearray) -> bytes:
    """ Read a varint and then the resulting number of bytes, read bytes are consumed.
    """
    array_len = read_varint(buffer)
    array = read_nbytes(buffer, array_len)
    return array


def read_nrevbytes(buffer: bytearray, length: int) -> bytes:
    """ Read and reverse the given number of bytes, read bytes are consumed.
    """
    array = bytes(reversed(buffer[:length]))
    del buffer[:length]
    return array


def read_input(buffer: bytearray, witnesses: List[bytes] = []) -> BitcoinTransactionInput:
    """ Parse a single input, read bytes are consumed.
    """
    outpoint = read_outpoint(buffer)
    script_sig = read_bytes(buffer)
    sequence = read_uint32(buffer)
    return BitcoinTransactionInput(outpoint, script_sig, sequence, witnesses)


def read_witnesses(buffer: bytearray, input_count: int, witnesses_offset: int) -> List[List[bytes]]:
    """ Parse the list of witnesses, a list for each input, read bytes are consumed.
    """
    witnesses_buf = buffer[witnesses_offset:]
    witnesses_per_input = []
    for _ in range(input_count):
        comp_count = read_varint(witnesses_buf)
        witnesses = []
        for _ in range(comp_count):
            witnesses.append(read_bytes(witnesses_buf))
        witnesses_per_input.append(witnesses)
    del buffer[witnesses_offset:witnesses_offset + len(buffer[witnesses_offset:]) - len(witnesses_buf)]
    return witnesses_per_input


def read_inputs(buffer: bytearray, with_witnesses: bool) -> List[BitcoinTransactionInput]:
    """ Parse a list of inputs, read bytes are consumed. Optionally include witnesses.
    """
    if with_witnesses:
        len_inputs, count_inputs = skip_inputs(buffer)
        len_outputs, _count_outputs = skip_outputs(buffer[len_inputs:])
        offset_witnesses = len_inputs + len_outputs
        witnesses_per_input = read_witnesses(buffer, count_inputs, offset_witnesses)
    count = read_varint(buffer)
    inputs = []
    if with_witnesses:
        for witnesses in witnesses_per_input:
            inputs.append(read_input(buffer, witnesses))
    else:
        for _ in range(count):
            inputs.append(read_input(buffer))
    return inputs


def read_output(buffer: bytearray) -> BitcoinTransactionOutput:
    """ Parse a single output, read bytes are consumed.
    """
    value, = struct.unpack('<Q', buffer[:8])
    del buffer[:8]
    script = read_bytes(buffer)
    return BitcoinTransactionOutput(value, script)


def read_outputs(buffer: bytearray) -> List[BitcoinTransactionOutput]:
    """ Parse a list of outputs, read bytes are consumed.
    """
    count = read_varint(buffer)
    outputs = []
    for _ in range(count):
        outputs.append(read_output(buffer))
    return outputs


def skip_inputs(buffer: bytearray) -> Tuple[int, int]:
    """ Return the number of bytes read and count of inputs, but don't consume any byte.
    """
    buffer2 = buffer.copy()
    inputs = read_inputs(buffer2, False)
    return len(buffer) - len(buffer2), len(inputs)


def skip_outputs(buffer: bytearray) -> Tuple[int, int]:
    """ Return the number of bytes read and count of outputs, but don't consume any byte.
    """
    buffer2 = buffer.copy()
    outputs = read_outputs(buffer2)
    return len(buffer) - len(buffer2), len(outputs)


def create_output_script(address: bytes) -> bytes:
    """ Return the Bitcoin output script for the given address (supports P2PKH and P2SH).

    Examples:

    >>> from hathor.crypto.util import decode_address
    >>> create_output_script(decode_address('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')).hex()
    '76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac'
    >>> create_output_script(decode_address('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).hex()
    'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87'
    """
    # OPCODES: https://en.bitcoin.it/wiki/Script#Opcodes
    # Prefixes: https://en.bitcoin.it/wiki/List_of_address_prefixes
    if address[0] in {0x00, 0x6f}:  # Base58 address starts with 1.. (mainnet) or m/n.. (testnet)
        assert len(address) == 25
        # P2PKH: OP_DUP OP_HASH160 OP_PUSHBYTES_20 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        # See: https://developer.bitcoin.org/devguide/transactions.html#pay-to-public-key-hash-p2pkh
        pub_key_hash = address[1:21]
        script = bytearray()
        script.append(0x76)  # OP_DUP
        script.append(0xa9)  # OP_HASH160
        script.append(0x14)  # OP_PUSHBYTES_20
        script.extend(pub_key_hash)
        script.append(0x88)  # OP_EQUALVERIFY
        script.append(0xac)  # OP_CHECKSIG
        return bytes(script)
    elif address[0] in {0x05, 0xc4}:  # Base58 address starts with 3.. (mainnet) or 2.. (testnet)
        assert len(address) == 25
        # P2SH: OP_HASH160 OP_PUSHBYTES_20 <Hash160(redeemScript)> OP_EQUAL
        # See: https://developer.bitcoin.org/devguide/transactions.html#pay-to-script-hash-p2sh
        redeem_script_hash = address[1:21]
        script = bytearray()
        script.append(0xa9)  # OP_HASH160
        script.append(0x14)  # OP_PUSHBYTES_20
        script.extend(redeem_script_hash)
        script.append(0x87)  # OP_EQUAL
        return bytes(script)
    else:
        raise ValueError('invalid address, or address type not supported')
