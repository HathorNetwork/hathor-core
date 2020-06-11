"""
Copyright 2019 Hathor Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from typing import List, NamedTuple

from structlog import get_logger

from hathor import protos

logger = get_logger()


class BitcoinAuxPow(NamedTuple):
    header_head: bytes  # 36 bytes
    coinbase_head: bytes  # variable length (at least 47 bytes)
    coinbase_tail: bytes  # variable length (at least 18 bytes)
    merkle_path: List[bytes]  # each element has 32 bytes
    header_tail: bytes  # 12 bytes

    @classmethod
    def dummy(cls) -> 'BitcoinAuxPow':
        """ Create a minimal valid AuxPOW.
        """
        from hathor.merged_mining import MAGIC_NUMBER
        return cls(b'\0' * 36, MAGIC_NUMBER, b'', [b'\0' * 32], b'\0' * 12)

    def calculate_hash(self, base_block_hash: bytes) -> bytes:
        """ Hash of the Bitcoin produced header, this is used for the block hash.
        """
        from hathor.merged_mining.bitcoin import build_merkle_root_from_path, sha256d_hash
        coinbase_tx_hash = sha256d_hash(self.coinbase_head + base_block_hash + self.coinbase_tail)
        merkle_root = bytes(reversed(build_merkle_root_from_path([coinbase_tx_hash] + self.merkle_path)))
        return sha256d_hash(self.header_head + merkle_root + self.header_tail)

    def verify(self, _base_block_hash: bytes) -> None:
        """ Check for inconsistencies, raises instance of TxValidationError on error.
        """
        from hathor.merged_mining import MAGIC_NUMBER
        from hathor.transaction.exceptions import AuxPowError
        if not self.coinbase_head.endswith(MAGIC_NUMBER):
            raise AuxPowError('cannot find MAGIC_NUMBER')
        if MAGIC_NUMBER in self.coinbase_head[42:len(MAGIC_NUMBER)]:  # 42 first bytes can be ignored
            raise AuxPowError('multiple instances of MAGIC_NUMBER')
        if len(self.merkle_path) > 12:
            raise AuxPowError('`merkle_path` too long')
        # XXX: is there anything else that needs to be verified?

    def to_proto(self) -> protos.BitcoinAuxPow:
        """ Create Protobuf instance, all values are copied.
        """
        return protos.BitcoinAuxPow(
            header_head=self.header_head,
            coinbase_head=self.coinbase_head,
            coinbase_tail=self.coinbase_tail,
            merkle_path=self.merkle_path,
            header_tail=self.header_tail,
        )

    @classmethod
    def create_from_proto(cls, aux_pow_proto: protos.BitcoinAuxPow) -> 'BitcoinAuxPow':
        """ Create a BitcionAuxPow instance from Protobuf.
        """
        return cls(
            header_head=aux_pow_proto.header_head,
            coinbase_head=aux_pow_proto.coinbase_head,
            coinbase_tail=aux_pow_proto.coinbase_tail,
            merkle_path=list(aux_pow_proto.merkle_path),
            header_tail=aux_pow_proto.header_tail,
        )

    def __bytes__(self) -> bytes:
        """ Convert to byte representation.

        | Size | Description          | Comments |
        |------|----------------------|----------|
        | 36   | `header_head`        | first 36 bytes of the header |
        | 1+   | `coinbase_head` size | byte length of the next field |
        | 47+  | `coinbase_head`      | coinbase bytes before hash of `block_data` |
        | 1+   | `coinbase_tail` size | byte length of the next field |
        | 18+  | `coinbase_tail`      | coinbase bytes after hash of `block_data` |
        | 1+   | `merkle_path` count  | the number of links on the `merkle_path` |
        | 32+  | `merkle_path`        | array of links, each one is 32 bytes long |
        | 12   | `header_tail`        | last 12 bytes of the header |
        """
        from hathor.merged_mining.bitcoin import encode_bytearray, encode_list
        struct_bytes = self.header_head
        struct_bytes += encode_bytearray(self.coinbase_head)
        struct_bytes += encode_bytearray(self.coinbase_tail)
        struct_bytes += encode_list(self.merkle_path)
        struct_bytes += self.header_tail
        return struct_bytes

    @classmethod
    def from_bytes(cls, b: bytes) -> 'BitcoinAuxPow':
        """ Convert bytes to class instance.
        """
        from hathor.merged_mining.bitcoin import read_bytes, read_nbytes, read_varint
        a = bytearray(b)
        header_head = read_nbytes(a, 36)
        coinbase_head = read_bytes(a)
        coinbase_tail = read_bytes(a)
        c = read_varint(a)
        merkle_path = []
        for _ in range(c):
            merkle_path.append(bytes(a[:32]))
            del a[:32]
        header_tail = read_nbytes(a, 12)
        return cls(
            header_head,
            coinbase_head,
            coinbase_tail,
            merkle_path,
            header_tail,
        )
