# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from struct import pack
from typing import Any, Optional

from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.storage import NCBlockStorage
from hathor.transaction.base_transaction import TxInput, TxOutput, TxVersion
from hathor.transaction.storage import TransactionStorage  # noqa: F401
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.transaction.transaction import Transaction
from hathor.transaction.util import VerboseCallback, decode_string_utf8, int_to_bytes, unpack, unpack_len

# Signal bits (B), version (B), inputs len (B), outputs len (B)
_FUNDS_FORMAT_STRING = '!BBBB'

# Signal bist (B), version (B), inputs len (B), outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!BBBB'


class TokenCreationTransaction(Transaction):
    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.TOKEN_CREATION_TRANSACTION,
        weight: float = 0,
        inputs: Optional[list[TxInput]] = None,
        outputs: Optional[list[TxOutput]] = None,
        parents: Optional[list[bytes]] = None,
        hash: Optional[bytes] = None,
        token_name: str = '',
        token_symbol: str = '',
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
        token_version: TokenVersion = TokenVersion.DEPOSIT,
    ) -> None:
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=version,
            weight=weight,
            inputs=inputs,
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            settings=settings,
        )
        self.token_version = token_version
        self.token_name = token_name
        self.token_symbol = token_symbol
        # for this special tx, its own hash is used as the created token uid. We're artificially
        # creating the tokens list here
        self.tokens = [hash] if hash is not None else []

    def __str__(self) -> str:
        return ', '.join([
            'TokenCreationTransaction(',
            f'nonce={self.nonce}',
            f'timestamp={self.timestamp}',
            f'version={int(self.version)}',
            f'weight={self.weight}',
            f'hash={self.hash_hex}',
            f'token_name={self.token_name}',
            f'token_symbol={self.token_symbol}',
            f'token_version={self.token_version})'
        ])

    def update_hash(self) -> None:
        """ When we update the hash, we also have to update the tokens uid list
        """
        super().update_hash()
        self.tokens = [self.hash]

    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorrect
        """
        (self.signal_bits, self.version, inputs_len, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)
        if verbose:
            verbose('signal_bits', self.signal_bits)
            verbose('version', self.version)
            verbose('inputs_len', inputs_len)
            verbose('outputs_len', outputs_len)

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf, verbose=verbose)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf, verbose=verbose)
            self.outputs.append(txout)

        # token name, symbol and version
        (self.token_name, self.token_symbol, self.token_version, buf) = (
            TokenCreationTransaction.deserialize_token_info(buf, verbose=verbose))

        return buf

    def get_funds_struct(self) -> bytes:
        """ Returns the funds data serialization of the transaction

        :return: funds data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(
            _FUNDS_FORMAT_STRING,
            self.signal_bits,
            self.version,
            len(self.inputs),
            len(self.outputs)
        )

        tx_inputs = []
        for tx_input in self.inputs:
            tx_inputs.append(bytes(tx_input))
        struct_bytes += b''.join(tx_inputs)

        tx_outputs = []
        for tx_output in self.outputs:
            tx_outputs.append(bytes(tx_output))
        struct_bytes += b''.join(tx_outputs)

        struct_bytes += self.serialize_token_info()

        return struct_bytes

    def get_sighash_all(self, *, skip_cache: bool = False) -> bytes:
        """ Returns a serialization of the inputs and outputs without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        if not skip_cache and self._sighash_cache:
            return self._sighash_cache

        struct_bytes = pack(
            _SIGHASH_ALL_FORMAT_STRING,
            self.signal_bits,
            self.version,
            len(self.inputs),
            len(self.outputs)
        )

        tx_inputs = []
        for tx_input in self.inputs:
            tx_inputs.append(tx_input.get_sighash_bytes())
        struct_bytes += b''.join(tx_inputs)

        tx_outputs = []
        for tx_output in self.outputs:
            tx_outputs.append(bytes(tx_output))
        struct_bytes += b''.join(tx_outputs)

        struct_bytes += self.serialize_token_info()

        for header in self.headers:
            struct_bytes += header.get_sighash_bytes()

        self._sighash_cache = struct_bytes

        return struct_bytes

    def serialize_token_info(self) -> bytes:
        """ Returns the serialization for token name and symbol
        """
        encoded_name = self.token_name.encode('utf-8')
        encoded_symbol = self.token_symbol.encode('utf-8')

        ret = b''
        ret += int_to_bytes(self.token_version, 1)
        ret += int_to_bytes(len(encoded_name), 1)
        ret += encoded_name
        ret += int_to_bytes(len(encoded_symbol), 1)
        ret += encoded_symbol

        return ret

    @classmethod
    def deserialize_token_info(
            cls,
            buf: bytes,
            *,
            verbose: VerboseCallback = None) -> tuple[str, str, TokenVersion, bytes]:
        """ Gets the token name, symbol and version from serialized format
        """
        (raw_token_version,), buf = unpack('!B', buf)
        if verbose:
            verbose('token_version', raw_token_version)

        try:
            token_version = TokenVersion(raw_token_version)
        except ValueError:
            raise ValueError('unknown token version: {}'.format(raw_token_version))

        (name_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('token_name_len', name_len)
        name, buf = unpack_len(name_len, buf)
        if verbose:
            verbose('token_name', name)
        (symbol_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('token_symbol_len', symbol_len)
        symbol, buf = unpack_len(symbol_len, buf)
        if verbose:
            verbose('token_symbol', symbol)

        # Token name and symbol can be only utf-8 valid strings for now
        decoded_name = decode_string_utf8(name, 'Token name')
        decoded_symbol = decode_string_utf8(symbol, 'Token symbol')

        return decoded_name, decoded_symbol, token_version, buf

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    def to_json_extended(self) -> dict[str, Any]:
        json = super().to_json_extended()
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    @override
    def _get_token_info_from_inputs(self, nc_block_storage: NCBlockStorage) -> TokenInfoDict:
        token_dict = super()._get_token_info_from_inputs(nc_block_storage)

        # we add the created token's info to token_dict, as the creation tx allows for mint/melt
        token_dict[self.hash] = TokenInfo(version=self.token_version, can_mint=True, can_melt=True)

        return token_dict
