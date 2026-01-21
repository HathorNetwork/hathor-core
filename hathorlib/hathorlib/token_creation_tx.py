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
from enum import IntEnum
from struct import error as StructError, pack
from typing import Tuple

from hathorlib.base_transaction import TxInput, TxOutput
from hathorlib.conf import HathorSettings
from hathorlib.exceptions import TransactionDataError
from hathorlib.scripts import DataScript
from hathorlib.transaction import Transaction
from hathorlib.utils import clean_token_string, int_to_bytes, unpack, unpack_len

settings = HathorSettings()

# Signal bits (B), version (B), inputs len (B), outputs len (B)
_FUNDS_FORMAT_STRING = '!BBBB'

# Signal bist (B), version (B), inputs len (B), outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!BBBB'


# used when (de)serializing token information
# version 1 is the default behavior
class TokenVersion(IntEnum):
    NATIVE = 0
    DEPOSIT = 1
    FEE = 2


class TokenCreationTransaction(Transaction):
    def __init__(self) -> None:
        super().__init__()
        # for this special tx, its own hash is used as the created token uid. We're artificially
        # creating the tokens list here
        self.tokens = []
        self.token_version: TokenVersion = TokenVersion.DEPOSIT

    def __str__(self) -> str:
        return (
            f'TokenCreationTransaction(nonce={self.nonce}, '
            f'timestamp={self.timestamp}, '
            f'version={int(self.version)}, '
            f'weight={self.weight:.6f}, '
            f'hash={self.hash_hex}, '
            f'token_name={self.token_name}, '
            f'token_symbol={self.token_symbol}, '
            f'token_version={self.token_version})'
        )

    def update_hash(self) -> None:
        """ When we update the hash, we also have to update the tokens uid list
        """
        super().update_hash()
        assert self.hash is not None
        self.tokens = [self.hash]

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.signal_bits, self.version, inputs_len, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf)
            self.outputs.append(txout)

        # token name and symbol
        (
            self.token_name,
            self.token_symbol,
            self.token_version,
            buf
        ) = TokenCreationTransaction.deserialize_token_info(buf)

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

    def get_sighash_all(self, clear_input_data: bool = True) -> bytes:
        """ Returns a serialization of the inputs and outputs without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        struct_bytes = pack(
            _SIGHASH_ALL_FORMAT_STRING,
            self.signal_bits,
            self.version,
            len(self.inputs),
            len(self.outputs)
        )

        tx_inputs = []
        for tx_input in self.inputs:
            tx_inputs.append(tx_input.get_sighash_bytes(clear_input_data))
        struct_bytes += b''.join(tx_inputs)

        tx_outputs = []
        for tx_output in self.outputs:
            tx_outputs.append(bytes(tx_output))
        struct_bytes += b''.join(tx_outputs)

        struct_bytes += self.serialize_token_info()

        for header in self.headers:
            struct_bytes += header.get_sighash_bytes()

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
    def deserialize_token_info(cls, buf: bytes) -> Tuple[str, str, TokenVersion, bytes]:
        """ Gets the token name, symbol and version from serialized format
        """
        (raw_token_version,), buf = unpack('!B', buf)
        try:
            token_version = TokenVersion(raw_token_version)
        except ValueError:
            raise ValueError('unknown token version: {}'.format(raw_token_version))

        (name_len,), buf = unpack('!B', buf)
        name, buf = unpack_len(name_len, buf)

        (symbol_len,), buf = unpack('!B', buf)
        symbol, buf = unpack_len(symbol_len, buf)

        # Token name and symbol can be only utf-8 valid strings for now
        decoded_name = decode_string_utf8(name, 'Token name')
        decoded_symbol = decode_string_utf8(symbol, 'Token symbol')

        return decoded_name, decoded_symbol, token_version, buf

    def verify_token_info(self) -> None:
        """ Validates token info
        """
        name_len = len(self.token_name)
        symbol_len = len(self.token_symbol)
        if name_len == 0 or name_len > settings.MAX_LENGTH_TOKEN_NAME:
            raise TransactionDataError('Invalid token name length ({})'.format(name_len))
        if symbol_len == 0 or symbol_len > settings.MAX_LENGTH_TOKEN_SYMBOL:
            raise TransactionDataError('Invalid token symbol length ({})'.format(symbol_len))

        # Can't create token with hathor name or symbol
        if clean_token_string(self.token_name) == clean_token_string(settings.HATHOR_TOKEN_NAME):
            raise TransactionDataError('Invalid token name ({})'.format(self.token_name))
        if clean_token_string(self.token_symbol) == clean_token_string(settings.HATHOR_TOKEN_SYMBOL):
            raise TransactionDataError('Invalid token symbol ({})'.format(self.token_symbol))

        # Can't create the token with NATIVE version
        if self.token_version == TokenVersion.NATIVE:
            raise TransactionDataError('Invalid token version ({})'.format(self.token_version))

    def is_nft_creation_standard(self) -> bool:
        """Returns True if it's a standard NFT creation transaction"""
        # We will check the outputs to validate that we have an NFT standard creation
        # https://github.com/HathorNetwork/rfcs/blob/master/text/0032-nft-standard.md#transaction-standard
        if len(self.outputs) < 2:
            # NFT creation must have at least a DataScript output (the first one) and a Token P2PKH output
            return False

        first_output = self.outputs[0]
        parsed_first_output = DataScript.parse_script(first_output.script)

        if parsed_first_output is None:
            # First output is not a DataScript output
            return False

        if first_output.value != 1 or first_output.token_data != 0:
            # NFT creation DataScript output must have value 1 and must be of HTR
            return False

        if not first_output.is_standard_script(only_standard_script_type=False):
            # Here we check that the script size is standard
            return False

        for output in self.outputs[1:]:
            if not output.is_standard_script():
                # Invalid output script for an NFT creation tx
                return False

            if output.get_token_index() not in [0, 1]:
                # All output (except the first) must be of HTR or the created token
                return False

        return True


def decode_string_utf8(encoded: bytes, key: str) -> str:
    """ Raises StructError in case it's not a valid utf-8 string
    """
    try:
        decoded = encoded.decode('utf-8')
        return decoded
    except UnicodeDecodeError:
        raise StructError('{} must be a valid utf-8 string.'.format(key))
