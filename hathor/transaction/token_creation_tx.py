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

from struct import error as StructError, pack
from typing import Any, Dict, List, Optional, Tuple

from hathor import protos
from hathor.conf import HathorSettings
from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.exceptions import InvalidToken, TransactionDataError
from hathor.transaction.storage import TransactionStorage  # noqa: F401
from hathor.transaction.transaction import TokenInfo
from hathor.transaction.util import clean_token_string, int_to_bytes, unpack, unpack_len

settings = HathorSettings()

# Version (H), inputs len (B), outputs len (B)
_FUNDS_FORMAT_STRING = '!HBB'

# Version (H), inputs len (B), outputs len (B)
_SIGHASH_ALL_FORMAT_STRING = '!HBB'

# used when (de)serializing token information
# version 1 expects only token name and symbol
TOKEN_INFO_VERSION = 1


class TokenCreationTransaction(Transaction):
    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: int = TxVersion.TOKEN_CREATION_TRANSACTION,
                 weight: float = 0,
                 inputs: Optional[List[TxInput]] = None,
                 outputs: Optional[List[TxOutput]] = None,
                 parents: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None,
                 token_name: str = '',
                 token_symbol: str = '',
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs,
                         outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
        self.token_name = token_name
        self.token_symbol = token_symbol
        # for this special tx, its own hash is used as the created token uid. We're artificially
        # creating the tokens list here
        self.tokens = [hash] if hash is not None else []

    def __str__(self) -> str:
        return ('TokenCreationTransaction(nonce=%d, timestamp=%s, version=%s, weight=%f, hash=%s,'
                'token_name=%s, token_symbol=%s)' % (self.nonce, self.timestamp, int(self.version),
                                                     self.weight, self.hash_hex, self.token_name, self.token_symbol))

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.TokenCreationTransaction(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            parents=self.parents,
            inputs=map(TxInput.to_proto, self.inputs),
            outputs=map(TxOutput.to_proto, self.outputs),
            token_info=self.serialize_token_info(),
            nonce=self.nonce,
            hash=self.hash,
        )
        if include_metadata:
            tx_proto.metadata.CopyFrom(self.get_metadata().to_proto())
        return protos.BaseTransaction(tokenCreationTransaction=tx_proto)

    @classmethod
    def create_from_proto(cls, tx_proto: protos.BaseTransaction,
                          storage: Optional['TransactionStorage'] = None) -> 'Transaction':
        transaction_proto = tx_proto.tokenCreationTransaction
        name, symbol, _ = cls.deserialize_token_info(transaction_proto.token_info)
        tx = cls(
            version=transaction_proto.version,
            weight=transaction_proto.weight,
            timestamp=transaction_proto.timestamp,
            nonce=transaction_proto.nonce,
            hash=transaction_proto.hash or None,
            parents=list(transaction_proto.parents),
            token_name=name,
            token_symbol=symbol,
            inputs=list(map(TxInput.create_from_proto, transaction_proto.inputs)),
            outputs=list(map(TxOutput.create_from_proto, transaction_proto.outputs)),
            storage=storage,
        )
        if transaction_proto.HasField('metadata'):
            from hathor.transaction import TransactionMetadata

            # make sure hash is not empty
            tx.hash = tx.hash or tx.calculate_hash()
            tx._metadata = TransactionMetadata.create_from_proto(tx.hash, transaction_proto.metadata)
        return tx

    def update_hash(self) -> None:
        """ When we update the hash, we also have to update the tokens uid list
        """
        super().update_hash()
        assert self.hash is not None
        self.tokens = [self.hash]

    def resolve(self, update_time: bool = True) -> bool:
        ret = super().resolve(update_time)
        assert self.hash is not None
        self.tokens = [self.hash]
        return ret

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.version, inputs_len, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf)
            self.outputs.append(txout)

        # token name and symbol
        self.token_name, self.token_symbol, buf = TokenCreationTransaction.deserialize_token_info(buf)

        return buf

    def get_funds_struct(self) -> bytes:
        """ Returns the funds data serialization of the transaction

        :return: funds data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(_FUNDS_FORMAT_STRING, self.version, len(self.inputs), len(self.outputs))

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

    def get_sighash_all(self) -> bytes:
        """ Returns a serialization of the inputs and outputs without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        if self._sighash_cache:
            return self._sighash_cache

        struct_bytes = pack(_SIGHASH_ALL_FORMAT_STRING, self.version, len(self.inputs), len(self.outputs))

        tx_inputs = []
        for tx_input in self.inputs:
            tx_inputs.append(tx_input.get_sighash_bytes())
        struct_bytes += b''.join(tx_inputs)

        tx_outputs = []
        for tx_output in self.outputs:
            tx_outputs.append(bytes(tx_output))
        struct_bytes += b''.join(tx_outputs)

        struct_bytes += self.serialize_token_info()
        self._sighash_cache = struct_bytes

        return struct_bytes

    def serialize_token_info(self) -> bytes:
        """ Returns the serialization for token name and symbol
        """
        encoded_name = self.token_name.encode('utf-8')
        encoded_symbol = self.token_symbol.encode('utf-8')

        ret = b''
        ret += int_to_bytes(TOKEN_INFO_VERSION, 1)
        ret += int_to_bytes(len(encoded_name), 1)
        ret += encoded_name
        ret += int_to_bytes(len(encoded_symbol), 1)
        ret += encoded_symbol
        return ret

    @classmethod
    def deserialize_token_info(cls, buf: bytes) -> Tuple[str, str, bytes]:
        """ Gets the token name and symbol from serialized format
        """
        (token_info_version,), buf = unpack('!B', buf)
        if token_info_version != TOKEN_INFO_VERSION:
            raise ValueError('unknown token info version: {}'.format(token_info_version))

        (name_len,), buf = unpack('!B', buf)
        name, buf = unpack_len(name_len, buf)
        (symbol_len,), buf = unpack('!B', buf)
        symbol, buf = unpack_len(symbol_len, buf)

        # Token name and symbol can be only utf-8 valid strings for now
        decoded_name = decode_string_utf8(name, 'Token name')
        decoded_symbol = decode_string_utf8(symbol, 'Token symbol')

        return decoded_name, decoded_symbol, buf

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> Dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    def to_json_extended(self) -> Dict[str, Any]:
        json = super().to_json_extended()
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    def verify(self) -> None:
        """ Run all validations as regular transactions plus validation on token info.

        We also overload verify_sum to make some different checks
        """
        super().verify()
        self.verify_token_info()

    def verify_sum(self) -> None:
        """ Besides all checks made on regular transactions, a few extra ones are made:
        - only HTR tokens on the inputs;
        - new tokens are actually being minted;

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        token_dict = self.get_token_info_from_inputs()

        # we add the created token's info to token_dict, as the creation tx allows for mint/melt
        assert self.hash is not None
        token_dict[self.hash] = TokenInfo(0, True, True)

        self.update_token_info_from_outputs(token_dict)

        # make sure tokens are being minted
        token_info = token_dict[self.hash]
        if token_info.amount <= 0:
            raise InvalidToken('Token creation transaction must mint new tokens')

        self.check_authorities_and_deposit(token_dict)

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


def decode_string_utf8(encoded: bytes, key: str) -> str:
    """ Raises StructError in case it's not a valid utf-8 string
    """
    try:
        decoded = encoded.decode('utf-8')
        return decoded
    except UnicodeDecodeError:
        raise StructError('{} must be a valid utf-8 string.'.format(key))
