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

from __future__ import annotations

import hashlib
from enum import IntEnum
from struct import pack
from typing import TYPE_CHECKING, Any, NamedTuple, Optional

from typing_extensions import override

from hathor.checkpoint import Checkpoint
from hathor.exception import InvalidNewTransaction
from hathor.transaction import TxInput, TxOutput, TxVersion
from hathor.transaction.base_transaction import TX_HASH_SIZE, GenericVertex
from hathor.transaction.exceptions import InvalidToken
from hathor.transaction.static_metadata import TransactionStaticMetadata
from hathor.transaction.util import VerboseCallback, unpack, unpack_len
from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

# Signal bits (B), version (B), token uids len (B) and inputs len (B), outputs len (B).
_FUNDS_FORMAT_STRING = '!BBBBB'

# Signal bits (B), version (B), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!BBBBB'


# used when (de)serializing token information
class TokenInfoVersion(IntEnum):
    DEPOSIT = 1
    FEE = 2


class TokenInfo(NamedTuple):
    amount: int
    can_mint: bool
    can_melt: bool
    version: TokenInfoVersion | None
    spent_outputs: list[TxOutput]
    outputs: list[TxOutput]


class RewardLockedInfo(NamedTuple):
    block_hash: VertexId
    blocks_needed: int


class Transaction(GenericVertex[TransactionStaticMetadata]):
    SERIALIZATION_NONCE_SIZE = 4

    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.REGULAR_TRANSACTION,
        weight: float = 0,
        inputs: Optional[list[TxInput]] = None,
        outputs: Optional[list[TxOutput]] = None,
        parents: Optional[list[VertexId]] = None,
        tokens: Optional[list[TokenUid]] = None,
        hash: Optional[VertexId] = None,
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
    ) -> None:
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=version,
            weight=weight,
            inputs=inputs or [],
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            settings=settings
        )
        self.tokens = tokens or []
        self._sighash_cache: Optional[bytes] = None
        self._sighash_data_cache: Optional[bytes] = None

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return False

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return True

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> 'Transaction':
        tx = cls()
        buf = tx.get_fields_from_struct(struct_bytes, verbose=verbose)

        if len(buf) != cls.SERIALIZATION_NONCE_SIZE:
            raise ValueError('Invalid sequence of bytes')

        [tx.nonce, ], buf = unpack('!I', buf)
        if verbose:
            verbose('nonce', tx.nonce)

        tx.update_hash()
        tx.storage = storage

        return tx

    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.signal_bits, self.version, tokens_len, inputs_len, outputs_len), buf = unpack(
            _FUNDS_FORMAT_STRING,
            buf
        )

        if verbose:
            verbose('signal_bits', self.signal_bits)
            verbose('version', self.version)
            verbose('tokens_len', tokens_len)
            verbose('inputs_len', inputs_len)
            verbose('outputs_len', outputs_len)

        for _ in range(tokens_len):
            token_uid, buf = unpack_len(TX_HASH_SIZE, buf)
            self.tokens.append(token_uid)
            if verbose:
                verbose('token_uid', token_uid.hex())

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf, verbose=verbose)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf, verbose=verbose)
            self.outputs.append(txout)

        return buf

    def get_funds_struct(self) -> bytes:
        """Return the funds data serialization of the transaction

        :return: funds data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(
            _FUNDS_FORMAT_STRING,
            self.signal_bits,
            self.version,
            len(self.tokens),
            len(self.inputs),
            len(self.outputs)
        )

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += bytes(tx_input)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        return struct_bytes

    def get_sighash_all(self) -> bytes:
        """Return a serialization of the inputs, outputs and tokens without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        # This method does not depend on the input itself, however we call it for each one to sign it.
        # For transactions that have many inputs there is a significant decrease on the verify time
        # when using this cache, so we call this method only once.
        if self._sighash_cache:
            return self._sighash_cache

        struct_bytes = bytearray(
            pack(
                _SIGHASH_ALL_FORMAT_STRING,
                self.signal_bits,
                self.version,
                len(self.tokens),
                len(self.inputs),
                len(self.outputs)
            )
        )

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += tx_input.get_sighash_bytes()

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        ret = bytes(struct_bytes)
        self._sighash_cache = ret
        return ret

    def get_sighash_all_data(self) -> bytes:
        """Return the sha256 hash of sighash_all"""
        if self._sighash_data_cache is None:
            self._sighash_data_cache = hashlib.sha256(self.get_sighash_all()).digest()

        return self._sighash_data_cache

    def get_token_uid(self, index: int) -> TokenUid:
        """Returns the token uid with corresponding index from the tx token uid list.

        Hathor always has index 0, but we don't include it in the token uid list, so other tokens are
        always 1-off. This means that token with index 1 is the first in the list.

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        """
        if index == 0:
            return self._settings.HATHOR_TOKEN_UID
        return self.tokens[index - 1]

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['tokens'] = [h.hex() for h in self.tokens]
        return json

    def verify_checkpoint(self, checkpoints: list[Checkpoint]) -> None:
        assert self.storage is not None
        if self.is_genesis:
            return
        meta = self.get_metadata()
        # at least one child must be checkpoint validated
        for child_tx in map(self.storage.get_transaction, meta.children):
            if child_tx.get_metadata().validation.is_checkpoint():
                return
        raise InvalidNewTransaction(f'Invalid new transaction {self.hash_hex}: expected to reach a checkpoint but '
                                    'none of its children is checkpoint-valid')

    def get_complete_token_info(self) -> dict[TokenUid, TokenInfo]:
        """
        Get a complete token info dict, including data from both inputs and outputs.
        """
        token_dict = self._get_token_info_from_inputs()
        self._update_token_info_from_outputs(token_dict=token_dict)

        return token_dict

    def _get_token_info_from_inputs(self) -> dict[TokenUid, TokenInfo]:
        """Sum up all tokens present in the inputs and their properties (amount, can_mint, can_melt)
        """

        # add HTR to token dict due to tx melting tokens: there might be an HTR output without any
        # input or authority. If we don't add it, an error will be raised when iterating through
        # the outputs of such tx (error: 'no token creation and no inputs for token 00')
        token_dict: dict[TokenUid, TokenInfo] = {
            self._settings.HATHOR_TOKEN_UID: TokenInfo(0, False, False, None, [], [])}

        for tx_input in self.inputs:
            spent_tx = self.get_spent_tx(tx_input)
            spent_output = spent_tx.outputs[tx_input.index]

            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            token_info_version: TokenInfoVersion | None = None

            if token_uid != self._settings.HATHOR_TOKEN_UID:
                assert self.storage is not None
                from hathor.transaction.token_creation_tx import TokenCreationTransaction
                token_creation_tx = self.storage.get_transaction(token_uid)
                assert isinstance(token_creation_tx, TokenCreationTransaction)
                token_info_version = token_creation_tx.token_info_version

            token_info = token_dict.get(
                 token_uid,
                 TokenInfo(amount=0, can_mint=False, can_melt=False, version=token_info_version,
                           spent_outputs=[], outputs=[]))
            amount = token_info.amount
            can_mint = token_info.can_mint
            can_melt = token_info.can_melt
            if spent_output.is_token_authority():
                can_mint = can_mint or spent_output.can_mint_token()
                can_melt = can_melt or spent_output.can_melt_token()
            else:
                amount -= spent_output.value

            token_dict[token_uid] = TokenInfo(
                amount,
                can_mint,
                can_melt,
                token_info_version,
                [*token_info.spent_outputs, spent_output],
                token_info.outputs
            )

        return token_dict

    def _update_token_info_from_outputs(self, *, token_dict: dict[TokenUid, TokenInfo]) -> None:
        """Iterate over the outputs and add values to token info dict. Updates the dict in-place.

        Also, checks if no token has authorities on the outputs not present on the inputs

        :raises InvalidToken: when there's an error in token operations
        """
        # iterate over outputs and add values to token_dict
        for index, tx_output in enumerate(self.outputs):
            token_uid = self.get_token_uid(tx_output.get_token_index())
            token_info = token_dict.get(token_uid)
            if token_info is None:
                raise InvalidToken('no inputs for token {}'.format(token_uid.hex()))
            else:
                # for authority outputs, make sure the same capability (mint/melt) was present in the inputs
                if tx_output.can_mint_token() and not token_info.can_mint:
                    raise InvalidToken('output has mint authority, but no input has it: {}'.format(
                        tx_output.to_human_readable()))
                if tx_output.can_melt_token() and not token_info.can_melt:
                    raise InvalidToken('output has melt authority, but no input has it: {}'.format(
                        tx_output.to_human_readable()))

                if tx_output.is_token_authority():
                    # make sure we only have authorities that we know of
                    if tx_output.value > TxOutput.ALL_AUTHORITIES:
                        raise InvalidToken('Invalid authorities in output (0b{0:b})'.format(tx_output.value))
                else:
                    # for regular outputs, just subtract from the total amount
                    sum_tokens = token_info.amount + tx_output.value
                    token_dict[token_uid] = TokenInfo(
                        sum_tokens,
                        token_info.can_mint,
                        token_info.can_melt,
                        token_info.version,
                        token_info.spent_outputs,
                        [*token_info.outputs, tx_output]
                    )

    def is_double_spending(self) -> bool:
        """ Iterate through inputs to check if they were already spent
            Used to prevent users from sending double spending transactions to the network
            Possible cases:
            - if spent_by is empty, which means self has not been added to the DAG yet, and it is not a double spending
            - elif spent_by == {self.hash}, which means self has been added to the DAG, and it is not a double spending
            - else, which means self has been added to the DAG, and it is a double spending.
        """
        assert self.storage is not None
        for tx_in in self.inputs:
            tx = self.storage.get_transaction(tx_in.tx_id)
            meta = tx.get_metadata()
            spent_by = meta.get_output_spent_by(tx_in.index)
            if spent_by and spent_by != self._hash:
                return True
        return False

    def is_spending_voided_tx(self) -> bool:
        """ Iterate through inputs to check if they are spending valid transactions
            Used to prevent users from sending transactions that spend a voided transaction
        """
        assert self.storage is not None
        for tx_in in self.inputs:
            tx = self.storage.get_transaction(tx_in.tx_id)
            meta = tx.get_metadata()
            if meta.voided_by:
                return True
        return False

    @override
    def init_static_metadata_from_storage(self, settings: HathorSettings, storage: 'TransactionStorage') -> None:
        static_metadata = TransactionStaticMetadata.create_from_storage(self, settings, storage)
        self.set_static_metadata(static_metadata)
