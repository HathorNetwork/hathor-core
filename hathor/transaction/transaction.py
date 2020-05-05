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

from collections import namedtuple
from struct import pack
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from twisted.logger import Logger

from hathor import protos
from hathor.conf import HathorSettings
from hathor.transaction import MAX_NUM_INPUTS, BaseTransaction, Block, TxInput, TxOutput, TxVersion
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.exceptions import (
    ConflictingInputs,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidOutputValue,
    InvalidToken,
    NoInputError,
    RewardLocked,
    ScriptError,
    TimestampError,
    TooManyInputs,
)
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount, unpack, unpack_len

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

settings = HathorSettings()

# Version (H), token uids len (B) and inputs len (B), outputs len (B).
_FUNDS_FORMAT_STRING = '!HBBB'

# Version (H), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!HBBB'

TokenInfo = namedtuple('TokenInfo', 'amount can_mint can_melt')


class Transaction(BaseTransaction):
    log = Logger()

    SERIALIZATION_NONCE_SIZE = 4

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: int = TxVersion.REGULAR_TRANSACTION,
                 weight: float = 0,
                 inputs: Optional[List[TxInput]] = None,
                 outputs: Optional[List[TxOutput]] = None,
                 parents: Optional[List[bytes]] = None,
                 tokens: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs
                         or [], outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
        self.tokens = tokens or []
        self._height_cache = None
        self._sighash_cache1 = None
        self._sighash_cache2 = None

    @property
    def is_block(self) -> bool:
        """Returns true if this is a block"""
        return False

    @property
    def is_transaction(self) -> bool:
        """Returns true if this is a transaction"""
        return True

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.Transaction(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            parents=self.parents,
            tokens=self.tokens,
            inputs=map(TxInput.to_proto, self.inputs),
            outputs=map(TxOutput.to_proto, self.outputs),
            nonce=self.nonce,
            hash=self.hash,
        )
        if include_metadata:
            tx_proto.metadata.CopyFrom(self.get_metadata().to_proto())
        return protos.BaseTransaction(transaction=tx_proto)

    @classmethod
    def create_from_proto(cls, tx_proto: protos.BaseTransaction,
                          storage: Optional['TransactionStorage'] = None) -> 'Transaction':
        transaction_proto = tx_proto.transaction
        tx = cls(
            version=transaction_proto.version,
            weight=transaction_proto.weight,
            timestamp=transaction_proto.timestamp,
            nonce=transaction_proto.nonce,
            hash=transaction_proto.hash or None,
            parents=list(transaction_proto.parents),
            tokens=list(transaction_proto.tokens),
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

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes,
                           storage: Optional['TransactionStorage'] = None) -> 'Transaction':
        tx = cls()
        buf = tx.get_fields_from_struct(struct_bytes)

        if len(buf) != cls.SERIALIZATION_NONCE_SIZE:
            raise ValueError('Invalid sequence of bytes')

        [tx.nonce, ], buf = unpack('!I', buf)

        tx.update_hash()
        tx.storage = storage

        return tx

    def calculate_height(self) -> int:
        # XXX: transactions don't have height, using 0 as a placeholder
        return 0

    def get_funds_fields_from_struct(self, buf: bytes) -> bytes:
        """ Gets all funds fields for a transaction from a buffer.

        :param buf: Bytes of a serialized transaction
        :type buf: bytes

        :return: A buffer containing the remaining struct bytes
        :rtype: bytes

        :raises ValueError: when the sequence of bytes is incorect
        """
        (self.version, tokens_len, inputs_len, outputs_len), buf = unpack(_FUNDS_FORMAT_STRING, buf)

        for _ in range(tokens_len):
            token_uid, buf = unpack_len(TX_HASH_SIZE, buf)
            self.tokens.append(token_uid)

        for _ in range(inputs_len):
            txin, buf = TxInput.create_from_bytes(buf)
            self.inputs.append(txin)

        for _ in range(outputs_len):
            txout, buf = TxOutput.create_from_bytes(buf)
            self.outputs.append(txout)

        return buf

    def get_funds_struct(self) -> bytes:
        """Return the funds data serialization of the transaction

        :return: funds data serialization of the transaction
        :rtype: bytes
        """
        struct_bytes = pack(_FUNDS_FORMAT_STRING, self.version, len(self.tokens), len(self.inputs), len(self.outputs))

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += bytes(tx_input)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        return struct_bytes

    def get_sighash_all(self, clear_input_data: bool = True) -> bytes:
        """Return a serialization of the inputs, outputs and tokens without including any other field

        :return: Serialization of the inputs, outputs and tokens
        :rtype: bytes
        """
        if clear_input_data and self._sighash_cache1:
            return self._sighash_cache1
        elif not clear_input_data and self._sighash_cache2:
            return self._sighash_cache2

        from hathor.transaction.util import int_to_bytes
        struct_bytes = bytearray(pack(_SIGHASH_ALL_FORMAT_STRING, self.version, len(self.tokens), len(self.inputs),
                            len(self.outputs)))

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            struct_bytes += tx_input.get_sighash_bytes(clear_input_data)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        ret = bytes(struct_bytes)
        if clear_input_data:
            self._sighash_cache1 = ret
        else:
            self._sighash_cache2 = ret
        return ret

    def get_token_uid(self, index: int) -> bytes:
        """Returns the token uid with corresponding index from the tx token uid list.

        Hathor always has index 0, but we don't include it in the token uid list, so other tokens are
        always 1-off. This means that token with index 1 is the first in the list.

        :param index: token index on the token uid list
        :type index: int

        :return: the token uid
        :rtype: bytes
        """
        if index == 0:
            return settings.HATHOR_TOKEN_UID
        return self.tokens[index - 1]

    def to_json(self, decode_script: bool = False) -> Dict[str, Any]:
        json = super().to_json(decode_script)
        json['tokens'] = [h.hex() for h in self.tokens]
        return json

    def verify(self) -> None:
        """ Common verification for all transactions:
           (i) number of inputs is at most 256
          (ii) number of outputs is at most 256
         (iii) confirms at least two pending transactions
          (iv) solves the pow (we verify weight is correct in HathorManager)
           (v) validates signature of inputs
          (vi) validates public key and output (of the inputs) addresses
         (vii) validate that both parents are valid
        (viii) validate input's timestamps
          (ix) validate inputs and outputs sum
        """
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_without_storage()
        self.verify_inputs()  # need to run verify_inputs first to check if all inputs exist
        self.verify_parents()
        self.verify_sum()

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_number_of_inputs()
        self.verify_number_of_outputs()
        self.verify_outputs()

    def verify_number_of_inputs(self) -> None:
        """Verify number of inputs is in a valid range"""
        if len(self.inputs) > MAX_NUM_INPUTS:
            raise TooManyInputs('Maximum number of inputs exceeded')

        if len(self.inputs) == 0:
            if not self.is_genesis:
                raise NoInputError('Transaction must have at least one input')

    def verify_outputs(self) -> None:
        """Verify outputs reference an existing token uid in the tx list and there are no hathor
        authority UTXOs

        :raises InvalidToken: output references non existent token uid or when there's a hathor authority utxo
        """
        for index, output in enumerate(self.outputs):
            # check index is valid
            if output.get_token_index() > len(self.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

            # no hathor authority UTXO
            if (output.get_token_index() == 0) and output.is_token_authority():
                raise InvalidToken('Cannot have authority UTXO for hathor tokens: {}'.format(
                    output.to_human_readable()))

            # output value must be positive
            if output.value <= 0:
                raise InvalidOutputValue('Output value must be a positive integer. Value: {} and index: {}'.format(
                    output.value, index))

    def get_token_info_from_inputs(self) -> Dict[bytes, TokenInfo]:
        """Sum up all tokens present in the inputs and their properties (amount, can_mint, can_melt)
        """
        token_dict: Dict[bytes, TokenInfo] = {}

        default_info: TokenInfo = TokenInfo(0, False, False)

        # add HTR to token dict due to tx melting tokens: there might be an HTR output without any
        # input or authority. If we don't add it, an error will be raised when iterating through
        # the outputs of such tx (error: 'no token creation and no inputs for token 00')
        token_dict[settings.HATHOR_TOKEN_UID] = TokenInfo(0, False, False)

        for tx_input in self.inputs:
            spent_tx = self.get_spent_tx(tx_input)
            spent_output = spent_tx.outputs[tx_input.index]

            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            (amount, can_mint, can_melt) = token_dict.get(token_uid, default_info)
            if spent_output.is_token_authority():
                can_mint = can_mint or spent_output.can_mint_token()
                can_melt = can_melt or spent_output.can_melt_token()
            else:
                amount -= spent_output.value
            token_dict[token_uid] = TokenInfo(amount, can_mint, can_melt)

        return token_dict

    def update_token_info_from_outputs(self, token_dict: Dict[bytes, TokenInfo]) -> None:
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
                    token_dict[token_uid] = TokenInfo(sum_tokens, token_info.can_mint, token_info.can_melt)

    def check_authorities_and_deposit(self, token_dict: Dict[bytes, TokenInfo]) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token. If sum of inputs
        and outputs is not 0, make sure inputs have mint/melt authority.

        token_dict sums up all tokens present in the tx and their properties (amount, can_mint, can_melt)
        amount = outputs - inputs, thus:
        - amount < 0 when melting
        - amount > 0 when minting

        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        withdraw = 0
        deposit = 0
        for token_uid, token_info in token_dict.items():
            if token_uid == settings.HATHOR_TOKEN_UID:
                continue

            if token_info.amount == 0:
                # that's the usual behavior, nothing to do
                pass
            elif token_info.amount < 0:
                # tokens have been melted
                if not token_info.can_melt:
                    raise InputOutputMismatch('{} {} tokens melted, but there is no melt authority input'.format(
                        token_info.amount, token_uid.hex()))
                withdraw += get_withdraw_amount(token_info.amount)
            else:
                # tokens have been minted
                if not token_info.can_mint:
                    raise InputOutputMismatch('{} {} tokens minted, but there is no mint authority input'.format(
                        (-1) * token_info.amount, token_uid.hex()))
                deposit += get_deposit_amount(token_info.amount)

        # check whether the deposit/withdraw amount is correct
        htr_expected_amount = withdraw - deposit
        htr_info = token_dict[settings.HATHOR_TOKEN_UID]
        if htr_info.amount != htr_expected_amount:
            raise InputOutputMismatch('HTR balance is different than expected. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

    def verify_sum(self) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token.

        If there are authority UTXOs involved, tokens can be minted or melted, so the above rule may
        not be respected.

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        token_dict = self.get_token_info_from_inputs()
        self.update_token_info_from_outputs(token_dict)
        self.check_authorities_and_deposit(token_dict)

    def verify_inputs(self) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        spent_outputs: Set[Tuple[bytes, int]] = set()
        for input_tx in self.inputs:
            try:
                spent_tx = self.get_spent_tx(input_tx)
                assert spent_tx.hash is not None
                if input_tx.index >= len(spent_tx.outputs):
                    raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                        input_tx.tx_id.hex(), input_tx.index))
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(input_tx.tx_id.hex()))

            if self.timestamp <= spent_tx.timestamp:
                raise TimestampError('tx={} timestamp={}, spent_tx={} timestamp={}'.format(
                    self.hash.hex() if self.hash else None,
                    self.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            if spent_tx.is_block:
                assert isinstance(spent_tx, Block)
                self.verify_spent_reward(spent_tx)

            self.verify_script(input_tx, spent_tx)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    self.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

    def verify_spent_reward(self, block: Block) -> None:
        """ Verify that the reward being spent is old enough (has enoughs blocks after it on the best chain).

        We only consider the blocks on the best chain up to the tx's timestamp.
        """
        assert self.storage is not None
        if self._height_cache:
            best_height = self._height_cache
        else:
            # using the timestamp, we get the block immediately before this transaction in the blockchain
            tips = self.storage.get_best_block_tips(self.timestamp - 1)
            assert len(tips) > 0
            tip = self.storage.get_transaction(tips[0])
            assert tip is not None
            assert self.timestamp > tip.timestamp
            best_height = tip.get_metadata().height
            self._height_cache = best_height
        spent_height = block.get_metadata().height
        spend_blocks = best_height - spent_height
        if spend_blocks < settings.REWARD_SPEND_MIN_BLOCKS:
            raise RewardLocked(f'Reward needs {settings.REWARD_SPEND_MIN_BLOCKS} blocks to be spent, {spend_blocks} '
                               'not enough')

    def verify_script(self, input_tx: TxInput, spent_tx: BaseTransaction) -> None:
        """
        :type input_tx: TxInput
        :type spent_tx: Transaction
        """
        from hathor.transaction.scripts import script_eval
        try:
            script_eval(self, input_tx, spent_tx)
        except ScriptError as e:
            raise InvalidInputData(e) from e

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
            if spent_by and spent_by != self.hash:
                return True
        return False
