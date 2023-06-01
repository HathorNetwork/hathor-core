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

import hashlib
from itertools import chain
from struct import pack
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

from hathor import daa
from hathor.checkpoint import Checkpoint
from hathor.conf import HathorSettings
from hathor.exception import InvalidNewTransaction
from hathor.profiler import get_cpu_profiler
from hathor.transaction import MAX_NUM_INPUTS, BaseTransaction, Block, TxInput, TxOutput, TxVersion
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.exceptions import (
    ConflictingInputs,
    DuplicatedParents,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidToken,
    NoInputError,
    RewardLocked,
    ScriptError,
    TimestampError,
    TooManyInputs,
    TooManySigOps,
    WeightError,
)
from hathor.transaction.util import VerboseCallback, get_deposit_amount, get_withdraw_amount, unpack, unpack_len
from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

settings = HathorSettings()
cpu = get_cpu_profiler()

# Signal bits (B), version (B), token uids len (B) and inputs len (B), outputs len (B).
_FUNDS_FORMAT_STRING = '!BBBBB'

# Signal bits (B), version (B), inputs len (B), and outputs len (B), token uids len (B).
_SIGHASH_ALL_FORMAT_STRING = '!BBBBB'


class TokenInfo(NamedTuple):
    amount: int
    can_mint: bool
    can_melt: bool


class RewardLockedInfo(NamedTuple):
    block_hash: VertexId
    blocks_needed: int


class Transaction(BaseTransaction):

    SERIALIZATION_NONCE_SIZE = 4

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 signal_bits: int = 0,
                 version: int = TxVersion.REGULAR_TRANSACTION,
                 weight: float = 0,
                 inputs: Optional[List[TxInput]] = None,
                 outputs: Optional[List[TxOutput]] = None,
                 parents: Optional[List[VertexId]] = None,
                 tokens: Optional[List[TokenUid]] = None,
                 hash: Optional[VertexId] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(nonce=nonce, timestamp=timestamp, signal_bits=signal_bits, version=version, weight=weight,
                         inputs=inputs or [], outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
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

    def calculate_height(self) -> int:
        # XXX: transactions don't have height, using 0 as a placeholder
        return 0

    def calculate_min_height(self) -> int:
        """Calculates the min height the first block confirming this tx needs to have for reward lock verification.

        Assumes tx has been fully verified (parents and inputs exist and have complete metadata).
        """
        if self.is_genesis:
            return 0
        return max(
            # 1) don't drop the min height of any parent tx or input tx
            self._calculate_inherited_min_height(),
            # 2) include the min height for any reward being spent
            self._calculate_my_min_height(),
        )

    def _calculate_inherited_min_height(self) -> int:
        """ Calculates min height inherited from any input or parent"""
        assert self.storage is not None
        min_height = 0
        iter_parents = map(self.storage.get_transaction, self.get_tx_parents())
        iter_inputs = map(self.get_spent_tx, self.inputs)
        for tx in chain(iter_parents, iter_inputs):
            min_height = max(min_height, tx.get_metadata().min_height)
        return min_height

    def _calculate_my_min_height(self) -> int:
        """ Calculates min height derived from own spent rewards"""
        min_height = 0
        for blk in self.iter_spent_rewards():
            min_height = max(min_height, blk.get_metadata().height + settings.REWARD_SPEND_MIN_BLOCKS + 1)
        return min_height

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
            return settings.HATHOR_TOKEN_UID
        return self.tokens[index - 1]

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> Dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['tokens'] = [h.hex() for h in self.tokens]
        return json

    def verify_basic(self, skip_block_weight_verification: bool = False) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if self.is_genesis:
            # TODO do genesis validation?
            return
        self.verify_parents_basic()
        self.verify_weight()
        self.verify_without_storage()

    def verify_checkpoint(self, checkpoints: List[Checkpoint]) -> None:
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

    def verify_parents_basic(self) -> None:
        """Verify number and non-duplicity of parents."""
        assert self.storage is not None

        # check if parents are duplicated
        parents_set = set(self.parents)
        if len(self.parents) > len(parents_set):
            raise DuplicatedParents('Tx has duplicated parents: {}', [tx_hash.hex() for tx_hash in self.parents])

        if len(self.parents) != 2:
            raise IncorrectParents(f'wrong number of parents (tx type): {len(self.parents)}, expecting 2')

    def verify_weight(self) -> None:
        """Validate minimum tx difficulty."""
        min_tx_weight = daa.minimum_tx_weight(self)
        max_tx_weight = min_tx_weight + settings.MAX_TX_WEIGHT_DIFF
        if self.weight < min_tx_weight - settings.WEIGHT_TOL:
            raise WeightError(f'Invalid new tx {self.hash_hex}: weight ({self.weight}) is '
                              f'smaller than the minimum weight ({min_tx_weight})')
        elif min_tx_weight > settings.MAX_TX_WEIGHT_DIFF_ACTIVATION and self.weight > max_tx_weight:
            raise WeightError(f'Invalid new tx {self.hash_hex}: weight ({self.weight}) is '
                              f'greater than the maximum allowed ({max_tx_weight})')

    @cpu.profiler(key=lambda self: 'tx-verify!{}'.format(self.hash.hex()))
    def verify(self, reject_locked_reward: bool = True) -> None:
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
        self.verify_sigops_input()
        self.verify_inputs()  # need to run verify_inputs first to check if all inputs exist
        self.verify_parents()
        self.verify_sum()
        if reject_locked_reward:
            self.verify_reward_locked()

    def verify_unsigned_skip_pow(self) -> None:
        """ Same as .verify but skipping pow and signature verification."""
        self.verify_number_of_inputs()
        self.verify_number_of_outputs()
        self.verify_outputs()
        self.verify_sigops_output()
        self.verify_sigops_input()
        self.verify_inputs(skip_script=True)  # need to run verify_inputs first to check if all inputs exist
        self.verify_parents()
        self.verify_sum()

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_number_of_inputs()
        self.verify_outputs()
        self.verify_sigops_output()

    def verify_number_of_inputs(self) -> None:
        """Verify number of inputs is in a valid range"""
        if len(self.inputs) > MAX_NUM_INPUTS:
            raise TooManyInputs('Maximum number of inputs exceeded')

        if len(self.inputs) == 0:
            if not self.is_genesis:
                raise NoInputError('Transaction must have at least one input')

    def verify_sigops_input(self) -> None:
        """ Count sig operations on all inputs and verify that the total sum is below the limit
        """
        from hathor.transaction.scripts import get_sigops_count
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        n_txops = 0
        for tx_input in self.inputs:
            try:
                spent_tx = self.get_spent_tx(tx_input)
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(tx_input.tx_id.hex()))
            assert spent_tx.hash is not None
            if tx_input.index >= len(spent_tx.outputs):
                raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    tx_input.tx_id.hex(), tx_input.index))
            n_txops += get_sigops_count(tx_input.data, spent_tx.outputs[tx_input.index].script)

        if n_txops > settings.MAX_TX_SIGOPS_INPUT:
            raise TooManySigOps(
                'TX[{}]: Max number of sigops for inputs exceeded ({})'.format(self.hash_hex, n_txops))

    def verify_outputs(self) -> None:
        """Verify outputs reference an existing token uid in the tokens list

        :raises InvalidToken: output references non existent token uid
        """
        super().verify_outputs()
        for output in self.outputs:
            # check index is valid
            if output.get_token_index() > len(self.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

    def get_token_info_from_inputs(self) -> Dict[TokenUid, TokenInfo]:
        """Sum up all tokens present in the inputs and their properties (amount, can_mint, can_melt)
        """
        token_dict: Dict[TokenUid, TokenInfo] = {}

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

    def update_token_info_from_outputs(self, token_dict: Dict[TokenUid, TokenInfo]) -> None:
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

    def check_authorities_and_deposit(self, token_dict: Dict[TokenUid, TokenInfo]) -> None:
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

    def iter_spent_rewards(self) -> Iterator[Block]:
        """Iterate over all the rewards being spent, assumes tx has been verified."""
        for input_tx in self.inputs:
            spent_tx = self.get_spent_tx(input_tx)
            if spent_tx.is_block:
                assert isinstance(spent_tx, Block)
                yield spent_tx

    def verify_inputs(self, *, skip_script: bool = False) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        spent_outputs: Set[Tuple[VertexId, int]] = set()
        for input_tx in self.inputs:
            if len(input_tx.data) > settings.MAX_INPUT_DATA_SIZE:
                raise InvalidInputDataSize('size: {} and max-size: {}'.format(
                    len(input_tx.data), settings.MAX_INPUT_DATA_SIZE
                ))

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

            if not skip_script:
                self.verify_script(input_tx, spent_tx)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    self.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

    def verify_reward_locked(self) -> None:
        """Will raise `RewardLocked` if any reward is spent before the best block height is enough."""
        info = self.get_spent_reward_locked_info()
        if info is not None:
            raise RewardLocked(f'Reward {info.block_hash.hex()} still needs {info.blocks_needed} to be unlocked.')

    def is_spent_reward_locked(self) -> bool:
        """ Verify whether any spent reward is currently locked."""
        return self.get_spent_reward_locked_info() is not None

    def get_spent_reward_locked_info(self) -> Optional[RewardLockedInfo]:
        """ Same verification as in `is_spent_reward_locked`, but returns extra information or None for False."""
        for blk in self.iter_spent_rewards():
            assert blk.hash is not None
            needed_height = self._spent_reward_needed_height(blk)
            if needed_height > 0:
                return RewardLockedInfo(blk.hash, needed_height)
        return None

    def _spent_reward_needed_height(self, block: Block) -> int:
        """ Returns height still needed to unlock this reward: 0 means it's unlocked."""
        assert self.storage is not None
        # omitting timestamp to get the current best block, this will usually hit the cache instead of being slow
        tips = self.storage.get_best_block_tips()
        assert len(tips) > 0
        best_height = min(self.storage.get_transaction(tip).get_metadata().height for tip in tips)
        spent_height = block.get_metadata().height
        spend_blocks = best_height - spent_height
        needed_height = settings.REWARD_SPEND_MIN_BLOCKS - spend_blocks
        return max(needed_height, 0)

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
