import hashlib
from collections import namedtuple
from struct import pack
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple

from twisted.logger import Logger

from hathor import protos
from hathor.conf import HathorSettings
from hathor.transaction import (
    MAX_NUM_INPUTS,
    MAX_NUM_OUTPUTS,
    BaseTransaction,
    TxInput,
    TxOutput,
    TxVersion,
    sum_weights,
)
from hathor.transaction.base_transaction import TX_HASH_SIZE
from hathor.transaction.exceptions import (
    ConflictingInputs,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidOutputValue,
    InvalidToken,
    ScriptError,
    TimestampError,
    TooManyInputs,
    TooManyOutputs,
)
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount, int_to_bytes, unpack, unpack_len

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

        tx.hash = tx.calculate_hash()
        tx.storage = storage

        return tx

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
        struct_bytes = pack(_SIGHASH_ALL_FORMAT_STRING, self.version, len(self.inputs), len(self.outputs),
                            len(self.tokens))

        for token_uid in self.tokens:
            struct_bytes += token_uid

        for tx_input in self.inputs:
            if not clear_input_data:
                struct_bytes += bytes(tx_input)
            else:
                struct_bytes += tx_input.tx_id
                struct_bytes += int_to_bytes(tx_input.index, 1)
                struct_bytes += int_to_bytes(0, 2)

        for tx_output in self.outputs:
            struct_bytes += bytes(tx_output)

        return struct_bytes

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
        """ Regular transactions have common validations and need to verify sum of inputs and outputs

        Other types of transactions with special rules should overload the verify method
        """
        self.verify_common()
        self.verify_sum()

    def verify_common(self) -> None:
        """ Common verification for all transactions:
           (i) number of inputs is at most 256
          (ii) number of outputs is at most 256
         (iii) confirms at least two pending transactions
          (iv) solves the pow (we verify weight is correct in HathorManager)
           (v) validates signature of inputs
          (vi) validates public key and output (of the inputs) addresses
         (vii) validate that both parents are valid
        (viii) validate input's timestamps
        """
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_without_storage()
        self.verify_inputs()  # need to run verify_inputs first to check if all inputs exist
        self.verify_parents()

    def verify_without_storage(self) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verify_pow()
        self.verify_number_of_inputs()
        self.verify_number_of_outputs()
        self.verify_outputs()

    def verify_number_of_inputs(self) -> None:
        """Verify number of inputs does not exceeds the limit"""
        if len(self.inputs) > MAX_NUM_INPUTS:
            raise TooManyInputs('Maximum number of inputs exceeded')

    def verify_number_of_outputs(self) -> None:
        """Verify number of outputs does not exceeds the limit"""
        if len(self.outputs) > MAX_NUM_OUTPUTS:
            raise TooManyOutputs('Maximum number of outputs exceeded')

    def verify_outputs(self) -> None:
        """Verify outputs reference an existing token uid in the tx list and there are no hathor
        authority UTXOs

        :raises InvalidToken: output references non existent token uid or when there's a hathor authority utxo
        """
        for output in self.outputs:
            # check index is valid
            if output.get_token_index() > len(self.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

            # no hathor authority UTXO
            if (output.get_token_index() == 0) and output.is_token_authority():
                raise InvalidToken('Cannot have authority UTXO for hathor tokens: {}'.format(
                    output.to_human_readable()))

    def create_token_uid(self, index: int) -> bytes:
        """Returns the token uid for a token in a given output position.

        The uid is the hash of an input_id + input_index. The input is the one whose index is the same
        as the token creation output. For eg, if the token creation UTXO is the 3rd output, we'll use
        the 3rd input for computing its uid.

        :param index: position of the token output in the output list
        :type index: int

        :return: the new token uid
        :rtype: bytes

        :raises InvalidToken: no matching input for given index
        """
        if index >= len(self.inputs):
            raise InvalidToken('no matching input for index {}'.format(index))
        _input: TxInput = self.inputs[index]
        m = hashlib.sha256()
        m.update(_input.tx_id)
        m.update(bytes([_input.index]))
        return m.digest()

    def verify_sum(self) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token.

        If there are authority UTXOs involved, tokens can be minted or melted, so the above rule may
        not be respected.

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        # token dict sums up all tokens present in the tx and their properties (amount, can_mint, can_melt)
        # amount = outputs - inputs, thus:
        # - amount < 0 when melting
        # - amount > 0 when minting
        token_dict: Dict[bytes, TokenInfo] = {}
        # created tokens contains tokens being created in this tx and the corresponding output index
        created_tokens: List[Tuple[bytes, int]] = []  # List[(token_uid, index)]

        default_info: TokenInfo = TokenInfo(0, False, False)

        # add HTR to token dict due to tx melting tokens: there's an HTR output without any
        # input or authority. If we don't add it, an error will be raised when iterating through
        # the outputs of such tx (error: 'no token creation and no inputs for token 00')
        token_dict[settings.HATHOR_TOKEN_UID] = TokenInfo(0, False, False)

        for input_tx in self.inputs:
            spent_tx = self.get_spent_tx(input_tx)
            spent_output = spent_tx.outputs[input_tx.index]

            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            (amount, can_mint, can_melt) = token_dict.get(token_uid, default_info)
            if spent_output.is_token_authority():
                can_mint = can_mint or spent_output.can_mint_token()
                can_melt = can_melt or spent_output.can_melt_token()
            else:
                amount -= spent_output.value
            token_dict[token_uid] = TokenInfo(amount, can_mint, can_melt)

        # iterate over outputs and subtract spent values from token_map
        for index, tx_output in enumerate(self.outputs):
            if tx_output.value <= 0:
                raise InvalidOutputValue('Output value must be a positive integer. Value: {} and index: {}'.format(
                    tx_output.value, index))

            token_uid = self.get_token_uid(tx_output.get_token_index())
            token_info = token_dict.get(token_uid)
            if token_info is None:
                # was not in the inputs, so it must be a new token
                if tx_output.is_token_creation():
                    created_tokens.append((token_uid, index))
                else:
                    raise InvalidToken('no token creation and no inputs for token {}'.format(token_uid.hex()))
            else:
                # for authority outputs, make sure the same capability (mint/melt) was present in the inputs
                if tx_output.can_mint_token() and not token_info.can_mint:
                    raise InvalidToken('output has mint authority, but no input has it: {}'.format(
                        tx_output.to_human_readable()))
                if tx_output.can_melt_token() and not token_info.can_melt:
                    raise InvalidToken('output has melt authority, but no input has it: {}'.format(
                        tx_output.to_human_readable()))

                # for regular outputs, just subtract from the total amount
                if not tx_output.is_token_authority():
                    sum_tokens = token_info.amount + tx_output.value
                    token_dict[token_uid] = TokenInfo(sum_tokens, token_info.can_mint, token_info.can_melt)

        # if sum of inputs and outputs is not 0, make sure inputs have mint/melt authority
        # also, calculates the required deposit and withdraw amounts of HTR
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
        htr_info = token_dict.get(settings.HATHOR_TOKEN_UID, default_info)
        if htr_info.amount != htr_expected_amount:
            raise InputOutputMismatch('HTR balance is different than expected. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

        # make sure created tokens have correct hash
        for token_uid, index in created_tokens:
            if token_uid != self.create_token_uid(index):
                raise InvalidToken('token creation with invalid uid; expecting {}, got {}; output index {}'.format(
                    self.create_token_uid(index), token_uid, index))

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
                    self.hash and self.hash.hex(),
                    self.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            self.verify_script(input_tx, spent_tx)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    self.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

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

    def update_voided_info(self) -> None:
        """ This method should be called only once when the transactions is added to the DAG.
        """
        assert self.hash is not None
        assert self.storage is not None

        voided_by: Set[bytes] = set()

        # Union of voided_by of parents
        for parent in self.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by:
                voided_by.update(parent_meta.voided_by)

        # Union of voided_by of inputs
        for txin in self.inputs:
            spent_tx = self.storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            if spent_meta.voided_by:
                voided_by.update(spent_meta.voided_by)

        # Update accumulated weight of the transactions voiding us.
        assert self.hash not in voided_by
        for h in voided_by:
            tx = self.storage.get_transaction(h)
            tx_meta = tx.get_metadata()
            tx_meta.accumulated_weight = sum_weights(tx_meta.accumulated_weight, self.weight)
            tx.storage.save_transaction(tx, only_metadata=True)

        # Then, we add ourselves.
        meta = self.get_metadata()
        assert not meta.voided_by or meta.voided_by == {self.hash}
        assert meta.accumulated_weight == self.weight
        if meta.conflict_with:
            voided_by.add(self.hash)

        if voided_by:
            meta.voided_by = voided_by.copy()
            self.storage.save_transaction(self, only_metadata=True)
            self.storage._del_from_cache(self)  # XXX: accessing private method

        # Check conflicts of the transactions voiding us.
        for h in voided_by:
            if h == self.hash:
                continue
            tx = self.storage.get_transaction(h)
            if not tx.is_block:
                tx.check_conflicts()

        # Finally, check our conflicts.
        meta = self.get_metadata()
        if meta.voided_by == {self.hash}:
            self.check_conflicts()

    def mark_as_voided(self) -> None:
        """ Mark a transaction as voided when it has a conflict and its aggregated weight
        is NOT the greatest one.
        """
        assert self.hash is not None
        self.log.debug('tx.mark_as_voided {}'.format(self.hash.hex()))
        meta = self.get_metadata()
        assert bool(meta.conflict_with)
        if meta.voided_by:
            assert self.hash in meta.voided_by
            return
        self.add_voided_by(self.hash)

    def add_voided_by(self, voided_hash: bytes) -> bool:
        """ Add a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        assert self.hash is not None
        assert self.storage is not None

        meta = self.get_metadata()
        if meta.voided_by and voided_hash in meta.voided_by:
            return False

        self.log.debug('add_voided_by tx={} voided_hash={}'.format(self.hash.hex(), voided_hash.hex()))

        from hathor.transaction.storage.traversal import BFSWalk
        bfs = BFSWalk(self.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        check_list: List[Transaction] = []
        for tx in bfs.run(self, skip_root=False):
            meta = tx.get_metadata()
            assert not meta.voided_by or voided_hash not in meta.voided_by
            if tx.hash != self.hash and meta.conflict_with and not meta.voided_by:
                check_list.extend(tx.storage.get_transaction(h) for h in meta.conflict_with)
            if meta.voided_by:
                meta.voided_by.add(voided_hash)
            else:
                meta.voided_by = {voided_hash}
            if meta.conflict_with:
                meta.voided_by.add(tx.hash)
                # All voided transactions with conflicts must have their accumulated weight calculated.
                tx.update_accumulated_weight(save_file=False)
            tx.storage.save_transaction(tx, only_metadata=True)
            tx.storage._del_from_cache(tx, relax_assert=True)  # XXX: accessing private method

        for tx in check_list:
            tx.check_conflicts()
        return True

    def mark_as_winner(self) -> None:
        """ Mark a transaction as winner when it has a conflict and its aggregated weight
        is the greatest one.
        """
        assert self.hash is not None
        self.log.debug('tx.mark_as_winner {}'.format(self.hash.hex()))
        meta = self.get_metadata()
        assert bool(meta.conflict_with)  # FIXME: this looks like a runtime guarantee, MUST NOT be an assert
        self.remove_voided_by(self.hash)

    def remove_voided_by(self, voided_hash: bytes) -> bool:
        """ Remove a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        from hathor.transaction.storage.traversal import BFSWalk

        assert self.hash is not None
        assert self.storage is not None

        meta = self.get_metadata()
        if not meta.voided_by:
            return False
        if voided_hash not in meta.voided_by:
            return False

        self.log.debug('remove_voided_by tx={} voided_hash={}'.format(self.hash.hex(), voided_hash.hex()))

        bfs = BFSWalk(self.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        check_list: List[Transaction] = []
        for tx in bfs.run(self, skip_root=False):
            meta = tx.get_metadata()
            if not (meta.voided_by and voided_hash in meta.voided_by):
                bfs.skip_neighbors(tx)
                continue
            if meta.voided_by:
                meta.voided_by.discard(voided_hash)
            if meta.voided_by == {tx.hash}:
                check_list.append(tx)
            tx.storage.save_transaction(tx, only_metadata=True)
            if not meta.voided_by:
                meta.voided_by = None
                self.storage._add_to_cache(tx)  # XXX: accessing private method

        for tx in check_list:
            tx.check_conflicts()
        return True

    def mark_inputs_as_used(self) -> None:
        """ Mark all its inputs as used
        """
        for txin in self.inputs:
            self.mark_input_as_used(txin)

    def mark_input_as_used(self, txin: 'TxInput') -> None:
        """ Mark a given input as used
        """
        assert self.hash is not None
        assert self.storage is not None

        spent_tx = self.storage.get_transaction(txin.tx_id)
        spent_meta = spent_tx.get_metadata()
        spent_by = spent_meta.spent_outputs[txin.index]  # Set[bytes(hash)]
        assert self.hash not in spent_by

        # Update our meta.conflict_with.
        meta = self.get_metadata()
        if spent_by:
            # We initially void ourselves. This conflict will be resolved later.
            if not meta.voided_by:
                meta.voided_by = {self.hash}
            else:
                meta.voided_by.add(self.hash)
            if meta.conflict_with:
                meta.conflict_with.extend(spent_by)
            else:
                meta.conflict_with = spent_by.copy()
        self.storage.save_transaction(self, only_metadata=True)

        for h in spent_by:
            # Update meta.conflict_with of our conflict transactions.
            tx = self.storage.get_transaction(h)
            tx_meta = tx.get_metadata()
            if tx_meta.conflict_with:
                tx_meta.conflict_with.append(self.hash)
            else:
                tx_meta.conflict_with = [self.hash]
            tx.storage.save_transaction(tx, only_metadata=True)

        # Add ourselves to meta.spent_by of our input.
        spent_by.append(self.hash)
        self.storage.save_transaction(spent_tx, only_metadata=True)

    def check_conflicts(self) -> None:
        """ Check which transaction is the winner of a conflict, the remaining are voided.

        The verification is made for each input, and `self` is only marked as winner if it
        wins in all its inputs.
        """
        assert self.hash is not None
        assert self.storage is not None
        self.log.debug('tx.check_conflicts {}'.format(self.hash.hex()))

        meta = self.get_metadata()
        if meta.voided_by != {self.hash}:
            return

        # Filter the possible candidates to compare to tx.
        candidates: List[Transaction] = []
        for h in meta.conflict_with or []:
            tx = self.storage.get_transaction(h)
            tx_meta = tx.get_metadata()
            if not tx_meta.voided_by or tx_meta.voided_by == {tx.hash}:
                candidates.append(tx)

        # Check whether we have the highest accumulated weight.
        # First with the voided transactions.
        is_highest = True
        for tx in candidates:
            tx_meta = tx.get_metadata()
            if tx_meta.voided_by:
                if tx_meta.accumulated_weight > meta.accumulated_weight:
                    is_highest = False
                    break
        if not is_highest:
            return

        # Then, with the executed transactions.
        tie_list = []
        for tx in candidates:
            tx_meta = tx.get_metadata()
            if not tx_meta.voided_by:
                tx.update_accumulated_weight(stop_value=meta.accumulated_weight)
                tx_meta = tx.get_metadata()
                d = tx_meta.accumulated_weight - meta.accumulated_weight
                if abs(d) < settings.WEIGHT_TOL:
                    tie_list.append(tx)
                elif d > 0:
                    is_highest = False
                    break
        if not is_highest:
            return

        # If we got here, either it was a tie or we won.
        # So, let's void the candidates.
        for tx in candidates:
            tx.mark_as_voided()

        if not tie_list:
            # If it is not a tie, we won. \o/
            self.mark_as_winner()

    def set_conflict_twins(self) -> None:
        """ Get all transactions that conflict with self
            and check if they are also a twin of self
        """
        assert self.storage is not None

        meta = self.get_metadata()
        if not meta.conflict_with:
            return

        conflict_txs = [self.storage.get_transaction(h) for h in meta.conflict_with]
        self.check_twins(conflict_txs)

    def check_twins(self, transactions: Iterable['BaseTransaction']) -> None:
        """ Check if the tx has any twins in transactions list
            A twin tx is a tx that has the same inputs and outputs
            We add all the hashes of the twin txs in the metadata

        :param transactions: list of transactions to be checked if they are twins with self
        """
        assert self.hash is not None
        assert self.storage is not None

        # Getting self metadata to save the new twins
        meta = self.get_metadata()

        # Sorting inputs and outputs for easier validation
        sorted_inputs = sorted(self.inputs, key=lambda x: (x.tx_id, x.index, x.data))
        sorted_outputs = sorted(self.outputs, key=lambda x: (x.script, x.value))

        for tx in transactions:
            assert tx.hash is not None

            # If quantity of inputs or outputs is different, it's not a twin
            # If the hash is the same it's not a twin
            if len(tx.inputs) != len(self.inputs) or len(tx.outputs) != len(self.outputs) or tx.hash == self.hash:
                continue

            # Verify if all the inputs are the same
            equal = True
            for index, tx_input in enumerate(sorted(tx.inputs, key=lambda x: (x.tx_id, x.index, x.data))):
                if (tx_input.tx_id != sorted_inputs[index].tx_id or tx_input.data != sorted_inputs[index].data
                        or tx_input.index != sorted_inputs[index].index):
                    equal = False
                    break

            # Verify if all the outputs are the same
            if equal:
                for index, tx_output in enumerate(sorted(tx.outputs, key=lambda x: (x.script, x.value))):
                    if (tx_output.value != sorted_outputs[index].value
                            or tx_output.script != sorted_outputs[index].script):
                        equal = False
                        break

            # If everything is equal we add in both metadatas
            if equal:
                meta.twins.append(tx.hash)
                tx_meta = tx.get_metadata()
                tx_meta.twins.append(self.hash)
                self.storage.save_transaction(tx, only_metadata=True)

        self.storage.save_transaction(self, only_metadata=True)

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
