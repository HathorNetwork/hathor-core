import hashlib
from collections import namedtuple
from itertools import chain
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Set, Tuple

from hathor import protos
from hathor.constants import HATHOR_TOKEN_UID
from hathor.transaction import MAX_NUM_INPUTS, MAX_NUM_OUTPUTS, BaseTransaction, TxInput, TxOutput
from hathor.transaction.exceptions import (
    ConflictingInputs,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidToken,
    ScriptError,
    TimestampError,
    TooManyInputs,
    TooManyOutputs,
)

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

TokenInfo = namedtuple('TokenInfo', 'amount can_mint can_melt')


class Transaction(BaseTransaction):
    def __init__(self, nonce: int = 0, timestamp: Optional[int] = None, version: int = 1, weight: float = 0,
                 height: int = 0, inputs: Optional[List[TxInput]] = None, outputs: Optional[List[TxOutput]] = None,
                 parents: Optional[List[bytes]] = None, tokens: Optional[List[bytes]] = None,
                 hash: Optional[bytes] = None, storage: Optional['TransactionStorage'] = None) -> None:
        """
            Creating new init just to make sure inputs will always be empty array
            Inputs: all inputs that are being used (empty in case of a block)
        """
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, height=height, inputs=inputs
                         or [], outputs=outputs or [], parents=parents or [], tokens=tokens or [], hash=hash,
                         storage=storage, is_block=False)

    def to_proto(self, include_metadata: bool = True) -> protos.BaseTransaction:
        tx_proto = protos.Transaction(
            version=self.version,
            weight=self.weight,
            timestamp=self.timestamp,
            height=self.height,
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
            height=transaction_proto.height,
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

    def verify(self) -> None:
        """
            We have to do the following verifications:
               (i) spends only unspent outputs
              (ii) sum of inputs is equal to the sum of outputs
             (iii) number of inputs is at most 256
              (iv) number of outputs is at most 256
               (v) confirms at least two pending transactions
              (vi) solves the pow with the correct weight (done in HathorManager)
             (vii) validates signature of inputs
            (viii) validates public key and output (of the inputs) addresses
              (ix) validate that both parents are valid
               (x) validate input's timestamps
        """
        if self.is_genesis:
            # TODO do genesis validation
            return
        self.verify_without_storage()
        self.verify_inputs()  # need to run verify_inputs first to check if all inputs exist
        self.verify_sum()
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
        # token dict sums up all tokens present in the tx and their properties (amount, mint, melt)
        token_dict: Dict[bytes, TokenInfo] = {}
        # created tokens contains tokens being created in this tx and the corresponding output index
        created_tokens: List[Tuple[bytes, int]] = []  # List[(token_uid, index)]

        default_info: TokenInfo = TokenInfo(0, False, False)

        for input_tx in self.inputs:
            spent_tx = self.get_spent_tx(input_tx)
            spent_output = spent_tx.outputs[input_tx.index]

            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            (amount, can_mint, can_melt) = token_dict.get(token_uid, default_info)
            if spent_output.is_token_authority():
                can_mint = can_mint or spent_output.can_mint_token()
                can_melt = can_melt or spent_output.can_melt_token()
            else:
                amount += spent_output.value
            token_dict[token_uid] = TokenInfo(amount, can_mint, can_melt)

        # iterate over outputs and subtract spent values from token_map
        for index, tx_output in enumerate(self.outputs):
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
                    sum_tokens = token_info.amount - tx_output.value
                    token_dict[token_uid] = TokenInfo(sum_tokens, token_info.can_mint, token_info.can_melt)

        # if sum of inputs and outputs is not 0, make sure inputs have mint/melt authority
        for token_uid, token_info in token_dict.items():
            if token_info.amount == 0:
                # that's the usual behavior, nothing to do
                pass
            elif token_uid == HATHOR_TOKEN_UID:
                raise InputOutputMismatch('Sum of inputs is different than the sum of outputs (difference: {})'.format(
                    token_info.amount))
            elif token_info.amount > 0:
                # tokens have been melted
                if not token_info.can_melt:
                    raise InputOutputMismatch('{} {} tokens melted, but there is no melt authority input'.format(
                        token_info.amount, token_uid.hex()))
            else:
                # tokens have been minted
                if not token_info.can_mint:
                    raise InputOutputMismatch('{} {} tokens minted, but there is no mint authority input'.format(
                        (-1) * token_info.amount, token_uid.hex()))

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
                raise TimestampError('tx={} timestamp={}, parent={} timestamp={}'.format(
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

    def get_spent_tx(self, input_tx: TxInput) -> BaseTransaction:
        # TODO Maybe we could use a TransactionCacheStorage in the future to reduce storage hit
        try:
            spent_tx = input_tx._tx
        except AttributeError:
            assert self.storage is not None
            spent_tx = self.storage.get_transaction(input_tx.tx_id)
            input_tx._tx = spent_tx
        return spent_tx

    def update_voided_info(self) -> None:
        """ Transaction's voided_by must equal the union of the voided_by of both its parents and its inputs.
        """
        assert self.hash is not None
        assert self.storage is not None

        voided_by = set()

        for parent in self.get_parents():
            parent_meta = parent.get_metadata()
            voided_by.update(parent_meta.voided_by)

        for txin in self.inputs:
            spent_tx = self.storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            voided_by.update(spent_meta.voided_by)

        meta = self.get_metadata()
        if self.hash in meta.voided_by:
            voided_by.add(self.hash)

        if voided_by:
            self.storage._del_from_cache(self)  # XXX: accessing private method

        if meta.voided_by != voided_by:
            meta.voided_by = voided_by.copy()
            self.storage.save_transaction(self, only_metadata=True)

        for h in voided_by:
            if h == self.hash:
                continue
            tx = self.storage.get_transaction(h)
            if not tx.is_block:
                tx.check_conflicts()

    def mark_as_voided(self) -> None:
        """ Mark a transaction as voided when it has a conflict and its aggregated weight
        is NOT the greatest one.
        """
        assert self.hash is not None
        meta = self.get_metadata()
        assert (len(meta.conflict_with) > 0)
        self.add_voided_by(self.hash)

    def add_voided_by(self, voided_hash: bytes) -> bool:
        """ Add a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        assert self.hash is not None
        assert self.storage is not None

        meta = self.get_metadata()
        if voided_hash in meta.voided_by:
            return False

        check_conflicts = False
        if meta.conflict_with and not meta.voided_by:
            check_conflicts = True

        it = chain(
            meta.children,
            chain(*meta.spent_outputs.values()),
        )
        for tx_hash in it:
            tx = self.storage.get_transaction(tx_hash)
            tx.add_voided_by(voided_hash)

        meta.voided_by.add(voided_hash)
        self.storage.save_transaction(self, only_metadata=True)
        self.storage._del_from_cache(self)  # XXX: accessing private method

        if check_conflicts:
            self.check_conflicts()

        return True

    def mark_as_winner(self) -> None:
        """ Mark a transaction as winner when it has a conflict and its aggregated weight
        is the greatest one.
        """
        assert self.hash is not None
        meta = self.get_metadata()
        assert (len(meta.conflict_with) > 0)  # FIXME: this looks like a runtime guarantee, MUST NOT be an assert
        self.remove_voided_by(self.hash)

    def remove_voided_by(self, voided_hash: bytes) -> bool:
        """ Remove a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        assert self.hash is not None
        assert self.storage is not None

        meta = self.get_metadata()
        if voided_hash not in meta.voided_by:
            return False

        meta.voided_by.discard(voided_hash)
        self.storage.save_transaction(self, only_metadata=True)

        if not meta.voided_by:
            self.storage._add_to_cache(self)

        it = chain(
            meta.children,
            chain(*meta.spent_outputs.values()),
        )
        for tx_hash in it:
            tx = self.storage.get_transaction(tx_hash)
            tx.remove_voided_by(voided_hash)

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
        spent_by.add(self.hash)
        self.storage.save_transaction(spent_tx, only_metadata=True)

        if len(spent_by) > 1:
            for h in spent_by:
                tx = self.storage.get_transaction(h)
                tx_meta = tx.get_metadata()
                tx_meta.conflict_with.update(spent_by)
                tx_meta.conflict_with.discard(tx.hash)
                tx.storage.save_transaction(tx, only_metadata=True)

        self.check_conflicts()

    def check_conflicts(self) -> None:
        """ Check which transaction is the winner of a conflict, the remaining are voided.
        """
        assert self.hash is not None
        assert self.storage is not None

        meta = self.get_metadata(force_reload=True)
        if not meta.conflict_with:
            return

        meta = self.update_accumulated_weight()

        # Conflicting transaction.
        tx_list = [self]
        winner_set = set()
        max_acc_weight = 0.0

        if len(meta.voided_by - set([self.hash])) == 0:
            winner_set.add(self.hash)
            max_acc_weight = meta.accumulated_weight

        for h in meta.conflict_with:
            # now we need to update accumulated weight and get new metadata info
            tx = self.storage.get_transaction(h)
            meta = tx.update_accumulated_weight()
            assert tx.hash is not None
            assert meta.hash is not None
            tx_list.append(tx)

            if len(meta.voided_by - set([tx.hash])) > 0:
                continue

            if meta.accumulated_weight == max_acc_weight:
                winner_set.add(meta.hash)
            elif meta.accumulated_weight > max_acc_weight:
                max_acc_weight = meta.accumulated_weight
                winner_set = set([meta.hash])

        if len(winner_set) > 1:
            winner_set = set()

        for tx in tx_list:
            if tx.hash in winner_set:
                tx.mark_as_winner()
            else:
                tx.mark_as_voided()

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

        # Sorting inputs and outputs to easir validation
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
                meta.twins.add(tx.hash)
                tx_meta = tx.get_metadata()
                tx_meta.twins.add(self.hash)
                self.storage.save_transaction(tx, only_metadata=True)

        self.storage.save_transaction(self, only_metadata=True)
