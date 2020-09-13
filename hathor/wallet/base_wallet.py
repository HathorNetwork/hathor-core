from abc import ABCMeta
from collections import defaultdict
from enum import Enum
from itertools import chain
from math import inf
from typing import TYPE_CHECKING, Any, DefaultDict, Dict, Iterable, List, NamedTuple, Optional, Tuple, Union

from structlog import get_logger
from twisted.internet.interfaces import IDelayedCall, IReactorCore
from twisted.internet.task import Clock

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.pubsub import EventArguments, HathorEvents, PubSubManager
from hathor.transaction import BaseTransaction, TxInput, TxOutput
from hathor.transaction.base_transaction import int_to_bytes
from hathor.transaction.scripts import P2PKH, create_output_script, parse_address_script
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.transaction import Transaction
from hathor.wallet.exceptions import InputDuplicated, InsufficientFunds, PrivateKeyNotFound

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from pycoin.key.Key import Key

settings = HathorSettings()
logger = get_logger()

# check interval for maybe_spent_txs
UTXO_CHECK_INTERVAL = 10
# how long a utxo might be in an intermediate state, being considered spent before we receive the tx that spends it
UTXO_SPENT_INTERVAL = 5


class WalletInputInfo(NamedTuple):
    tx_id: bytes
    index: Any  # FIXME: actually `int`, rename this field because `namedtuple` has an `index` method
    private_key: bytes


class WalletOutputInfo(NamedTuple):
    address: bytes
    value: int
    timelock: Optional[int]
    token_uid: str = settings.HATHOR_TOKEN_UID.hex()


class WalletBalance(NamedTuple):
    locked: int = 0
    available: int = 0


class WalletBalanceUpdate(NamedTuple):
    call_id: IDelayedCall
    timelock: int


class BaseWallet:
    reactor: IReactorCore
    keys: Dict[str, Any]

    class WalletType(Enum):
        # Hierarchical Deterministic Wallet
        HD = 'hd'

        # Normal key pair wallet
        KEY_PAIR = 'keypair'

    def __init__(self, directory: str = './', pubsub: Optional[PubSubManager] = None,
                 reactor: Optional[IReactorCore] = None) -> None:
        """ A wallet will hold the unspent and spent transactions

        All files will be stored in the same directory, and it should
        only contain wallet associated files.

        :param directory: where to store wallet associated files
        :type directory: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`

        :param reactor: Twisted reactor that handles the time now
        :type reactor: :py:class:`twisted.internet.Reactor`
        """
        self.log = logger.new()

        # Dict[token_id, Dict[Tuple[tx_id, index], UnspentTx]]
        self.unspent_txs: DefaultDict[bytes, Dict[Tuple[bytes, int], UnspentTx]] = defaultdict(dict)

        # Dict[token_id, Dict[Tuple[tx_id, index], UnspentTx]]
        self.maybe_spent_txs: DefaultDict[bytes, Dict[Tuple[bytes, int], UnspentTx]] = defaultdict(dict)

        # Dict[Tuple(tx_id, index), List[SpentTx]]
        # We have for each output, which txs spent it
        self.spent_txs: Dict[Tuple[bytes, int], List['SpentTx']] = defaultdict(list)

        # Save each spent tx that was voided and is not spending tokens from this wallet anymore
        self.voided_spent: Dict[Tuple[bytes, int], List['SpentTx']] = defaultdict(list)

        # Save each unspent tx that was voided and is not increasing the tokens of this wallet anymore
        self.voided_unspent: Dict[Tuple[bytes, int], UnspentTx] = {}

        # Wallet now has locked balance (with timelock) and available balance
        self.balance: Dict[bytes, WalletBalance] = defaultdict(WalletBalance)

        # WalletBalanceUpdate object to store the callLater to update the balance
        self.balance_update: Optional[WalletBalanceUpdate] = None

        self.pubsub: Optional[PubSubManager] = pubsub

        # in test mode, we assume a lot of txs will be generated and prevent creating twin txs
        self.test_mode: bool = False

        self.pubsub_events = [
            HathorEvents.STORAGE_TX_VOIDED,
            HathorEvents.STORAGE_TX_WINNER,
        ]

        if reactor is None:
            from twisted.internet import reactor as twisted_reactor
            reactor = twisted_reactor
        self.reactor = reactor

    def _manually_initialize(self) -> None:
        pass

    def start(self) -> None:
        """ Start the pubsub subscription if wallet has a pubsub
        """
        if self.pubsub:
            for event in self.pubsub_events:
                self.pubsub.subscribe(event, self.handle_publish)

        self.reactor.callLater(UTXO_CHECK_INTERVAL, self._check_utxos)

    def stop(self) -> None:
        """ Stop the pubsub subscription if wallet has a pubsub
        """
        if self.pubsub:
            for event in self.pubsub_events:
                self.pubsub.unsubscribe(event, self.handle_publish)

    def _check_utxos(self) -> None:
        """ Go through all elements in maybe_spent_txs and check if any of them should be
        moved back to unspent_txs
        """
        now = int(self.reactor.seconds())
        for token_id, utxos in self.maybe_spent_txs.items():
            for key in list(utxos):
                utxo = utxos[key]
                if utxo.maybe_spent_ts + UTXO_SPENT_INTERVAL < now:
                    utxos.pop(key)
                    utxo.maybe_spent_ts = inf
                    self.unspent_txs[token_id][key] = utxo
        self.reactor.callLater(UTXO_CHECK_INTERVAL, self._check_utxos)

    def handle_publish(self, key: HathorEvents, args: EventArguments) -> None:
        data = args.__dict__
        if key == HathorEvents.STORAGE_TX_VOIDED:
            self.on_tx_voided(data['tx'])
        elif key == HathorEvents.STORAGE_TX_WINNER:
            self.on_tx_winner(data['tx'])
        else:
            raise NotImplementedError

    def is_locked(self) -> bool:
        raise NotImplementedError

    def get_unused_address(self, mark_as_used: bool = True) -> str:
        raise NotImplementedError

    def get_unused_address_bytes(self, mark_as_used: bool = True) -> bytes:
        address_str = self.get_unused_address(mark_as_used)
        return decode_address(address_str)

    def tokens_received(self, address58: str) -> None:
        raise NotImplementedError

    def get_private_key(self, address58: str) -> 'EllipticCurvePrivateKey':
        raise NotImplementedError

    def get_input_aux_data(self, data_to_sign: bytes, private_key: 'Key') -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def prepare_transaction(self, cls: ABCMeta, inputs: List[WalletInputInfo],
                            outputs: List[WalletOutputInfo], timestamp: Optional[int] = None) -> Transaction:
        """Prepares the tx inputs and outputs.

        Can be used to create blocks by passing empty list to inputs.

        :param cls: defines if we're creating a Transaction or Block
        :type cls: :py:class:`hathor.transaction.Block` or :py:class:`hathor.transaction.Transaction`

        :param inputs: the tx inputs
        :type inputs: List[WalletInputInfo]

        :param outputs: the tx outputs
        :type inputs: List[WalletOutputInfo]

        :param timestamp: timestamp to use for the transaction
        :type timestamp: int
        """
        tx_outputs = []
        token_dict: Dict[bytes, int] = {}   # Dict[token_uid, index]
        tokens = []         # List[bytes] = List[token_uid]
        for txout in outputs:
            token_uid = bytes.fromhex(txout.token_uid)
            if token_uid == settings.HATHOR_TOKEN_UID:
                token_index = 0
            elif token_uid in token_dict:
                token_index = token_dict[token_uid]
            else:
                tokens.append(token_uid)
                token_index = len(tokens)
                token_dict[token_uid] = token_index

            timelock = int_to_bytes(txout.timelock, 4) if txout.timelock else None
            tx_outputs.append(TxOutput(txout.value, create_output_script(txout.address, timelock), token_index))

        tx_inputs = []
        private_keys = []
        for wtxin in inputs:
            private_keys.append(wtxin.private_key)
            tx_inputs.append(TxInput(wtxin.tx_id, wtxin.index, b''))

        tx = cls(inputs=tx_inputs, outputs=tx_outputs, tokens=tokens, timestamp=timestamp)
        data_to_sign = tx.get_sighash_all()

        for txin, privkey in zip(tx.inputs, private_keys):
            public_key_bytes, signature = self.get_input_aux_data(data_to_sign, privkey)
            txin.data = P2PKH.create_input_data(public_key_bytes, signature)

        return tx

    def prepare_transaction_incomplete_inputs(self, cls: ABCMeta, inputs: List[WalletInputInfo],
                                              outputs: List[WalletOutputInfo], tx_storage: TransactionStorage,
                                              force: bool = False, timestamp: Optional[int] = None) -> Transaction:
        """Uses prepare_transaction() to prepare transaction.

        The difference is that the inputs argument does not contain the private key
        corresponding to it.

        Consider the wallet UI scenario: the user will see all unspent txs and can select
        which ones he wants to use as input, but the wallet is responsible for managing
        the keys, so he won't be able to send the inputs with the corresponding key.

        :param cls: class to create the object
        :type cls: Transaction or Block

        :param inputs: list of inputs of the tx
        :type inputs: List[WalletInputInfo]

        :param outputs: list of outputs of the tx
        :type outputs: List[WalletOutputInfo]

        :param force: if True we will search the private key not only in the unspent txs
            this parameter, when set to True, can be used to allow a double spending
        :type force: bool

        :param tx_storage: storage to search for output tx
        :type tx_storage: TransactionStorage

        :param timestamp: the tx timestamp
        :type timestamp: int

        :raises PrivateKeyNotFound: when trying to spend output and we don't have the corresponding
            key in our wallet
        """
        new_inputs = self.prepare_incomplete_inputs(inputs, tx_storage, force)
        return self.prepare_transaction(cls, new_inputs, outputs, timestamp)

    def prepare_incomplete_inputs(self, inputs: List[WalletInputInfo], tx_storage: TransactionStorage,
                                  force: bool = False) -> List[WalletInputInfo]:
        """Adds the keys to the inputs

        :param inputs: list of inputs of the tx
        :type inputs: List[WalletInputInfo]

        :param force: if True we will search the private key not only in the unspent txs
            this parameter, when set to True, can be used to allow a double spending
        :type force: bool

        :param tx_storage: storage to search for output tx
        :type tx_storage: TransactionStorage

        :raises PrivateKeyNotFound: when trying to spend output and we don't have the corresponding
            key in our wallet
        """
        if len(inputs) != len(set(inputs)):
            # Same input is used more than once
            raise InputDuplicated
        new_inputs: List[WalletInputInfo] = []
        for _input in inputs:
            new_input = None
            output_tx = tx_storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_id = output_tx.get_token_uid(output.get_token_index())
            key = (_input.tx_id, _input.index)
            # we'll remove this utxo so it can't be selected again shortly
            utxo = self.unspent_txs[token_id].pop(key, None)
            if utxo is None:
                utxo = self.maybe_spent_txs[token_id].pop(key, None)
            if utxo:
                new_input = WalletInputInfo(_input.tx_id, _input.index, self.get_private_key(utxo.address))
                utxo.maybe_spent_ts = int(self.reactor.seconds())
                self.maybe_spent_txs[token_id][key] = utxo
            elif force:
                script_type = parse_address_script(output.script)

                if script_type:
                    address = script_type.address
                    if address in self.keys:
                        new_input = WalletInputInfo(_input.tx_id, _input.index, self.get_private_key(address))

            if new_input:
                new_inputs.insert(0, new_input)
            else:
                raise PrivateKeyNotFound

        return new_inputs

    def prepare_transaction_compute_inputs(self, cls: ABCMeta, outputs: List[WalletOutputInfo],
                                           timestamp: Optional[int] = None) -> Transaction:
        """Calculates the inputs given the outputs and uses prepare_transaction() to prepare
        transaction. Handles change.

        :param cls: defines if we're creating a Transaction or Block
        :type cls: :py:class:`hathor.transaction.Block` or :py:class:`hathor.transaction.Transaction`

        :param outputs: the tx outputs
        :type outputs: List[WalletOutputInfo]

        :param timestamp: the tx timestamp
        :type timestamp: int
        """
        inputs, outputs = self.prepare_compute_inputs(outputs, timestamp)
        return self.prepare_transaction(cls, inputs, outputs, timestamp)

    def prepare_compute_inputs(
        self, outputs: List[WalletOutputInfo], timestamp: Optional[int] = None
    ) -> Tuple[List[WalletInputInfo], List[WalletOutputInfo]]:
        """Calculates the inputs given the outputs. Handles change.

        :param outputs: the tx outputs
        :type outputs: List[WalletOutputInfo]

        :param timestamp: the tx timestamp
        :type timestamp: int
        """
        token_dict: Dict[bytes, int] = defaultdict(int)
        for output in outputs:
            token_uid = bytes.fromhex(output.token_uid)
            token_dict[token_uid] += output.value

        max_spent_ts = None
        if timestamp is not None:
            max_spent_ts = timestamp - 1
        tx_inputs = []
        for token_uid, amount in token_dict.items():
            inputs, total_inputs_amount = self.get_inputs_from_amount(amount, token_uid, max_spent_ts)
            change_tx = self.handle_change_tx(total_inputs_amount, amount, token_uid)
            if change_tx:
                # change is usually the first output
                outputs.insert(0, change_tx)
            tx_inputs.extend(inputs)
        return tx_inputs, outputs

    def separate_inputs(self, inputs: List['TxInput'],
                        tx_storage: 'TransactionStorage') -> Tuple[List['TxInput'], List['TxInput']]:
        """Separates the inputs from a tx into 2 groups: the ones that belong to this wallet and the ones that don't

        :param inputs: transaction to decode
        :type inputs: List[py:class:`hathor.transaction.TxInput`]

        :return my_inputs: list of all inputs belonging to this wallet
        :rtype my_inputs: List[py:class:`hathor.transaction.TxInput`]

        :param tx_storage: storage to search for output tx
        :type tx_storage: TransactionStorage

        :return other_inputs: list of all inputs NOT belonging to this wallet
        :rtype other_inputs: List[py:class:`hathor.transaction.TxInput`]
        """
        my_inputs = []
        other_inputs = []
        for _input, address58 in self.match_inputs(inputs, tx_storage):
            if address58:
                my_inputs.append(_input)
            else:
                other_inputs.append(_input)

        return my_inputs, other_inputs

    def sign_transaction(self, tx: Transaction, tx_storage: 'TransactionStorage') -> None:
        """Signs a transaction. Iterates over all inputs and signs the ones belonging to this wallet.

        :param tx: transaction to sign
        :type tx: py:class:`hathor.transaction.Transaction`

        :param tx_storage: storage to search for output tx
        :type tx_storage: TransactionStorage

        :return: there's no return. This function modifies the tx given to it
        :rtype: None
        """
        data_to_sign = tx.get_sighash_all()

        for _input, address58 in self.match_inputs(tx.inputs, tx_storage):
            if address58:
                public_key_bytes, signature = self.get_input_aux_data(data_to_sign, self.get_private_key(address58))
                _input.data = P2PKH.create_input_data(public_key_bytes, signature)

    def handle_change_tx(self, sum_inputs: int, sum_outputs: int,
                         token_uid: bytes = settings.HATHOR_TOKEN_UID) -> Optional[WalletOutputInfo]:
        """Creates an output transaction with the change value

        :param sum_inputs: Sum of the input amounts
        :type sum_inputs: int

        :param sum_outputs: Total value we're spending
        :type outputs: int

        :param token_uid: token uid of this utxo
        :type token_uid: bytes

        :return: Return an output with the change
        :rtype: :py:class:`hathor.wallet.base_wallet.WalletOutputInfo`
        """
        if sum_inputs > sum_outputs:
            difference = sum_inputs - sum_outputs
            address_b58 = self.get_unused_address()
            address = decode_address(address_b58)
            # Changes txs don't have timelock
            new_output = WalletOutputInfo(address, difference, None, token_uid.hex())
            return new_output
        return None

    def get_inputs_from_amount(self, amount: int, token_uid: bytes = settings.HATHOR_TOKEN_UID,
                               max_ts: Optional[int] = None) -> Tuple[List[WalletInputInfo], int]:
        """Creates inputs from our pool of unspent tx given a value

        This is a very simple algorithm, so it does not try to find the best combination
        of inputs.

        :param amount: amount requested
        :type amount: int

        :param token_uid: the token uid for the requested amount
        :type token_uid: bytes

        :param max_ts: maximum timestamp the inputs can have
        :type max_ts: int

        :raises InsufficientFunds: if the wallet does not have enough ballance
        """
        inputs_tx = []
        total_inputs_amount = 0

        utxos = self.unspent_txs[token_uid]
        for utxo in utxos.values():
            if (max_ts is not None and utxo.timestamp > max_ts) or utxo.test_used:
                continue
            if not utxo.is_locked(self.reactor) and not utxo.is_token_authority():
                # I can only use the outputs that are not locked and are not an authority utxo
                inputs_tx.append(WalletInputInfo(utxo.tx_id, utxo.index, self.get_private_key(utxo.address)))
                total_inputs_amount += utxo.value

                if total_inputs_amount >= amount:
                    break

            if total_inputs_amount >= amount:
                break

        if total_inputs_amount < amount:
            raise InsufficientFunds('Requested amount: {} / Available: {}'.format(amount, total_inputs_amount))

        for _input in inputs_tx:
            utxo = self.unspent_txs[token_uid].pop((_input.tx_id, _input.index))
            utxo.maybe_spent_ts = int(self.reactor.seconds())
            self.maybe_spent_txs[token_uid][(_input.tx_id, _input.index)] = utxo

        return inputs_tx, total_inputs_amount

    def on_new_tx(self, tx: BaseTransaction) -> None:
        """Checks the inputs and outputs of a transaction for matching keys.

        If an output matches, will add it to the unspent_txs dict.
        If an input matches, removes from unspent_txs dict and adds to spent_txs dict.
        """
        assert tx.hash is not None

        updated = False

        # check outputs
        for index, output in enumerate(tx.outputs):
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                if script_type_out.address in self.keys:
                    token_id = tx.get_token_uid(output.get_token_index())
                    # this wallet received tokens
                    utxo = UnspentTx(tx.hash, index, output.value, tx.timestamp, script_type_out.address,
                                     output.token_data, timelock=script_type_out.timelock)
                    self.unspent_txs[token_id][(tx.hash, index)] = utxo
                    # mark key as used
                    self.tokens_received(script_type_out.address)
                    updated = True
                    # publish new output and new balance
                    self.publish_update(HathorEvents.WALLET_OUTPUT_RECEIVED, total=self.get_total_tx(), output=utxo)
            else:
                # it's the only one we know, so log warning
                self.log.warn('unknown script')

        # check inputs
        for _input in tx.inputs:
            assert tx.storage is not None
            output_tx = tx.storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_id = output_tx.get_token_uid(output.get_token_index())

            script_type_out = parse_address_script(output.script)
            if script_type_out:
                if script_type_out.address in self.keys:
                    # this wallet spent tokens
                    # remove from unspent_txs
                    key = (_input.tx_id, _input.index)
                    old_utxo = self.unspent_txs[token_id].pop(key, None)
                    if old_utxo is None:
                        old_utxo = self.maybe_spent_txs[token_id].pop(key, None)
                    if old_utxo:
                        # add to spent_txs
                        spent = SpentTx(tx.hash, _input.tx_id, _input.index, old_utxo.value, tx.timestamp)
                        self.spent_txs[key].append(spent)
                        updated = True
                        # publish spent output and new balance
                        self.publish_update(HathorEvents.WALLET_INPUT_SPENT, output_spent=spent)
                    else:
                        # If we dont have it in the unspent_txs, it must be in the spent_txs
                        # So we append this spent with the others
                        if key in self.spent_txs:
                            output_tx = tx.storage.get_transaction(_input.tx_id)
                            output = output_tx.outputs[_input.index]
                            spent = SpentTx(tx.hash, _input.tx_id, _input.index, output.value, tx.timestamp)
                            self.spent_txs[key].append(spent)
            else:
                self.log.warn('unknown input data')

        if updated:
            # TODO update history file?
            # XXX should wallet always update it or it will be called externally?
            self.update_balance()

    def on_tx_voided(self, tx: Transaction) -> None:
        """ This method is called when a tx is voided in a conflict
            We use it to update the balance and the variable that stores it
            We check it's outputs and inputs to update wallet information

            For outputs we have the following situations:

            . Not used yet, so it's still in the unspent_txs, we remove it from there and decrease the balance
            . Already used, so it's in spent_txs, we remove from there
            . Not found anywhere, so it was already updated in another conflict resolution

            For inputs we have the following situations:

            . If it's in the unspent_txs, we have to do nothing
            . If it's in the spent_txs, we remove from the array. If this was the last tx, we recreate in the unspent

            :param tx: Transaction that was voided
            :type tx: :py:class:`hathor.transaction.Transaction`
        """
        assert tx.hash is not None
        assert tx.storage is not None

        should_update = False

        # check outputs
        for index, tx_output in enumerate(tx.outputs):
            script_type_out = parse_address_script(tx_output.script)
            token_id = tx.get_token_uid(tx_output.get_token_index())
            if script_type_out:
                if script_type_out.address in self.keys:
                    # Remove this output from unspent_tx, if still there
                    key = (tx.hash, index)
                    utxo = self.unspent_txs[token_id].pop(key, None)
                    if utxo is None:
                        utxo = self.maybe_spent_txs[token_id].pop(key, None)
                    if utxo:
                        # Output found: update balance
                        should_update = True
                    else:
                        # If it is in spent tx, remove from dict
                        if key in self.spent_txs:
                            should_update = True
                            del self.spent_txs[key]

                    # Save in voided_unspent, if it's not there yet
                    # First try to find it in voided_unspent
                    voided_utxo = self.voided_unspent.get(key, None)
                    if not voided_utxo:
                        # If it's not there, we add it
                        voided = UnspentTx(tx.hash, index, tx_output.value, tx.timestamp, script_type_out.address,
                                           tx_output.token_data, voided=True, timelock=script_type_out.timelock)
                        self.voided_unspent[key] = voided
                        should_update = True

        # check inputs
        for _input in tx.inputs:
            output_tx = tx.storage.get_transaction(_input.tx_id)
            output_ = output_tx.outputs[_input.index]
            script_type_out = parse_address_script(output_.script)
            token_id = output_tx.get_token_uid(output_.get_token_index())
            if script_type_out:
                if script_type_out.address in self.keys:
                    output: Optional[TxOutput] = None
                    # Try to find in spent tx
                    key = (_input.tx_id, _input.index)
                    if key in self.spent_txs:
                        list_index = -1
                        for i, spent in enumerate(self.spent_txs[key]):
                            if (spent.tx_id == tx.hash and spent.from_index == _input.index
                                    and spent.from_tx_id == _input.tx_id):
                                list_index = i
                                break

                        if list_index > -1:
                            # Spent found: remove from list
                            spent = self.spent_txs[key].pop(list_index)

                            if len(self.spent_txs[key]) == 0:
                                # If this was the last input that spent this output, we recreate the output
                                output_tx = tx.storage.get_transaction(spent.from_tx_id)
                                output = output_tx.outputs[spent.from_index]
                                assert output is not None

                                script_type_out = parse_address_script(output.script)
                                if script_type_out and script_type_out.address in self.keys:
                                    utxo = UnspentTx(_input.tx_id, _input.index, output.value,
                                                     output_tx.timestamp, script_type_out.address,
                                                     output.token_data, timelock=script_type_out.timelock)
                                    self.unspent_txs[token_id][key] = utxo

                            should_update = True

                    # Save in voided_spent, if it's not there yet
                    # First try to find it in voided_spent
                    voided_stxi_list = self.voided_spent.get(key, [])
                    list_index = -1
                    for i, spent in enumerate(voided_stxi_list):
                        if (spent.tx_id == tx.hash and spent.from_index == _input.index
                                and spent.from_tx_id == _input.tx_id):
                            list_index = i
                            break
                    if list_index == -1:
                        # If it's not there, we add it
                        if output is None:
                            output_tx = tx.storage.get_transaction(_input.tx_id)
                            output = output_tx.outputs[_input.index]

                        voided_spent = SpentTx(tx.hash, _input.tx_id, _input.index, output.value, tx.timestamp,
                                               voided=True)
                        self.voided_spent[key].append(voided_spent)
                        should_update = True

        if should_update:
            # update balance
            self.update_balance()
            # publish update history
            self.publish_update(HathorEvents.WALLET_HISTORY_UPDATED)

    def on_tx_winner(self, tx: Transaction) -> None:
        """ This method is called when a tx is set as winner of a conflict
            We use it to update the balance and the variable that stores it
            We check it's outputs and inputs to update wallet information

            For outputs we have the following situations:

            . In case it's in the spent or unspent we do nothing
            . In case is not found, it was deleted because of a previous conflict, so we recreate in the unspent

            For inputs we have the following situations:

            . If it's in the unspent_txs, we remove from there and add in the spent_txs
            . If it's in the spent_txs, we do nothing
            . If it's not in both, we add in the spent_txs

            :param tx: Transaction that was voided
            :type tx: :py:class:`hathor.transaction.Transaction`
        """
        assert tx.hash is not None
        assert tx.storage is not None

        should_update = False
        # check outputs
        for index, output in enumerate(tx.outputs):
            script_type_out = parse_address_script(output.script)
            token_id = tx.get_token_uid(output.get_token_index())
            if script_type_out:
                if script_type_out.address in self.keys:
                    # Find output
                    key = (tx.hash, index)
                    utxo = self.unspent_txs[token_id].get(key)
                    if utxo is None:
                        utxo = self.maybe_spent_txs[token_id].get(key)
                    if not utxo:
                        # Not found in unspent
                        # Try to find in spent tx
                        if key not in self.spent_txs or len(self.spent_txs[key]) == 0:
                            # If it's not in unspet or spent it was deleted, so we create again in the unspent
                            utxo = UnspentTx(tx.hash, index, output.value, tx.timestamp, script_type_out.address,
                                             output.token_data, timelock=script_type_out.timelock)
                            self.unspent_txs[token_id][key] = utxo

                    # Remove from voided_unspent, if it's there
                    voided_utxo = self.voided_unspent.pop(key, None)
                    if voided_utxo:
                        # If it's there, we should update
                        should_update = True

        # check inputs
        for _input in tx.inputs:
            output_tx = tx.storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_id = output_tx.get_token_uid(output.get_token_index())

            script_type_out = parse_address_script(output.script)
            if script_type_out:
                if script_type_out.address in self.keys:
                    key = (_input.tx_id, _input.index)
                    # Remove from voided_spent, if it's there
                    # First try to find it in voided_spent
                    voided_stxi_list = self.voided_spent.get(key, [])
                    list_index = -1
                    for i, spent in enumerate(voided_stxi_list):
                        if (spent.tx_id == tx.hash and spent.from_index == _input.index
                                and spent.from_tx_id == _input.tx_id):
                            list_index = i
                            break
                    if list_index > -1:
                        # If it's there, we remove it
                        self.voided_spent[key].pop(list_index)
                        should_update = True

                    # Remove from unspent_txs, if it's there
                    old_utxo = self.unspent_txs[token_id].pop(key, None)
                    if old_utxo is None:
                        old_utxo = self.maybe_spent_txs[token_id].pop(key, None)
                    if old_utxo:
                        # add to spent_txs
                        spent = SpentTx(tx.hash, _input.tx_id, _input.index, old_utxo.value, tx.timestamp)
                        self.spent_txs[(_input.tx_id, _input.index)].append(spent)
                        should_update = True
                        continue

                    # If we dont have it in the unspent_txs, we check in the spent txs
                    # Try to find in spent tx
                    found = False
                    if key in self.spent_txs:
                        list_index = -1
                        for i, spent in enumerate(self.spent_txs[key]):
                            if (spent.tx_id == tx.hash and spent.from_index == _input.index
                                    and spent.from_tx_id == _input.tx_id):
                                list_index = i
                                break

                        if list_index > -1:
                            found = True

                    if not found:
                        # If spent not found, we recreate it
                        # Get tx from output to get the value
                        output_tx = tx.storage.get_transaction(_input.tx_id)
                        output = output_tx.outputs[_input.index]

                        spent = SpentTx(tx.hash, _input.tx_id, _input.index, output.value, tx.timestamp)
                        self.spent_txs[key].append(spent)
                        should_update = True

        if should_update:
            # update balance
            self.update_balance()
            # publish update history
            self.publish_update(HathorEvents.WALLET_HISTORY_UPDATED)

    def get_history(self, count: int = 10, page: int = 1) -> Tuple[List[Union['SpentTx', 'UnspentTx']], int]:
        """Return the last transactions in this wallet ordered by timestamp and the total

        :rtype: tuple[list[SpentTx, UnspentTx], int]
        """
        history: List[Union['SpentTx', 'UnspentTx']] = []

        for obj_dict in self.unspent_txs.values():
            history += obj_dict.values()

        for obj_dict in self.maybe_spent_txs.values():
            history += obj_dict.values()

        for obj_list in self.spent_txs.values():
            history += obj_list

        history += self.voided_unspent.values()

        for obj_list in self.voided_spent.values():
            history += obj_list

        ordered_history = sorted(history, key=lambda el: el.timestamp, reverse=True)

        total = len(ordered_history)
        start_index = (page - 1) * count
        end_index = start_index + count

        return ordered_history[start_index:end_index], total

    def get_total_tx(self) -> int:
        """Return the total number of transactions that happened in this wallet (to and from the wallet)

        :rtype: int
        """
        total_unspent = sum([len(utxo_dict) for utxo_dict in self.unspent_txs.values()])
        total_maybe_spent = sum([len(utxo_dict) for utxo_dict in self.maybe_spent_txs.values()])
        return total_unspent + total_maybe_spent + len(self.spent_txs)

    def publish_update(self, event: HathorEvents, **kwargs: Any) -> None:
        """ Executes pubsub publish if pubsub is defined in the Wallet
        """
        if self.pubsub:
            self.pubsub.publish(event, **kwargs)

    def update_balance(self) -> None:
        """ Calculate the balance of the wallet considering locked and not locked outputs
        """
        smallest_timestamp = inf
        for token_id, utxos in self.unspent_txs.items():
            balance = {'locked': 0, 'available': 0}
            for utxo in chain(utxos.values(), self.maybe_spent_txs[token_id].values()):
                if utxo.is_token_authority():
                    # authority utxos don't transfer value
                    continue
                if utxo.is_locked(self.reactor):
                    assert utxo.timelock is not None
                    balance['locked'] += utxo.value
                    smallest_timestamp = min(smallest_timestamp, utxo.timelock)
                else:
                    balance['available'] += utxo.value

            self.balance[token_id] = WalletBalance(balance['locked'], balance['available'])

        self.should_schedule_update(smallest_timestamp)

        # publish new balance
        self.publish_update(HathorEvents.WALLET_BALANCE_UPDATED, balance=self.balance)

    def should_schedule_update(self, smallest_timestamp: float) -> None:
        """ Checks if we need to schedule a balance update for later

        :param smallest_timestamp: smallest lock timestamp of an UTXO
        :type smallest_timestamp: float (usually an int, but might be inf)
        """
        if smallest_timestamp < inf:
            # We have an unspent tx that is locked
            if self.balance_update:
                if self.balance_update.timelock == smallest_timestamp:
                    # It's already scheduled for the smallest timelock
                    return
                elif self.balance_update.timelock > smallest_timestamp:
                    # Cancel the scheduled call to create one for the smallest timestamp
                    self.balance_update.call_id.cancel()

            # Create the new balance update
            diff = smallest_timestamp - int(self.reactor.seconds()) + 1
            call_id = self.reactor.callLater(diff, self.update_balance)
            self.balance_update = WalletBalanceUpdate(call_id, int(smallest_timestamp))
        else:
            # If dont have any other timelock, set balance update to None
            self.balance_update = None

    def match_inputs(self, inputs: List[TxInput],
                     tx_storage: TransactionStorage) -> Iterable[Tuple[TxInput, Optional[str]]]:
        """Returns an iterable with the inputs that belong and don't belong to this wallet

        :return: An iterable with the inputs and corresponding address, if it belongs to this wallet
        :rtype: Iterable[(TxInput, str(base58))]
        """
        for _input in inputs:
            output_tx = tx_storage.get_transaction(_input.tx_id)
            output = output_tx.outputs[_input.index]
            token_id = output_tx.get_token_uid(output.get_token_index())
            utxo = self.unspent_txs[token_id].get((_input.tx_id, _input.index))
            if utxo is None:
                utxo = self.maybe_spent_txs[token_id].get((_input.tx_id, _input.index))
            # is it in our wallet?
            if utxo:
                yield _input, utxo.address
            else:
                # we couldn't find the UTXO, so it's not ours
                yield _input, None


class UnspentTx:
    def __init__(self, tx_id: bytes, index: int, value: int, timestamp: int, address: str, token_data: int,
                 voided: bool = False, timelock: Optional[int] = None) -> None:
        self.tx_id = tx_id
        self.index = index
        self.value = value
        self.timestamp = timestamp
        self.address = address
        self.token_data = token_data
        self.voided = voided
        self.timelock = timelock
        self.test_used = False      # flag to prevent twin txs being created (for tests only!!)
        self.maybe_spent_ts = inf

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data['timestamp'] = self.timestamp
        data['tx_id'] = self.tx_id.hex()
        data['index'] = self.index
        data['value'] = self.value
        data['address'] = self.address
        data['token_data'] = self.token_data
        data['voided'] = self.voided
        data['timelock'] = self.timelock
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UnspentTx':
        return cls(bytes.fromhex(data['tx_id']), data['index'], data['value'], data['timestamp'], data['address'],
                   data['token_data'], data['voided'], data['timelock'])

    def is_locked(self, reactor: Clock) -> bool:
        """ Returns if the unspent tx is locked or available to be spent

            :param reactor: reactor to get the current time
            :type reactor: :py:class:`twisted.internet.Reactor`

            :return: if the unspent tx is locked
            :rtype: bool
        """
        if self.timelock is None or self.timelock < int(reactor.seconds()):
            return False
        else:
            return True

    def is_token_authority(self) -> bool:
        """Whether this is a token authority utxo"""
        return (self.token_data & TxOutput.TOKEN_AUTHORITY_MASK) > 0


class SpentTx:
    def __init__(self, tx_id: bytes, from_tx_id: bytes, from_index: int, value: int, timestamp: int,
                 voided: bool = False) -> None:
        """tx_id: the tx spending the output
        from_tx_id: tx where we received the tokens
        from_index: index in the above tx
        """
        self.tx_id = tx_id
        self.from_tx_id = from_tx_id
        self.from_index = from_index
        self.value = value
        self.timestamp = timestamp
        self.voided = voided

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data['timestamp'] = self.timestamp
        data['tx_id'] = self.tx_id.hex()
        data['from_tx_id'] = self.from_tx_id.hex()
        data['from_index'] = self.from_index
        data['value'] = self.value
        data['voided'] = self.voided
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SpentTx':
        return cls(
            bytes.fromhex(data['tx_id']), bytes.fromhex(data['from_tx_id']), data['from_index'], data['value'],
            data['timestamp'])
