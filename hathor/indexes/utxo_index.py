# Copyright 2022 Hathor Labs
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

from abc import abstractmethod
from dataclasses import dataclass
from typing import Iterator, Optional

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction, Block, TxOutput
from hathor.transaction.scripts import parse_address_script
from hathor.util import sorted_merger

logger = get_logger()

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=True,
)


@dataclass(frozen=True)
class UtxoIndexItem:
    token_uid: bytes
    tx_id: bytes
    index: int
    address: str
    amount: int
    timelock: Optional[int]
    heightlock: Optional[int]

    def __repr__(self):
        return (
            'UtxoIndexItem('
            f'token_uid={self.token_uid.hex()},'
            f'tx_id={self.tx_id.hex()},'
            f'index={self.index},'
            f'address={self.address},'
            f'amount={self.amount},'
            f'timelock={self.timelock},'
            f'heightlock={self.heightlock}'
            ')'
        )

    @classmethod
    def from_tx_output(cls, tx: BaseTransaction, index: int, tx_output: TxOutput) -> 'UtxoIndexItem':
        settings = get_global_settings()

        if tx_output.is_token_authority():
            raise ValueError('UtxoIndexItem cannot be used with a token authority output')

        address_script = parse_address_script(tx_output.script)
        if address_script is None:
            raise ValueError('UtxoIndexItem can only be used with scripts supported by `parse_address_script`')

        heightlock: Optional[int]
        if isinstance(tx, Block):
            heightlock = tx.get_height() + settings.REWARD_SPEND_MIN_BLOCKS
        else:
            heightlock = None
        # XXX: timelock forced to None when there is a heightlock
        timelock: Optional[int] = address_script.get_timelock() if heightlock is None else None
        # XXX: that is, at least one of them must but None
        assert timelock is None or heightlock is None

        return cls(
            token_uid=tx.get_token_uid(tx_output.get_token_index()),
            tx_id=tx.hash,
            index=index,
            address=address_script.address,
            amount=tx_output.value,
            timelock=timelock,
            heightlock=heightlock,
        )


def _should_skip_output(tx_output: TxOutput) -> bool:
    if tx_output.is_token_authority():
        return True
    if parse_address_script(tx_output.script) is None:
        return True
    return False


class UtxoIndex(BaseIndex):
    """ Index of UTXOs by address+token

    This index is currently optional and only used for an optional API.

    It is expected to be called with only non-voided transactions and blocks, including the genesis. It ignores
    token-authority outputs and data-only outputs, generally outputs that don't have an amount or a script where an
    address can be extracted from.
    """

    def __init__(self, *, settings: HathorSettings) -> None:
        super().__init__(settings=settings)
        self.log = logger.new()

    # interface methods provided by the base class

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.update(tx)

    def update(self, tx: BaseTransaction) -> None:
        tx_meta = tx.get_metadata()
        if tx_meta.voided_by:
            self._update_voided(tx)
        else:
            self._update_executed(tx)

    def del_tx(self, tx: BaseTransaction) -> None:
        self._update_voided(tx)

    def _update_executed(self, tx: BaseTransaction) -> None:
        """ This method processes both inputs and output from a transaction.

        - mark transaction as added
        - inputs are removed from the index
        """
        tx_meta = tx.get_metadata()
        assert not tx_meta.voided_by
        log = self.log.new(tx=tx.hash_hex)
        log.debug('update executed')
        # remove all inputs
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            # Use resolve_spent_output for shielded-aware lookup
            resolved = spent_tx.resolve_spent_output(tx_input.index)
            if not isinstance(resolved, TxOutput):
                # Shielded outputs don't have public value/token for the UTXO index
                continue
            spent_tx_output = resolved
            log_it = log.new(tx_id=spent_tx.hash_hex, index=tx_input.index)
            if _should_skip_output(spent_tx_output):
                log_it.debug('ignore input')
                continue
            log_it.debug('remove output that became spent')
            self._remove_utxo(UtxoIndexItem.from_tx_output(spent_tx, tx_input.index, spent_tx_output))
        # add outputs that aren't spent
        for index, tx_output in enumerate(tx.outputs):
            log_it = log.new(index=index)
            if _should_skip_output(tx_output):
                log_it.debug('ignore output')
                continue
            spent_by = tx_meta.get_output_spent_by(index)
            if spent_by is not None:
                log_it.debug('do not add output that is spent', spent_by=spent_by.hex())
                continue
            log_it.debug('add new unspent output')
            self._add_utxo(UtxoIndexItem.from_tx_output(tx, index, tx_output))

    def _update_voided(self, tx: BaseTransaction) -> None:
        """ This method does the opposite of _update_executed when processing the given transaction.

        - inputs are added back to the index
        - outpus are removed from the index
        """
        tx_meta = tx.get_metadata()
        assert tx_meta.voided_by
        log = self.log.new(tx=tx.hash_hex)
        log.debug('update voided')
        # remove all outputs
        for index, tx_output in enumerate(tx.outputs):
            log_it = log.new(index=index)
            if _should_skip_output(tx_output):
                log_it.debug('ignore output')
                continue
            log_it.debug('remove voided output')
            self._remove_utxo(UtxoIndexItem.from_tx_output(tx, index, tx_output))
        # re-add inputs that aren't voided
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            # Use resolve_spent_output for shielded-aware lookup
            resolved = spent_tx.resolve_spent_output(tx_input.index)
            if not isinstance(resolved, TxOutput):
                # Shielded outputs don't have public value/token for the UTXO index
                continue
            spent_tx_output = resolved
            log_it = log.new(tx_id=spent_tx.hash_hex, index=tx_input.index)
            if _should_skip_output(spent_tx_output):
                log_it.debug('ignore input')
                continue
            if spent_tx.get_metadata().voided_by:
                log_it.debug('do not re-add input that spend voided')
                continue
            spent_tx_meta = spent_tx.get_metadata()
            spent_by = spent_tx_meta.get_output_spent_by(tx_input.index)
            if spent_by is not None and spent_by != tx.hash:
                log_it.debug('do not re-add input that is spent by other tx', spent_by=spent_by.hex())
                continue
            log_it.debug('re-add input that became unspent')
            self._add_utxo(UtxoIndexItem.from_tx_output(spent_tx, tx_input.index, spent_tx_output))

    def iter_utxos(self, *, address: str, target_amount: int, token_uid: Optional[bytes] = None,
                   target_timestamp: Optional[int] = None,
                   target_height: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        """ Search UTXOs for a given token_uid+address+target_value, if no token_uid is given, HTR is assumed.
        """
        settings = get_global_settings()
        actual_token_uid = token_uid if token_uid is not None else settings.HATHOR_TOKEN_UID
        iter_nolock = self._iter_utxos_nolock(token_uid=actual_token_uid, address=address,
                                              target_amount=target_amount)
        iter_timelock = self._iter_utxos_timelock(token_uid=actual_token_uid, address=address,
                                                  target_amount=target_amount,
                                                  target_timestamp=target_timestamp)
        iter_heightlock = self._iter_utxos_heightlock(token_uid=actual_token_uid, address=address,
                                                      target_amount=target_amount,
                                                      target_height=target_height)
        iter_utxos = sorted_merger(
            iter_nolock,
            iter_timelock,
            iter_heightlock,
            key=lambda item: (item.amount, item.tx_id, item.index),
            reverse=True,
        )

        next_higher: Optional[UtxoIndexItem] = None
        amount_sum = 0
        count_utxos = 0
        # we may have up to 3 items with amount higher than target_amount, skip until we get one lower, then yield it
        # and start counting the amount_sum
        for utxo_item in iter_utxos:
            if utxo_item.amount >= target_amount:
                next_higher = utxo_item
            else:
                amount_sum += utxo_item.amount
                count_utxos += 1
                if next_higher is not None:
                    yield next_higher
                yield utxo_item
                break
        else:
            # XXX: because we didn't break, yield next_higher now
            if next_higher is not None:
                yield next_higher
        # now that the next higher is out of the way, continue from where we were and stop when we reach a sum enough
        # to cover the target amount
        for utxo_item in iter_utxos:
            if amount_sum >= target_amount:
                break
            # there's also no point in yielding more outputs than can be used as inputs, if there are more, the caller
            # will just have to use the larger than target_amount UTXO (if there is any), or consolidate UTXOs first
            if count_utxos >= settings.MAX_NUM_INPUTS:
                break
            amount_sum += utxo_item.amount
            count_utxos += 1
            yield utxo_item

    # internal methods that the base class needs to be implemented

    @abstractmethod
    def _add_utxo(self, item: UtxoIndexItem) -> None:
        """ Internal method to add a UTXO and its associated data.

        Note: this method is MUST BE idempotent, calling _add_utxo a second time MUST NOT fail.
        Note: timelock and heightlock CANNOT be both not None, that is AT MOST one will be given.
        """
        raise NotImplementedError

    @abstractmethod
    def _remove_utxo(self, item: UtxoIndexItem) -> None:
        """ Internal method to add a UTXO and its associated data.

        Note: this method is MUST BE idempotent, calling _remove_utxo a second time MUST NOT fail.
        """
        raise NotImplementedError

    # all of the iterators should start with the next UTXO with amount higher than target_amount, if there are any, and
    # then yield UTXOs with amounts in decreasing order until there are no more UTXOs

    @abstractmethod
    def _iter_utxos_nolock(self, *, token_uid: bytes, address: str, target_amount: int) -> Iterator[UtxoIndexItem]:
        """Iterate over all UTXOs that DO NOT HAVE any locks."""
        raise NotImplementedError

    @abstractmethod
    def _iter_utxos_timelock(self, *, token_uid: bytes, address: str, target_amount: int,
                             target_timestamp: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        """Iterate over all UTXOs that ONLY HAVE timelocks that will be unlocked at target_timestamp."""
        raise NotImplementedError

    @abstractmethod
    def _iter_utxos_heightlock(self, *, token_uid: bytes, address: str, target_amount: int,
                               target_height: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        """Iterate over all UTXOs that ONLY HAVE heightlocks that will be unlocked at target_height."""
        raise NotImplementedError
