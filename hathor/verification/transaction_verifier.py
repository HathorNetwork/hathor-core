#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Transaction, TxInput
from hathor.transaction.transaction import TokenInfo
from hathor.types import TokenUid
from hathor.verification.vertex_verifier import VertexVerifier

cpu = get_cpu_profiler()


class TransactionVerifier(VertexVerifier):
    __slots__ = ()

    def verify_basic(self, tx: Transaction) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if tx.is_genesis:
            # TODO do genesis validation?
            return
        self.verify_parents_basic(tx)
        self.verify_weight(tx)
        self.verify_without_storage(tx)

    @cpu.profiler(key=lambda _, tx: 'tx-verify!{}'.format(tx.hash.hex()))
    def verify(self, tx: Transaction, *, reject_locked_reward: bool = True) -> None:
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
        if tx.is_genesis:
            # TODO do genesis validation
            return
        self.verify_without_storage(tx)
        self.verify_sigops_input(tx)
        self.verify_inputs(tx)  # need to run verify_inputs first to check if all inputs exist
        self.verify_parents(tx)
        self.verify_sum(tx)
        if reject_locked_reward:
            self.verify_reward_locked(tx)

    def verify_unsigned_skip_pow(self, tx: Transaction) -> None:
        """ Same as .verify but skipping pow and signature verification."""
        tx.verify_unsigned_skip_pow()

    def verify_parents_basic(self, tx: Transaction) -> None:
        """Verify number and non-duplicity of parents."""
        tx.verify_parents_basic()

    def verify_weight(self, tx: Transaction) -> None:
        """Validate minimum tx difficulty."""
        tx.verify_weight()

    def verify_without_storage(self, tx: Transaction) -> None:
        """ Run all verifications that do not need a storage.
        """
        tx.verify_without_storage()

    def verify_sigops_input(self, tx: Transaction) -> None:
        """ Count sig operations on all inputs and verify that the total sum is below the limit
        """
        tx.verify_sigops_input()

    def verify_inputs(self, tx: Transaction, *, skip_script: bool = False) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        tx.verify_inputs(skip_script=skip_script)

    def verify_script(self, *, tx: Transaction, input_tx: TxInput, spent_tx: BaseTransaction) -> None:
        """
        :type tx: Transaction
        :type input_tx: TxInput
        :type spent_tx: Transaction
        """
        tx.verify_script(input_tx, spent_tx)

    def verify_sum(self, tx: Transaction) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token.

        If there are authority UTXOs involved, tokens can be minted or melted, so the above rule may
        not be respected.

        :raises InvalidToken: when there's an error in token operations
        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        tx.verify_sum()

    def verify_reward_locked(self, tx: Transaction) -> None:
        """Will raise `RewardLocked` if any reward is spent before the best block height is enough, considering only
        the block rewards spent by this tx itself, and not the inherited `min_height`."""
        tx.verify_reward_locked()

    def verify_number_of_inputs(self, tx: Transaction) -> None:
        """Verify number of inputs is in a valid range"""
        tx.verify_number_of_inputs()

    def verify_outputs(self, tx: BaseTransaction) -> None:
        """Verify outputs reference an existing token uid in the tokens list

        :raises InvalidToken: output references non existent token uid
        """
        tx.verify_outputs()

    def update_token_info_from_outputs(self, tx: Transaction, *, token_dict: dict[TokenUid, TokenInfo]) -> None:
        """Iterate over the outputs and add values to token info dict. Updates the dict in-place.

        Also, checks if no token has authorities on the outputs not present on the inputs

        :raises InvalidToken: when there's an error in token operations
        """
        tx.update_token_info_from_outputs(token_dict)
