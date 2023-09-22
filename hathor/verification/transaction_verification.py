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
from hathor.transaction import Transaction

cpu = get_cpu_profiler()


def verify_basic(transaction: Transaction) -> None:
    """Partially run validations, the ones that need parents/inputs are skipped."""
    if transaction.is_genesis:
        # TODO do genesis validation?
        return
    transaction.verify_parents_basic()
    transaction.verify_weight()
    transaction.verify_without_storage()


@cpu.profiler(key=lambda tx: 'tx-verify!{}'.format(tx.hash.hex()))
def verify(tx: Transaction, *, reject_locked_reward: bool = True) -> None:
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
    tx.verify_without_storage()
    tx.verify_sigops_input()
    tx.verify_inputs()  # need to run verify_inputs first to check if all inputs exist
    tx.verify_parents()
    tx.verify_sum()
    if reject_locked_reward:
        tx.verify_reward_locked()
