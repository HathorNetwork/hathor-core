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

from collections import deque
from typing import TYPE_CHECKING, Deque, List

from structlog import get_logger

from hathor import daa
from hathor.conf import HathorSettings
from hathor.transaction.exceptions import RewardLocked
from hathor.util import Random
from hathor.wallet.exceptions import InsufficientFunds
from tests.utils import NoCandidatesError, gen_new_double_spending, gen_new_tx

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.transaction import Transaction

settings = HathorSettings()
logger = get_logger()


class RandomTransactionGenerator:
    """ Generates random transactions without mining. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """

    MAX_LATEST_TRANSACTIONS_LEN = 10

    def __init__(self, manager: 'HathorManager', rng: Random, *,
                 rate: float, hashpower: float, ignore_no_funds: bool = False):
        """
        :param: rate: Number of transactions per second
        :param: hashpower: Number of hashes per second
        """
        self.manager = manager

        # List of addresses to send tokens. If this list is empty, tokens will be sent to an address
        # of its own wallet.
        self.send_to: List[str] = []

        self.clock = manager.reactor
        self.rate = rate
        self.hashpower = hashpower
        self.ignore_no_funds = ignore_no_funds
        self.tx = None
        self.delayedcall = None
        self.log = logger.new()
        self.rng = rng

        # Most recent transactions generated here.
        # The lowest index has the most recent transaction.
        self.latest_transactions: Deque[Transaction] = deque()

        self.double_spending_only = False

    def start(self):
        """ Start generating random transactions.
        """
        self.schedule_next_transaction()

    def stop(self):
        """ Stop generating random transactions.
        """
        if self.delayedcall:
            self.delayedcall.cancel()
            self.delayedcall = None

    def enable_double_spending(self):
        self.double_spending_only = True

    def schedule_next_transaction(self):
        """ Schedule the generation of a new transaction.
        """
        if self.tx:
            ret = self.manager.propagate_tx(self.tx, fails_silently=False)
            assert ret is True
            self.latest_transactions.appendleft(self.tx.hash)
            if len(self.latest_transactions) > self.MAX_LATEST_TRANSACTIONS_LEN:
                self.latest_transactions.pop()
            self.tx = None

        dt = self.rng.expovariate(self.rate)
        self.log.debug('randomized step: schedule new transaction step ', dt=dt)
        self.delayedcall = self.clock.callLater(dt, self.new_tx_step1)

    def new_tx_step1(self):
        """ Generate a new transaction and schedule the mining part of the transaction.
        """
        balance = self.manager.wallet.balance[settings.HATHOR_TOKEN_UID]
        if balance.available == 0 and self.ignore_no_funds:
            self.delayedcall = self.clock.callLater(0, self.schedule_next_transaction)
            return

        if not self.send_to:
            address = self.manager.wallet.get_unused_address(mark_as_used=False)
        else:
            address = self.rng.choice(self.send_to)

        value = self.rng.randint(1, balance.available)
        self.log.debug('randomized step: send to', address=address, amount=value / 100)

        if not self.double_spending_only:
            try:
                tx = gen_new_tx(self.manager, address, value)
            except (InsufficientFunds, RewardLocked):
                self.delayedcall = self.clock.callLater(0, self.schedule_next_transaction)
                return
        else:
            try:
                tx = gen_new_double_spending(self.manager)
                tx.nonce = self.rng.getrandbits(32)
            except NoCandidatesError:
                self.delayedcall = self.clock.callLater(0, self.schedule_next_transaction)
                return

        tx.weight = daa.minimum_tx_weight(tx)
        tx.update_hash()

        geometric_p = 2**(-tx.weight)
        trials = self.rng.geometric(geometric_p)
        dt = 1.0 * trials / self.hashpower

        self.tx = tx
        self.delayedcall = self.clock.callLater(dt, self.schedule_next_transaction)
        self.log.debug('randomized step: schedule next transaction', dt=dt, hash=tx.hash_hex)
