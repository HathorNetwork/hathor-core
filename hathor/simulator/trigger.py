# Copyright 2023 Hathor Labs
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathor.simulator.miner import AbstractMiner
    from hathor.wallet import BaseWallet


class Trigger(ABC):
    """Abstract class to stop simulation when a certain condition is satisfied."""
    @abstractmethod
    def should_stop(self) -> bool:
        """This method must return True when the stop condition is satisfied."""
        raise NotImplementedError


class StopAfterNMinedBlocks(Trigger):
    """Stop the simulation after `miner` finds N blocks. Note that these blocks might be orphan."""
    def __init__(self, miner: 'AbstractMiner', *, quantity: int) -> None:
        self.miner = miner
        self.quantity = quantity
        self.reset()

    def reset(self) -> None:
        """Reset the counter, so this trigger can be reused."""
        self.initial_blocks_found = self.miner.get_blocks_found()

    def should_stop(self) -> bool:
        diff = self.miner.get_blocks_found() - self.initial_blocks_found
        return diff >= self.quantity


class StopAfterMinimumBalance(Trigger):
    """Stop the simulation after `wallet` reaches a minimum unlocked balance."""
    def __init__(self, wallet: 'BaseWallet', token_uid: bytes, minimum_balance: int) -> None:
        self.wallet = wallet
        self.token_uid = token_uid
        self.minimum_balance = minimum_balance

    def should_stop(self) -> bool:
        balance = self.wallet.balance[self.token_uid].available
        return balance >= self.minimum_balance
