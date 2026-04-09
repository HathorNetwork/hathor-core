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
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from re import Match, Pattern

    from hathor.p2p.protocol import HathorLineReceiver
    from hathor.simulator.fake_connection import FakeConnection
    from hathor.simulator.miner import AbstractMiner
    from hathor.simulator.tx_generator import RandomTransactionGenerator
    from hathor.wallet import BaseWallet


class Trigger(ABC):
    """Abstract class to stop simulation when a certain condition is satisfied."""
    @abstractmethod
    def should_stop(self) -> bool:
        """This method must return True when the stop condition is satisfied."""
        raise NotImplementedError


class StopAfterNMinedBlocks(Trigger):
    """
    Stop the simulation after `miner` finds at least N blocks. Note that these blocks might be orphan.

    Use `miner.pause_after_exactly()` instead of this trigger if you need "exactly N blocks" behavior, instead of
    "at least N blocks".
    """
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


class StopAfterNTransactions(Trigger):
    """Stop the simulation after N transactions are found."""
    def __init__(self, tx_generator: 'RandomTransactionGenerator', *, quantity: int) -> None:
        self.tx_generator = tx_generator
        self.quantity = quantity
        self.reset()

    def reset(self) -> None:
        """Reset the counter, so this trigger can be reused."""
        self.initial_counter = self.tx_generator.transactions_found

    def should_stop(self) -> bool:
        diff = self.tx_generator.transactions_found - self.initial_counter
        return diff >= self.quantity


class StopWhenTrue(Trigger):
    """Stop the simulation when a function returns true."""
    def __init__(self, fn: Callable[[], bool]) -> None:
        self.fn = fn

    def should_stop(self) -> bool:
        return self.fn()


class StopWhenSynced(Trigger):
    """Stop the simulation when both agents runnning on a connection report that they have synced."""
    def __init__(self, connection: 'FakeConnection') -> None:
        self.connection = connection

    def should_stop(self) -> bool:
        return self.connection.is_both_synced()


class All(Trigger):
    """Aggregator that returns True when all sub-triggers return True.

    XXX: note that not all sub-triggers will be called, this will short-circuit, in order, if one sub-trigger returns
    False, which follows the same behavior of builtins.all"""
    def __init__(self, sub_triggers: list[Trigger]) -> None:
        self._sub_triggers = sub_triggers

    def should_stop(self) -> bool:
        return all(trigger.should_stop() for trigger in self._sub_triggers)


class StopWhenSendLineMatch(Trigger):
    """Stop the simulation when the node sends a line that matches a designated regex pattern.
    """

    def __init__(self, protocol: 'HathorLineReceiver', regex: 'Pattern') -> None:
        # patches protocol.sendLine
        self.original_send_line = protocol.sendLine
        setattr(protocol, 'sendLine', self._send_line_wrapper)

        # regex pattern
        self.regex = regex

        # list of matches
        self.matches: list['Match'] = []

    def _send_line_wrapper(self, line: str) -> None:
        """Check if line matches a designated regex pattern."""
        self.original_send_line(line)
        match = self.regex.match(line)
        if match:
            self.matches.append(match)

    def should_stop(self) -> bool:
        if self.matches:
            self.matches = []
            return True
        return False
