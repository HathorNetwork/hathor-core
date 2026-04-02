# Copyright 2026 Hathor Labs
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

"""Test blueprint classes used across simulator tests."""

from hathorlib.nanocontracts.blueprint import Blueprint
from hathorlib.nanocontracts.context import Context
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import NC_HTR_TOKEN_UID, NCActionType, SignedData, TxOutputScript, public, view


class Counter(Blueprint):
    count: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.count = 0

    @public
    def increment(self, ctx: Context) -> None:
        self.count += 1

    @public
    def increment_and_emit(self, ctx: Context) -> None:
        self.count += 1
        self.syscall.emit_event(b'incremented')

    @view
    def get_count(self) -> int:
        return self.count


class Vault(Blueprint):
    total: int

    @public(allow_actions=[NCActionType.DEPOSIT])
    def initialize(self, ctx: Context) -> None:
        deposit = ctx.get_single_action(NC_HTR_TOKEN_UID)
        self.total = deposit.amount  # type: ignore

    @public(allow_actions=[NCActionType.DEPOSIT])
    def deposit_more(self, ctx: Context) -> None:
        deposit = ctx.get_single_action(NC_HTR_TOKEN_UID)
        self.total += deposit.amount  # type: ignore

    @public(allow_actions=[NCActionType.WITHDRAWAL])
    def withdraw(self, ctx: Context, amount: int) -> None:
        if amount > self.total:
            raise NCFail('Insufficient funds')
        self.total -= amount

    @view
    def get_total(self) -> int:
        return self.total


class TimeLock(Blueprint):
    unlock_time: int

    @public
    def initialize(self, ctx: Context, lock_seconds: int) -> None:
        self.unlock_time = ctx.block.timestamp + lock_seconds

    @public
    def claim(self, ctx: Context) -> None:
        if ctx.block.timestamp < self.unlock_time:
            raise NCFail('Too early')

    @view
    def get_unlock_time(self) -> int:
        return self.unlock_time


class FailingBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 42

    @public
    def fail_method(self, ctx: Context, v: int) -> None:
        self.value = v
        raise NCFail('intentional failure')

    @public
    def set_value(self, ctx: Context, v: int) -> None:
        self.value = v

    @view
    def get_value(self) -> int:
        return self.value


class EventEmitter(Blueprint):
    event_count: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.event_count = 0

    @public
    def emit_one(self, ctx: Context) -> None:
        self.event_count += 1
        self.syscall.emit_event(b'event_one')

    @public
    def emit_two(self, ctx: Context) -> None:
        self.event_count += 2
        self.syscall.emit_event(b'event_a')
        self.syscall.emit_event(b'event_b')

    @view
    def get_event_count(self) -> int:
        return self.event_count


class CollectionArgs(Blueprint):
    total: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.total = 0

    @public
    def sum_list(self, ctx: Context, values: list[int]) -> None:
        self.total = sum(values)

    @public
    def sum_dict_values(self, ctx: Context, mapping: dict[str, int]) -> None:
        self.total = sum(mapping.values())

    @public
    def count_unique(self, ctx: Context, items: set[int]) -> None:
        self.total = len(items)

    @view
    def get_total(self) -> int:
        return self.total


class SignedMessage(Blueprint):
    message: str
    oracle_script: TxOutputScript

    @public
    def initialize(self, ctx: Context, oracle_script: TxOutputScript) -> None:
        self.message = ''
        self.oracle_script = oracle_script

    @public
    def set_message(self, ctx: Context, signed: SignedData[str]) -> None:
        if not signed.checksig(self.syscall.get_contract_id(), self.oracle_script):
            raise NCFail('invalid signature')
        self.message = signed.data

    @view
    def get_message(self) -> str:
        return self.message
