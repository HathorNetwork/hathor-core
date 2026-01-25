# Copyright 2024 Hathor Labs
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

"""
Tests for CPython sandbox protection against OCB attack vectors.

This test file covers attack vectors from 0000-ocb-attacks.md using
LOW CONFIGURABLE LIMITS to verify sandbox behavior safely.

Dangerous tests (infinite loops, large allocations with default limits)
are in test_sandbox_dangerous.py.

Note: This file focuses on OPERATION LIMITS which work reliably.
Size limits (list, string, dict, etc.) and type restrictions (float/complex)
have inconsistent behavior in the sandbox and are not tested here.
"""
# mypy: disable-error-code="attr-defined"

from io import StringIO
from unittest import skipUnless

from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.sandbox import SANDBOX_AVAILABLE, SandboxConfig
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build")
class SandboxOperationLimitTestCase(BlueprintTestCase):
    """Test operation limit enforcement in various scenarios."""

    def test_loop_blocked_with_low_operation_limit(self) -> None:
        """Loop blocked by low operation limit (safe test)."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class TestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        total = 0
        for i in range(500):
            total = total + i
'''
        # Register and create contract
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build new runner with restrictive limits FIRST
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=150))

        # Then create the contract
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    def test_normal_execution_within_limits(self) -> None:
        """Verify normal execution within limits succeeds."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class NormalBlueprint(Blueprint):
    counter: int
    data: str

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0
        self.data = ""

    @public
    def do_normal_work(self, ctx: Context) -> None:
        for i in range(100):
            self.counter = self.counter + 1

        self.data = "x" * 1000

        numbers = [i for i in range(50)]
        total = 0
        for n in numbers:
            total = total + n

        self.counter = total
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        ctx = self.create_context()
        self.runner.create_contract(contract_id, blueprint_id, ctx)

        # This should succeed with default limits
        self.runner.call_public_method(contract_id, 'do_normal_work', ctx)

        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.counter, 1225)  # sum(0..49)
        self.assertEqual(len(contract.data), 1000)

    def test_syscalls_do_not_count_as_operations(self) -> None:
        """Verify syscalls do not count towards operation limits."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class SyscallTest(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def many_syscalls(self, ctx: Context) -> None:
        for i in range(50):
            _ = self.syscall.get_contract_id()
            _ = self.syscall.get_blueprint_id()
            self.counter = self.counter + 1
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        ctx = self.create_context()

        # Build new runner with operation limit high enough for 50 iterations FIRST
        # Each iteration: Assign + 2*Attribute + BinOp + 2*(Attribute + Call for syscall) = ~8 ops
        # So 50 iterations = ~400 ops, plus For(1) + Call(1) overhead
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))

        # Then create the contract
        self.runner.create_contract(contract_id, blueprint_id, ctx)

        # This should succeed - syscalls don't count towards limit
        self.runner.call_public_method(contract_id, 'many_syscalls', ctx)

        # Verify work was done
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.counter, 50)


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build")
class CrossContractOperationLimitTestCase(BlueprintTestCase):
    """Test operation limit enforcement across contract calls."""

    def test_cross_contract_operation_count_not_reset(self) -> None:
        """
        Verify operation count is NOT reset when calling another contract.

        Uses low limits to be safe.
        """
        code_worker = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class WorkerBlueprint(Blueprint):
    other_contract: ContractId | None

    @public
    def initialize(self, ctx: Context) -> None:
        self.other_contract = None

    @public
    def set_other(self, ctx: Context, other: ContractId) -> None:
        self.other_contract = other

    @public
    def do_work(self, ctx: Context, iterations: int) -> None:
        total = 0
        for i in range(iterations):
            total = total + i

    @public
    def do_work_and_call_other(self, ctx: Context, my_iterations: int, other_iterations: int) -> None:
        total = 0
        for i in range(my_iterations):
            total = total + i
        if self.other_contract is not None:
            self.syscall.get_contract(self.other_contract, blueprint_id=None).public().do_work(other_iterations)
'''
        # Register and create contracts
        blueprint_id = self._register_blueprint_contents(
            StringIO(code_worker),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()

        ctx = self.create_context()

        # Build new runner with restrictive limits FIRST
        # Each loop iteration counts: Assign + BinOp = ~2 ops, plus For + Call overhead
        # 150 iterations = ~305 ops, 300 iterations = ~605 ops
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))

        # Then create the contracts
        self.runner.create_contract(contract_a, blueprint_id, ctx)
        self.runner.create_contract(contract_b, blueprint_id, ctx)

        # Link contract A to contract B
        self.runner.call_public_method(contract_a, 'set_other', ctx, contract_b)

        # First, verify each contract can do 150 iterations alone (under 1000 limit)
        self.runner.call_public_method(contract_a, 'do_work', ctx, 150)
        self.runner.call_public_method(contract_b, 'do_work', ctx, 150)

        # Now, contract A does 300, then calls contract B which does 300
        # Total = ~1210 operations, should exceed the 1000 limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(
                contract_a, 'do_work_and_call_other', ctx, 300, 300
            )

        self.assertIsNotNone(cm.exception.__cause__)

    def test_chain_of_three_contracts(self) -> None:
        """Test operation counting across a chain of 3 contracts (safe with low limits)."""
        code = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class ChainBlueprint(Blueprint):
    next_contract: ContractId | None

    @public
    def initialize(self, ctx: Context) -> None:
        self.next_contract = None

    @public
    def set_next(self, ctx: Context, next_id: ContractId) -> None:
        self.next_contract = next_id

    @public
    def chain_work(self, ctx: Context, iterations: int) -> None:
        total = 0
        for i in range(iterations):
            total = total + i
        if self.next_contract is not None:
            self.syscall.get_contract(self.next_contract, blueprint_id=None).public().chain_work(iterations)
'''
        # Register and create contracts
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()
        contract_c = self.gen_random_contract_id()

        ctx = self.create_context()

        # Build new runner with restrictive limits FIRST
        # Use a low limit to make the test deterministic
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))

        # Then create the contracts
        self.runner.create_contract(contract_a, blueprint_id, ctx)
        self.runner.create_contract(contract_b, blueprint_id, ctx)
        self.runner.create_contract(contract_c, blueprint_id, ctx)

        # Chain: A -> B -> C
        self.runner.call_public_method(contract_a, 'set_next', ctx, contract_b)
        self.runner.call_public_method(contract_b, 'set_next', ctx, contract_c)

        # Each does 30 iterations, 3 contracts = ~90 loop iterations total
        # Should succeed with 1000 operation limit
        self.runner.call_public_method(contract_a, 'chain_work', ctx, 30)

        # Each does 500 iterations, 3 contracts = ~1500 loop iterations
        # Total operations will exceed 1000 limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_a, 'chain_work', ctx, 500)

        self.assertIsNotNone(cm.exception.__cause__)

    def test_view_calls_between_contracts(self) -> None:
        """Test that view method calls between contracts work correctly."""
        code = '''
from hathor import Blueprint, Context, export, public, view
from hathor import ContractId

@export
class ViewTest(Blueprint):
    value: int
    other: ContractId | None

    @public
    def initialize(self, ctx: Context, value: int) -> None:
        self.value = value
        self.other = None

    @public
    def set_other(self, ctx: Context, other: ContractId) -> None:
        self.other = other

    @view
    def get_value(self) -> int:
        return self.value

    @view
    def get_total(self) -> int:
        my_value = self.value
        other_value = 0
        if self.other is not None:
            other_value = self.syscall.get_contract(self.other, blueprint_id=None).view().get_value()
        return my_value + other_value
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()

        ctx = self.create_context()
        self.runner.create_contract(contract_a, blueprint_id, ctx, 100)
        self.runner.create_contract(contract_b, blueprint_id, ctx, 200)

        self.runner.call_public_method(contract_a, 'set_other', ctx, contract_b)

        # View call should return combined value
        total = self.runner.call_view_method(contract_a, 'get_total')
        self.assertEqual(total, 300)


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build")
class MultipleOCBSandboxTestCase(BlueprintTestCase):
    """Tests using multiple On-Chain Blueprints with different code."""

    def test_two_different_blueprints_share_operation_count(self) -> None:
        """Test that two contracts from DIFFERENT blueprints share operation count."""
        code_blueprint1 = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class Blueprint1(Blueprint):
    target: ContractId | None

    @public
    def initialize(self, ctx: Context) -> None:
        self.target = None

    @public
    def set_target(self, ctx: Context, target: ContractId) -> None:
        self.target = target

    @public
    def work_then_call(self, ctx: Context, my_work: int, target_work: int) -> None:
        total = 0
        for i in range(my_work):
            total = total + i
        if self.target is not None:
            self.syscall.get_contract(self.target, blueprint_id=None).public().do_work(target_work)
'''

        code_blueprint2 = '''
from hathor import Blueprint, Context, export, public

@export
class Blueprint2(Blueprint):
    result: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.result = 0

    @public
    def do_work(self, ctx: Context, iterations: int) -> None:
        total = 0
        for i in range(iterations):
            total = total + i
        self.result = total
'''
        # Register and create contracts
        blueprint1_id = self._register_blueprint_contents(
            StringIO(code_blueprint1),
            skip_verification=True,
        )
        blueprint2_id = self._register_blueprint_contents(
            StringIO(code_blueprint2),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()

        ctx = self.create_context()

        # Build new runner with restrictive limits FIRST
        # Use a low limit to make the test deterministic
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))

        # Then create the contracts
        self.runner.create_contract(contract_a, blueprint1_id, ctx)
        self.runner.create_contract(contract_b, blueprint2_id, ctx)

        self.runner.call_public_method(contract_a, 'set_target', ctx, contract_b)

        # Each does 50 iterations = 100 loop iterations total, should succeed
        self.runner.call_public_method(contract_a, 'work_then_call', ctx, 50, 50)

        # Each does 500 iterations = 1000 loop iterations total, should exceed limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_a, 'work_then_call', ctx, 500, 500)

        self.assertIsNotNone(cm.exception.__cause__)

    def test_reentrant_calls_share_operation_count(self) -> None:
        """Test that reentrant calls (A calls B calls A) share operation count."""
        code = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class ReentrantBlueprint(Blueprint):
    other: ContractId | None
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.other = None
        self.counter = 0

    @public
    def set_other(self, ctx: Context, other: ContractId) -> None:
        self.other = other

    @public(allow_reentrancy=True)
    def ping_pong(self, ctx: Context, depth: int, work_per_call: int) -> None:
        total = 0
        for i in range(work_per_call):
            total = total + i
        self.counter = self.counter + 1

        if depth > 0 and self.other is not None:
            self.syscall.get_contract(self.other, blueprint_id=None).public().ping_pong(depth - 1, work_per_call)
'''
        # Register and create contracts
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()

        ctx = self.create_context()

        # Build new runner with restrictive limits FIRST
        # Use a low limit to make the test deterministic
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))

        # Then create the contracts
        self.runner.create_contract(contract_a, blueprint_id, ctx)
        self.runner.create_contract(contract_b, blueprint_id, ctx)

        # Set up ping-pong: A -> B, B -> A
        self.runner.call_public_method(contract_a, 'set_other', ctx, contract_b)
        self.runner.call_public_method(contract_b, 'set_other', ctx, contract_a)

        # 3 calls (depth=2) with 30 work each, should succeed
        self.runner.call_public_method(contract_a, 'ping_pong', ctx, 2, 30)

        # 10 calls (depth=9) with 200 work each = ~2000 iterations, should exceed 1000 limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_a, 'ping_pong', ctx, 9, 200)

        self.assertIsNotNone(cm.exception.__cause__)
