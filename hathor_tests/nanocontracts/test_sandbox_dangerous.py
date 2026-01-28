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
DANGEROUS sandbox tests that could lock up test workers if sandbox fails.

These tests verify that the sandbox properly stops actual DoS attacks like
infinite loops and massive allocations. They should be run separately from
the main test suite:

    poetry run pytest hathor_tests/nanocontracts/test_sandbox_dangerous.py -v

WARNING: If the sandbox is not working properly, these tests WILL lock up
the test worker indefinitely.
"""

from io import StringIO

from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class DangerousSandboxTestCase(BlueprintTestCase):
    """
    Dangerous tests that could lock workers if sandbox fails.

    These test actual DoS attack patterns that would be dangerous without
    the sandbox protection.
    """

    def setUp(self) -> None:
        super().setUp()
        MeteredExecutor.reset_sandbox_limits()

    def tearDown(self) -> None:
        MeteredExecutor.reset_sandbox_limits()
        super().tearDown()

    # =========================================================================
    # D3: Time DoS - Infinite loops
    # =========================================================================

    def test_d3_1_infinite_while_loop(self) -> None:
        """D3.1: Infinite while loop blocked by statement limit."""
        code = '''
from hathor import Blueprint, Context, public

class InfiniteLoop(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def attack(self, ctx: Context) -> None:
        while True:
            self.counter = self.counter + 1

__blueprint__ = InfiniteLoop
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_d3_1b_minimal_infinite_loop(self) -> None:
        """D3.1b: Minimal infinite loop (while True: pass) blocked by statement limit."""
        code = '''
from hathor import Blueprint, Context, public

class MinimalInfiniteLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        while True: pass

__blueprint__ = MinimalInfiniteLoop
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_d3_2_effectively_infinite_loop(self) -> None:
        """D3.2: Very large loop (10^15 iterations) blocked by statement limit."""
        code = '''
from hathor import Blueprint, Context, public

class BigLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        for i in range(10**15):
            pass

__blueprint__ = BigLoop
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    # =========================================================================
    # D1: Computational DoS - Expensive operations
    # =========================================================================

    def test_d1_1_exponential_computation(self) -> None:
        """D1.1: Exponential computation (x = x * x) stopped by limits."""
        code = '''
from hathor import Blueprint, Context, public

class ExpCompute(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        x = 2
        for _ in range(1000):
            x = x * x

__blueprint__ = ExpCompute
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        # Should be RuntimeError (statement limit) or OverflowError (int size)
        self.assertIsInstance(cm.exception.__cause__, (RuntimeError, OverflowError))

    def test_d1_2_large_loop_10m_iterations(self) -> None:
        """D1.2: Large loop (10M iterations) stopped by statement limit."""
        code = '''
from hathor import Blueprint, Context, public

class LargeLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        total = 0
        for i in range(10000000):
            total = total + i

__blueprint__ = LargeLoop
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_d1_3_nested_loops_100m_iterations(self) -> None:
        """D1.3: Nested loops (10K x 10K = 100M iterations) stopped by statement limit."""
        code = '''
from hathor import Blueprint, Context, public

class NestedLoops(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        for i in range(10000):
            for j in range(10000):
                pass

__blueprint__ = NestedLoops
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)
