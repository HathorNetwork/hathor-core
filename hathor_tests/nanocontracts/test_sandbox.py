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
Safe tests for CPython sandbox integration in nanocontracts.

These tests verify that the statement limit is enforced during blueprint execution.
Dangerous tests (infinite loops, etc.) are in test_sandbox_dangerous.py.
"""

from io import StringIO

from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class SandboxLimitsTestCase(BlueprintTestCase):
    """Test that CPython sandbox limits are enforced during blueprint execution."""

    def setUp(self) -> None:
        super().setUp()
        # Reset sandbox limits to defaults before each test
        MeteredExecutor.reset_sandbox_limits()

    def tearDown(self) -> None:
        # Reset sandbox limits after each test
        MeteredExecutor.reset_sandbox_limits()
        super().tearDown()

    def test_statement_limit_with_low_limit(self) -> None:
        """Test statement limit works with a low configurable limit (safe test)."""
        code = '''
from hathor import Blueprint, Context, public

class TestBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def do_work(self, ctx: Context) -> None:
        for i in range(100):
            self.counter = self.counter + 1

__blueprint__ = TestBlueprint
'''
        # Register blueprint and create contract with DEFAULT limits
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # NOW set restrictive limits
        MeteredExecutor.max_statements = 50
        MeteredExecutor._apply_sandbox_limits()

        # With limit of 50, a loop of 100 should fail
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'do_work', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_statement_limit_accumulates_across_calls(self) -> None:
        """Test that statement count accumulates across nested method calls."""
        code = '''
from hathor import Blueprint, Context, public

class TestBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def outer(self, ctx: Context) -> None:
        for i in range(30):
            self.counter = self.counter + 1
        self.inner(ctx)

    @public
    def inner(self, ctx: Context) -> None:
        for i in range(30):
            self.counter = self.counter + 1

__blueprint__ = TestBlueprint
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Set limit that would pass for either method alone but fail for both
        MeteredExecutor.max_statements = 100
        MeteredExecutor._apply_sandbox_limits()

        # outer() does 30 iterations, then calls inner() which does 30 more
        # Total should exceed 100 statements
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'outer', self.create_context())

        self.assertIsInstance(cm.exception.__cause__, RuntimeError)

    def test_normal_execution_succeeds(self) -> None:
        """Test that normal execution within limits succeeds."""
        code = '''
from hathor import Blueprint, Context, public

class NormalBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def do_work(self, ctx: Context, iterations: int) -> None:
        for i in range(iterations):
            self.counter = self.counter + 1

__blueprint__ = NormalBlueprint
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(
            contract_id,
            blueprint_id,
            self.create_context(),
        )

        # This should succeed - within all limits
        self.runner.call_public_method(
            contract_id,
            'do_work',
            self.create_context(),
            100,
        )

        # Verify the work was done
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.counter, 100)

    def test_statement_count_resets_between_transactions(self) -> None:
        """Test that statement count resets between separate transactions."""
        code = '''
from hathor import Blueprint, Context, public

class TestBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def do_work(self, ctx: Context) -> None:
        for i in range(40):
            self.counter = self.counter + 1

__blueprint__ = TestBlueprint
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Set limit that allows 40 iterations but not 80
        MeteredExecutor.max_statements = 100
        MeteredExecutor._apply_sandbox_limits()

        # First call should succeed (40 iterations)
        self.runner.call_public_method(contract_id, 'do_work', self.create_context())

        # Second call should also succeed because counter resets
        self.runner.call_public_method(contract_id, 'do_work', self.create_context())

        # Verify the work was done (2 calls x 40 iterations = 80)
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.counter, 80)
