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

These tests verify that the operation limit is enforced during blueprint execution.
Dangerous tests (infinite loops, etc.) are in test_sandbox_dangerous.py.
"""
# mypy: disable-error-code="attr-defined,name-defined"

from io import StringIO
from unittest import skipUnless

from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.sandbox import SANDBOX_AVAILABLE, SandboxConfig
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build (python -V should show '-sandbox' suffix)")
class SandboxLimitsTestCase(BlueprintTestCase):
    """Test that CPython sandbox limits are enforced during blueprint execution."""

    def test_operation_limit_with_low_limit(self) -> None:
        """Test operation limit works with a low configurable limit (safe test)."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class TestBlueprint(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def do_work(self, ctx: Context) -> None:
        for i in range(100):
            self.counter = self.counter + 1
'''
        # Register blueprint first
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build runner with restrictive limits BEFORE creating contract
        # This ensures the contract is created on the runner with sandbox config
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # With limit of 100, a loop of 100 should fail (uses ~200+ operations)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'do_work', self.create_context())

        # The cause should be a sandbox-related exception
        self.assertIsNotNone(cm.exception.__cause__)

    def test_operation_limit_accumulates_across_calls(self) -> None:
        """Test that operation count accumulates across nested method calls."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
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
'''
        # Register blueprint and create contract with restrictive limits
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build runner with restrictive limits (100 ops for 30 + 30 loop iterations)
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # With limit of 100, two loops of 30 should fail (uses ~100+ operations)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'outer', self.create_context())

        # The cause should be a sandbox-related exception
        self.assertIsNotNone(cm.exception.__cause__)
