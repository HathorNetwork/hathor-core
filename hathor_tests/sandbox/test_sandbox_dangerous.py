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
# mypy: disable-error-code="attr-defined,name-defined"

import signal
from functools import wraps
from io import StringIO
from typing import Any, Callable
from unittest import skipUnless

from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.sandbox import SANDBOX_AVAILABLE, SandboxConfig
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


def timeout(seconds: int) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to add a timeout to a test function.

    If the test takes longer than the specified seconds, it raises a TimeoutError.
    This prevents tests from hanging indefinitely if the sandbox fails.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            def handler(signum: int, frame: Any) -> None:
                raise TimeoutError(f"Test timed out after {seconds} seconds")

            # Set up the signal handler
            old_handler = signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                return func(*args, **kwargs)
            finally:
                # Restore the old handler and cancel the alarm
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        return wrapper
    return decorator


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build with sys.sandbox support")
class DangerousSandboxTestCase(BlueprintTestCase):
    """
    Dangerous tests that could lock workers if sandbox fails.

    These test actual DoS attack patterns that would be dangerous without
    the sandbox protection.
    """

    # =========================================================================
    # D3: Time DoS - Infinite loops
    # =========================================================================

    @timeout(30)
    def test_d3_1_infinite_while_loop(self) -> None:
        """D3.1: Infinite while loop blocked by operation limit."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class InfiniteLoop(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.counter = 0

    @public
    def attack(self, ctx: Context) -> None:
        while True:
            self.counter = self.counter + 1
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(30)
    def test_d3_1b_minimal_infinite_loop(self) -> None:
        """D3.1b: Minimal infinite loop (while True: pass) blocked by operation limit."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class MinimalInfiniteLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        while True: pass
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(30)
    def test_d3_2_effectively_infinite_loop(self) -> None:
        """D3.2: Very large loop (10^15 iterations) blocked by operation limit."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class BigLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        for i in range(10**15):
            pass
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    # =========================================================================
    # D1: Computational DoS - Expensive operations
    # =========================================================================

    @timeout(30)
    def test_d1_1_exponential_computation(self) -> None:
        """D1.1: Exponential computation (x = x * x) stopped by limits."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class ExpCompute(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        x = 2
        for _ in range(1000):
            x = x * x
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(30)
    def test_d1_2_large_loop_10m_iterations(self) -> None:
        """D1.2: Large loop (10M iterations) stopped by operation limit."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class LargeLoop(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        total = 0
        for i in range(10000000):
            total = total + i
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(30)
    def test_d1_3_nested_loops_100m_iterations(self) -> None:
        """D1.3: Nested loops (10K x 10K = 100M iterations) stopped by operation limit."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class NestedLoops(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        for i in range(10000):
            for j in range(10000):
                pass
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)
