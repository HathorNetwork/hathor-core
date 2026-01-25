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
Tests for SandboxCounters feature that tracks operation counts before/after each call.

These tests verify that sandbox_counters is correctly populated for each CallRecord,
tracking the before, after, and delta operation counts across single and cross-contract calls.
"""
# mypy: disable-error-code="attr-defined,union-attr"

from io import StringIO
from unittest import skipUnless

from hathor.nanocontracts.metered_exec import MeteredExecutor
from hathor.nanocontracts.runner.call_info import CallType
from hathor.nanocontracts.sandbox import DISABLED_CONFIG, SANDBOX_AVAILABLE, SandboxConfig, SandboxCounts
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build (python -V should show '-sandbox' suffix)")
class SandboxCountersTestCase(BlueprintTestCase):
    """Test that SandboxCounters is correctly populated for each CallRecord."""

    def test_single_call_counter_tracking(self) -> None:
        """Verify sandbox_counters is populated for a single method call with before, after, and delta."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class CounterBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def do_work(self, ctx: Context) -> None:
        for i in range(50):
            self.value = self.value + 1
'''
        # Register blueprint and create contract
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build runner with sandbox config enabled
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100_000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Call the method
        self.runner.call_public_method(contract_id, 'do_work', self.create_context())

        # Get call info and verify counters
        call_info = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info.calls)
        self.assertEqual(len(call_info.calls), 1)

        call_record = call_info.calls[0]
        self.assertEqual(call_record.type, CallType.PUBLIC)
        self.assertEqual(call_record.method_name, 'do_work')

        # Verify sandbox_counters is populated
        self.assertIsNotNone(call_record.sandbox_counters)
        counters = call_record.sandbox_counters

        # Verify before counters are populated
        self.assertIsNotNone(counters.before, "before counters should be populated")
        self.assertIsInstance(counters.before, SandboxCounts)

        # Verify after counters are populated
        self.assertIsNotNone(counters.after, "after counters should be populated")
        self.assertIsInstance(counters.after, SandboxCounts)

        # Verify delta is calculated correctly
        delta = counters.delta
        self.assertIsInstance(delta, SandboxCounts)
        self.assertGreater(delta.operation_count, 0, "operation_count delta should be positive")

        # Verify after >= before for operation_count
        self.assertGreaterEqual(
            counters.after.operation_count,
            counters.before.operation_count,
            "after should be >= before"
        )

    def test_cross_contract_call_counter_tracking(self) -> None:
        """Verify each call in a cross-contract chain has its own counters showing accumulation."""
        code = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class ChainBlueprint(Blueprint):
    next_contract: ContractId | None
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.next_contract = None
        self.value = 0

    @public
    def set_next(self, ctx: Context, next_id: ContractId) -> None:
        self.next_contract = next_id

    @public
    def chain_work(self, ctx: Context, iterations: int) -> None:
        for i in range(iterations):
            self.value = self.value + 1
        if self.next_contract is not None:
            self.syscall.get_contract(self.next_contract, blueprint_id=None).public().chain_work(iterations)
'''
        # Register blueprint and create contracts
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )

        contract_a = self.gen_random_contract_id()
        contract_b = self.gen_random_contract_id()
        contract_c = self.gen_random_contract_id()

        ctx = self.create_context()

        # Build runner with sandbox config enabled
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100_000))

        # Create contracts
        self.runner.create_contract(contract_a, blueprint_id, ctx)
        self.runner.create_contract(contract_b, blueprint_id, ctx)
        self.runner.create_contract(contract_c, blueprint_id, ctx)

        # Chain: A -> B -> C
        self.runner.call_public_method(contract_a, 'set_next', ctx, contract_b)
        self.runner.call_public_method(contract_b, 'set_next', ctx, contract_c)

        # Call chain_work which will call A -> B -> C
        self.runner.call_public_method(contract_a, 'chain_work', ctx, 30)

        # Get call info and verify counters
        call_info = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info.calls)

        # Should have 3 calls: A, B, C
        chain_work_calls = [c for c in call_info.calls if c.method_name == 'chain_work']
        self.assertEqual(len(chain_work_calls), 3)

        # Verify each call has sandbox_counters populated
        for i, call_record in enumerate(chain_work_calls):
            self.assertIsNotNone(
                call_record.sandbox_counters,
                f"Call {i} should have sandbox_counters"
            )
            counters = call_record.sandbox_counters
            self.assertIsNotNone(counters.before, f"Call {i}: before counters should be populated")
            self.assertIsNotNone(counters.after, f"Call {i}: after counters should be populated")
            self.assertGreater(
                counters.delta.operation_count,
                0,
                f"Call {i}: delta should be positive"
            )

        # Verify counters show accumulation across calls
        # For nested calls, the counters are captured in call order, not completion order:
        # - A starts, captures before_A
        # - A calls B, B starts, captures before_B (> before_A)
        # - B calls C, C starts, captures before_C (> before_B)
        # - C completes, after_C captured
        # - B completes, after_B captured (= after_C since nothing in between)
        # - A completes, after_A captured (= after_B since nothing in between)
        for i in range(1, len(chain_work_calls)):
            prev_counters = chain_work_calls[i - 1].sandbox_counters
            curr_counters = chain_work_calls[i].sandbox_counters
            assert prev_counters is not None
            assert curr_counters is not None
            assert prev_counters.before is not None
            assert curr_counters.before is not None

            # The 'before' of a nested call should be >= 'before' of its caller
            # (since some operations happened before the nested call was made)
            self.assertGreaterEqual(
                curr_counters.before.operation_count,
                prev_counters.before.operation_count,
                f"Call {i}: before should be >= previous call's before (showing accumulation)"
            )

    def test_view_method_counter_tracking(self) -> None:
        """Verify counters work for view methods."""
        code = '''
from hathor import Blueprint, Context, export, public, view

@export
class ViewBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context, initial_value: int) -> None:
        self.value = initial_value

    @view
    def get_value(self) -> int:
        total = 0
        for i in range(20):
            total = total + 1
        return self.value + total
'''
        # Register blueprint and create contract
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build runner with sandbox config enabled
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100_000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context(), 100)

        # Call view method
        result = self.runner.call_view_method(contract_id, 'get_value')
        self.assertEqual(result, 120)  # 100 + 20

        # Get call info and verify counters
        call_info = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info.calls)
        self.assertEqual(len(call_info.calls), 1)

        call_record = call_info.calls[0]
        self.assertEqual(call_record.type, CallType.VIEW)
        self.assertEqual(call_record.method_name, 'get_value')

        # Verify sandbox_counters is populated for view method
        self.assertIsNotNone(call_record.sandbox_counters)
        counters = call_record.sandbox_counters

        self.assertIsNotNone(counters.before, "before counters should be populated")
        self.assertIsNotNone(counters.after, "after counters should be populated")
        self.assertGreater(counters.delta.operation_count, 0, "delta should be positive")

    def test_no_sandbox_counters_are_none(self) -> None:
        """Verify sandbox_counters is None when sandbox is not configured."""
        code = '''
from hathor import Blueprint, Context, export, public

@export
class SimpleBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def increment(self, ctx: Context) -> None:
        self.value = self.value + 1
'''
        # Register blueprint and create contract
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()

        # Build runner WITHOUT sandbox config (sandbox_config=DISABLED_CONFIG)
        self.runner = self.build_runner(sandbox_config=DISABLED_CONFIG)
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Call the method
        self.runner.call_public_method(contract_id, 'increment', self.create_context())

        # Get call info and verify counters are None
        call_info = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info.calls)
        self.assertEqual(len(call_info.calls), 1)

        call_record = call_info.calls[0]
        self.assertIsNone(
            call_record.sandbox_counters,
            "sandbox_counters should be None when sandbox is not configured"
        )


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build (python -V should show '-sandbox' suffix)")
class OCBLoadingCostCachingTestCase(BlueprintTestCase):
    """Test that OCB loading costs are correctly cached and applied consistently.

    These tests verify that:
    1. The loading cost of an OCB is the same whether it's freshly loaded or cached
    2. Cross-contract calls with cached OCBs have consistent total costs
    """

    def test_ocb_loading_costs_are_stored_in_cache(self) -> None:
        """Verify that loading costs are correctly stored in the BlueprintCache."""
        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class CacheStorageBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        code = Code.from_python_code(code_text, self._settings)
        ocb = OnChainBlueprint(hash=b'\x02' * 32, code=code)

        # Load with sandbox config
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        # Verify costs are accessible via public property
        cached_costs = ocb.loading_costs
        self.assertIsNotNone(cached_costs)

        self.assertIsInstance(cached_costs, SandboxCounts)
        self.assertGreater(
            cached_costs.operation_count,
            0,
            "Loading should consume operations"
        )

    def test_ocb_no_loading_costs_without_sandbox(self) -> None:
        """Verify that no loading costs are stored when sandbox is not active."""
        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class NoSandboxBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass
'''
        code = Code.from_python_code(code_text, self._settings)
        ocb = OnChainBlueprint(hash=b'\x03' * 32, code=code)

        # Load with sandbox disabled (DISABLED_CONFIG)
        ocb.get_blueprint_class()

        # Verify loading_costs is None (zero counts → None via `or None`)
        self.assertIsNone(ocb.loading_costs)

    def test_ocb_cached_loading_cost_applied_via_add_counts(self) -> None:
        """Verify that cached loading cost is applied via sys.sandbox.add_counts."""
        import sys

        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class AddCountsBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        code = Code.from_python_code(code_text, self._settings)
        ocb = OnChainBlueprint(hash=b'\x01' * 32, code=code)

        # First load - captures loading costs (fresh executor each call, like factory.for_loading())
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        # Get the cached loading costs
        cached_loading_cost = ocb.loading_costs.operation_count
        self.assertGreater(cached_loading_cost, 0)

        # Second load - should call add_counts with cached cost
        # Enable sandbox manually to measure the effect of add_counts
        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        before_count = sys.sandbox.get_counts()['operation_count']
        self.assertEqual(before_count, 0)

        # This should call add_counts() since blueprint is cached
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        after_count = sys.sandbox.get_counts()['operation_count']
        sys.sandbox.reset()

        # The count should have increased by exactly the cached loading cost
        self.assertEqual(
            after_count,
            cached_loading_cost,
            f"add_counts should apply cached cost: expected={cached_loading_cost}, got={after_count}"
        )

    def test_ocb_loading_cost_consistency_fresh_vs_cached(self) -> None:
        """Verify that loading cost is the same whether fresh or cached.

        Creates two identical OCBs and loads them:
        - OCB1: loaded fresh (not cached)
        - OCB2: loaded fresh, then loaded again (cached)

        The fresh load cost of OCB1 should equal the cached load cost of OCB2.
        """
        import sys

        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class ConsistencyBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def work(self, ctx: Context) -> None:
        for i in range(20):
            self.value = self.value + i
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        # Create two identical OCBs (different hash so they're separate instances)
        code1 = Code.from_python_code(code_text, self._settings)
        ocb1 = OnChainBlueprint(hash=b'\x10' * 32, code=code1)

        code2 = Code.from_python_code(code_text, self._settings)
        ocb2 = OnChainBlueprint(hash=b'\x11' * 32, code=code2)

        # Load OCB1 fresh and get its loading cost
        ocb1.get_blueprint_class(MeteredExecutor(config=sandbox_config))
        ocb1_fresh_cost = ocb1.loading_costs.operation_count

        # Load OCB2 fresh first (to populate cache)
        ocb2.get_blueprint_class(MeteredExecutor(config=sandbox_config))
        ocb2_fresh_cost = ocb2.loading_costs.operation_count

        # Fresh costs should be equal (same code)
        self.assertEqual(
            ocb1_fresh_cost,
            ocb2_fresh_cost,
            "Fresh loading costs for identical code should be equal"
        )

        # Now load OCB2 from cache and measure via sandbox
        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        ocb2.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        ocb2_cached_cost = sys.sandbox.get_counts()['operation_count']
        sys.sandbox.reset()

        # Cached cost should equal fresh cost
        self.assertEqual(
            ocb2_fresh_cost,
            ocb2_cached_cost,
            f"Cached load should apply same cost as fresh: fresh={ocb2_fresh_cost}, cached={ocb2_cached_cost}"
        )

    def test_cross_contract_ocb_loading_cost_consistency(self) -> None:
        """Verify total execution cost is the same whether OCBs are cached or not.

        This test creates two contracts from different OCBs, where contract A calls
        contract B. It verifies that the total cost is the same regardless of whether
        the OCBs were previously cached.
        """
        code_caller = '''
from hathor import Blueprint, Context, export, public
from hathor import ContractId

@export
class CallerBlueprint(Blueprint):
    target: ContractId | None

    @public
    def initialize(self, ctx: Context) -> None:
        self.target = None

    @public
    def set_target(self, ctx: Context, target: ContractId) -> None:
        self.target = target

    @public
    def call_target(self, ctx: Context) -> None:
        if self.target is not None:
            self.syscall.get_contract(self.target, blueprint_id=None).public().do_work()
'''

        code_callee = '''
from hathor import Blueprint, Context, export, public

@export
class CalleeBlueprint(Blueprint):
    result: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.result = 0

    @public
    def do_work(self, ctx: Context) -> None:
        total = 0
        for i in range(50):
            total = total + i
        self.result = total
'''
        # Register blueprints
        caller_blueprint_id = self._register_blueprint_contents(
            StringIO(code_caller),
            skip_verification=True,
        )
        callee_blueprint_id = self._register_blueprint_contents(
            StringIO(code_callee),
            skip_verification=True,
        )

        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        # === First run: Fresh runner, measure total cost ===
        contract_a1 = self.gen_random_contract_id()
        contract_b1 = self.gen_random_contract_id()

        self.runner = self.build_runner(sandbox_config=sandbox_config)
        self.runner.create_contract(contract_a1, caller_blueprint_id, self.create_context())
        self.runner.create_contract(contract_b1, callee_blueprint_id, self.create_context())
        self.runner.call_public_method(contract_a1, 'set_target', self.create_context(), contract_b1)

        # Call and measure cost
        self.runner.call_public_method(contract_a1, 'call_target', self.create_context())

        call_info_1 = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info_1.calls)

        # Get total operation count from call records
        first_run_total_ops = 0
        for call_record in call_info_1.calls:
            if call_record.sandbox_counters is not None:
                first_run_total_ops += call_record.sandbox_counters.delta.operation_count

        # === Second run: Same runner (blueprints are in catalog, so cached), measure again ===
        contract_a2 = self.gen_random_contract_id()
        contract_b2 = self.gen_random_contract_id()

        self.runner.create_contract(contract_a2, caller_blueprint_id, self.create_context())
        self.runner.create_contract(contract_b2, callee_blueprint_id, self.create_context())
        self.runner.call_public_method(contract_a2, 'set_target', self.create_context(), contract_b2)

        self.runner.call_public_method(contract_a2, 'call_target', self.create_context())

        call_info_2 = self.runner.get_last_call_info()
        self.assertIsNotNone(call_info_2.calls)

        second_run_total_ops = 0
        for call_record in call_info_2.calls:
            if call_record.sandbox_counters is not None:
                second_run_total_ops += call_record.sandbox_counters.delta.operation_count

        # Verify total costs are equal
        self.assertEqual(
            first_run_total_ops,
            second_run_total_ops,
            f"Total operation cost should be consistent: first={first_run_total_ops}, second={second_run_total_ops}"
        )

    def test_multiple_ocbs_cached_loading_costs_accumulate(self) -> None:
        """Verify that loading costs from multiple cached OCBs accumulate correctly."""
        import sys

        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text_1 = '''
from hathor import Blueprint, Context, export, public

@export
class Blueprint1(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass
'''

        code_text_2 = '''
from hathor import Blueprint, Context, export, public

@export
class Blueprint2(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def compute(self, ctx: Context) -> None:
        for i in range(10):
            self.value = self.value + i
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        # Create two OCBs
        code1 = Code.from_python_code(code_text_1, self._settings)
        ocb1 = OnChainBlueprint(hash=b'\x04' * 32, code=code1)

        code2 = Code.from_python_code(code_text_2, self._settings)
        ocb2 = OnChainBlueprint(hash=b'\x05' * 32, code=code2)

        # Load both OCBs fresh to populate caches (fresh executor each call)
        ocb1.get_blueprint_class(MeteredExecutor(config=sandbox_config))
        ocb2.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        # Get individual cached costs
        ocb1_cost = ocb1.loading_costs.operation_count
        ocb2_cost = ocb2.loading_costs.operation_count

        self.assertGreater(ocb1_cost, 0)
        self.assertGreater(ocb2_cost, 0)

        # Now load both from cache with sandbox active
        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        ocb1.get_blueprint_class(MeteredExecutor(config=sandbox_config))
        count_after_ocb1 = sys.sandbox.get_counts()['operation_count']

        ocb2.get_blueprint_class(MeteredExecutor(config=sandbox_config))
        count_after_both = sys.sandbox.get_counts()['operation_count']

        sys.sandbox.reset()

        # Verify individual costs applied correctly
        self.assertEqual(
            count_after_ocb1,
            ocb1_cost,
            f"OCB1 cached cost should be applied: expected={ocb1_cost}, got={count_after_ocb1}"
        )

        # Verify costs accumulate
        expected_total = ocb1_cost + ocb2_cost
        self.assertEqual(
            count_after_both,
            expected_total,
            f"Costs should accumulate: expected={expected_total}, got={count_after_both}"
        )

    def test_ocb_loading_cost_deduplicated_per_call_chain(self) -> None:
        """Verify that OCB loading costs are charged only once per call chain.

        This test directly verifies the _charged_blueprint_ids tracking mechanism
        by checking that when a blueprint is accessed multiple times in a single
        call chain, its loading cost is only counted once.
        """
        import sys

        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class TestBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def work(self, ctx: Context) -> None:
        for i in range(10):
            self.value = self.value + i
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        # Create an OCB and get its loading cost
        code = Code.from_python_code(code_text, self._settings)
        ocb = OnChainBlueprint(hash=b'\x20' * 32, code=code)

        # First access - loads the blueprint and captures loading costs
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        self.assertIsNotNone(ocb.loading_costs)
        loading_cost = ocb.loading_costs.operation_count
        self.assertGreater(loading_cost, 0, "Blueprint should have loading cost")

        # Now test: accessing the cached blueprint twice with sandbox active
        # First access (skip_loading_cost=False) should add loading cost
        # Second access (skip_loading_cost=True) should NOT add loading cost

        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        # First cached access with skip_loading_cost=False
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=False)
        after_first = sys.sandbox.get_counts()['operation_count']

        # Second cached access with skip_loading_cost=True
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=True)
        after_second = sys.sandbox.get_counts()['operation_count']

        sys.sandbox.reset()

        # Verify first access added loading cost
        self.assertEqual(
            after_first,
            loading_cost,
            f"First access should add loading cost: expected={loading_cost}, got={after_first}"
        )

        # Verify second access did NOT add loading cost (due to skip_loading_cost=True)
        self.assertEqual(
            after_second,
            loading_cost,  # Should still be the same as after first
            f"Second access with skip should NOT add cost: expected={loading_cost}, got={after_second}"
        )

        # For completeness, verify that without skip flag, cost would be doubled
        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        # Two accesses without skip
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=False)
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=False)
        after_both_without_skip = sys.sandbox.get_counts()['operation_count']

        sys.sandbox.reset()

        # Both should add loading cost
        self.assertEqual(
            after_both_without_skip,
            2 * loading_cost,
            f"Two accesses without skip should double cost: expected={2 * loading_cost}, got={after_both_without_skip}"
        )

    def test_ocb_loading_cost_in_call_record(self) -> None:
        """Verify that ocb_loading_cost is properly populated in CallRecord for OCBs.

        Note: This test uses the direct OCB/sandbox API since the test framework
        registers blueprints in a catalog (not as on-chain blueprints), and only
        on-chain blueprints have loading costs tracked.
        """
        import sys

        from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint

        code_text = '''
from hathor import Blueprint, Context, export, public

@export
class TestBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def work(self, ctx: Context) -> None:
        for i in range(10):
            self.value = self.value + i
'''
        sandbox_config = SandboxConfig(max_operations=100_000, allow_specialized_opcodes=True)

        # Create an OCB and verify its loading cost is captured
        code = Code.from_python_code(code_text, self._settings)
        ocb = OnChainBlueprint(hash=b'\x30' * 32, code=code)

        # Load with sandbox config to capture loading costs
        ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config))

        loading_costs = ocb.loading_costs
        self.assertIsNotNone(loading_costs)
        self.assertIsInstance(loading_costs, SandboxCounts)
        self.assertGreater(loading_costs.operation_count, 0)

        # Verify that get_blueprint_class returns loading_cost when not skipped
        sys.sandbox.enable()
        sandbox_config.apply()
        sys.sandbox.reset_counts()

        # When skip_loading_cost=False, the cost should be charged and returned
        blueprint_class1 = ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=False)
        after_first_load = sys.sandbox.get_counts()['operation_count']

        # When skip_loading_cost=True, the cost should NOT be charged
        blueprint_class2 = ocb.get_blueprint_class(MeteredExecutor(config=sandbox_config), skip_loading_cost=True)
        after_second_load = sys.sandbox.get_counts()['operation_count']

        sys.sandbox.reset()

        # First access should have added loading cost
        self.assertEqual(after_first_load, loading_costs.operation_count)

        # Second access (with skip) should not have added any cost
        self.assertEqual(after_second_load, after_first_load)

        # Verify that both accesses return the same class
        self.assertIs(blueprint_class1, blueprint_class2)

    def test_ocb_loading_cost_reset_between_call_chains(self) -> None:
        """Verify that loading cost tracking is reset between separate call chains.

        Two separate calls should each charge loading costs independently.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class SimpleBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.value = 0

    @public
    def increment(self, ctx: Context) -> None:
        self.value = self.value + 1
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )

        sandbox_config = SandboxConfig(max_operations=100_000)
        contract_id = self.gen_random_contract_id()

        self.runner = self.build_runner(sandbox_config=sandbox_config)
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # First call
        self.runner.call_public_method(contract_id, 'increment', self.create_context())
        call_info_1 = self.runner.get_last_call_info()

        first_call_ops = 0
        for call_record in call_info_1.calls:
            if call_record.sandbox_counters is not None:
                first_call_ops += call_record.sandbox_counters.delta.operation_count

        # Second call (separate call chain)
        self.runner.call_public_method(contract_id, 'increment', self.create_context())
        call_info_2 = self.runner.get_last_call_info()

        second_call_ops = 0
        for call_record in call_info_2.calls:
            if call_record.sandbox_counters is not None:
                second_call_ops += call_record.sandbox_counters.delta.operation_count

        # Both calls should have the same operation cost (including loading)
        # because loading costs are charged fresh for each call chain
        self.assertEqual(
            first_call_ops,
            second_call_ops,
            f"Separate call chains should have same cost: first={first_call_ops}, second={second_call_ops}"
        )
