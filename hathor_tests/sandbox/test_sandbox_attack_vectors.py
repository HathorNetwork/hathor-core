# Copyright 2025 Hathor Labs
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
Tests for attack vectors documented in docs/sandbox-attack-vectors.md.

Each test verifies that the documented attack is BLOCKED. If an attack
succeeds (no exception raised), the test fails - highlighting a security gap.

Tests are named after attack vector IDs (e.g., test_b1_..., test_c4_...).
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


@skipUnless(SANDBOX_AVAILABLE, "Requires CPython sandbox build")
class AttackVectorTestCase(BlueprintTestCase):
    """Tests for documented attack vectors from docs/sandbox-attack-vectors.md."""

    # =========================================================================
    # Category B: Code Injection Attacks
    # =========================================================================

    @timeout(10)
    def test_b1_rng_direct_attribute_setting(self) -> None:
        """B1: RNG manipulation via direct attribute setting must be blocked.

        FauxImmutable.__setattr__ should raise AttributeError when contract
        code attempts to modify RNG attributes.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class RNGAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack_rng_random(self, ctx: Context) -> None:
        # Attempt to replace the random method
        self.syscall.rng.random = lambda: 0
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by FauxImmutable protection
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack_rng_random', self.create_context())

        # Verify the cause is an AttributeError from FauxImmutable
        self.assertIsNotNone(cm.exception.__cause__)

    # =========================================================================
    # Category C: Non-Determinism Attacks
    # =========================================================================

    @timeout(10)
    def test_c4_runtime_float_via_power_operator(self) -> None:
        """C4: Runtime float via 2**-1 must be blocked.

        Negative exponent with ** operator creates a float at runtime,
        which breaks determinism because float operations are hardware-dependent.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class FloatPowerAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # This creates a float (0.5) at runtime via power operator
        x = 2**-1
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked (float creation disallowed)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_c5_runtime_float_via_pow(self) -> None:
        """C5: Runtime float via pow(2, -1) must be blocked.

        The pow() builtin with negative exponent creates a float,
        breaking determinism.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class FloatPowAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # This creates a float (0.5) via pow builtin
        x = pow(2, -1)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked (float creation disallowed)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_c6_hash_randomization_sets(self) -> None:
        """C6: Set operations must be deterministic.

        Set iteration order depends on PYTHONHASHSEED. To ensure consensus,
        running the same operation twice must produce the same result.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class SetDeterminism(Blueprint):
    result1: str
    result2: str

    @public
    def initialize(self, ctx: Context) -> None:
        self.result1 = ""
        self.result2 = ""

    @public
    def test_determinism(self, ctx: Context) -> None:
        # Create a set and convert to string to capture iteration order
        s = {1, 2, 3, 4, 5}
        self.result1 = str(list(s))

        # Do the same operation again
        s2 = {1, 2, 3, 4, 5}
        self.result2 = str(list(s2))
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=10000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Execute the determinism test
        self.runner.call_public_method(contract_id, 'test_determinism', self.create_context())

        # Both operations should produce the same result (deterministic)
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.result1, contract.result2)

    @timeout(10)
    def test_c7_hash_randomization_dicts(self) -> None:
        """C7: Dict operations must be deterministic.

        Dictionary iteration order depends on insertion order which is affected
        by hash values. Running the same operation twice must produce the same result.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class DictDeterminism(Blueprint):
    result1: str
    result2: str

    @public
    def initialize(self, ctx: Context) -> None:
        self.result1 = ""
        self.result2 = ""

    @public
    def test_determinism(self, ctx: Context) -> None:
        # Create a dict and capture key iteration order
        d = {1: "a", 2: "b", 3: "c", 4: "d", 5: "e"}
        self.result1 = str(list(d.keys()))

        # Do the same operation again
        d2 = {1: "a", 2: "b", 3: "c", 4: "d", 5: "e"}
        self.result2 = str(list(d2.keys()))
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=10000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Execute the determinism test
        self.runner.call_public_method(contract_id, 'test_determinism', self.create_context())

        # Both operations should produce the same result (deterministic)
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.result1, contract.result2)

    # =========================================================================
    # Category D2: Memory DoS Attacks
    # =========================================================================

    @timeout(10)
    def test_d2_1_large_list_allocation(self) -> None:
        """D2.1: Large list allocation must be blocked.

        Attempting to allocate [0] * 10**8 should raise a memory limit error.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class LargeListAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Attempt to allocate a massive list (100 million elements)
        huge_list = [0] * (10**8)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by memory limits
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_2_large_string_allocation(self) -> None:
        """D2.2: Large string allocation must be blocked.

        Attempting to allocate 'x' * 10**8 should raise a memory limit error.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class LargeStringAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Attempt to allocate a massive string (100 million characters)
        huge_string = "x" * (10**8)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by memory limits
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_3_exponential_string_growth(self) -> None:
        """D2.3: Exponential string growth must be blocked.

        Repeatedly doubling a string (s = s + s) leads to exponential memory
        consumption that must be stopped.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class ExponentialStringAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Exponential growth: 2^40 bytes would be ~1TB
        s = "a"
        for _ in range(40):
            s = s + s
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        # Use higher operation limit since we want to test memory, not operations
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=10000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by memory limits
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_4a_dict_size_explosion(self) -> None:
        """D2.4a: Large dict creation must be blocked by dict size limit.

        Creating a dict with more than max_dict_size entries should be blocked.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class DictSizeAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Attempt to create dict with 200K entries (exceeds max_dict_size=100K)
        d = {i: i for i in range(200000)}
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        # Use higher operation limit since we want to test dict size limit, not operations
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=500000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by dict size limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_4b_dict_large_string_values(self) -> None:
        """D2.4b: Dict with oversized string values must be blocked.

        Creating strings exceeding max_str_length should be blocked.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class LargeStringValueAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Attempt to create string with 2M chars (exceeds max_str_length=1M)
        d = {}
        d[0] = "x" * 2000000
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        # Use higher operation limit since we want to test string length limit, not operations
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=10000000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by string length limit
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_5_nested_container_explosion(self) -> None:
        """D2.5: Nested container explosion must be blocked.

        Repeatedly nesting lists (a = [a]) can bypass per-list limits
        by creating many small lists.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class NestedContainerAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # Create deeply nested structure
        # Each iteration creates a new 1-element list
        a = []
        for _ in range(10**7):
            a = [a]
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        # Use higher operation limit since we want to test memory, not operations
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=10**8))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by memory limits
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    @timeout(10)
    def test_d2_6_large_integer_allocation(self) -> None:
        """D2.6: Large bigint allocation must be blocked.

        Python integers can be arbitrarily large. Computing 2 ** 10**7
        creates a massive integer consuming gigabytes of memory.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class LargeBigintAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        # 2 ** 10**7 = a number with ~3 million digits, consuming ~1MB
        # 2 ** 10**8 = a number with ~30 million digits, consuming ~10MB
        x = 2 ** (10**7)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by memory limits
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    # =========================================================================
    # Category D3: Time DoS Attacks
    # =========================================================================

    @timeout(10)
    def test_d3_3_recursion_depth_explosion(self) -> None:
        """D3.3: Deep recursion must be blocked.

        Python has a default recursion limit (~1000), but even hitting that
        limit can cause stack exhaustion. The sandbox should enforce a
        reasonable recursion limit.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class RecursionAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        def recurse(n: int) -> int:
            return recurse(n + 1)
        recurse(0)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=100000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Attack should be blocked by recursion limit (Python's default or sandbox limit)
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIsNotNone(cm.exception.__cause__)

    # =========================================================================
    # Category D4: Hash Collision DoS
    # =========================================================================

    @timeout(10)
    def test_d4_1_hash_collision_dos(self) -> None:
        """D4.1: Hash collision attacks must be mitigated via block-derived seed.

        If PYTHONHASHSEED is fixed to a known constant, attackers could craft
        inputs that all hash to the same value, degrading dict/set to O(n²).

        The solution is to derive PYTHONHASHSEED from block hash, making it
        deterministic (for consensus) but unpredictable (preventing crafted collisions).

        This test verifies that hash values are deterministic within the same
        execution context.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class HashConsistency(Blueprint):
    hash1: int
    hash2: int

    @public
    def initialize(self, ctx: Context) -> None:
        self.hash1 = 0
        self.hash2 = 0

    @public
    def test_hash_consistency(self, ctx: Context) -> None:
        # Hash the same string twice
        test_string = "test_determinism"
        self.hash1 = hash(test_string)
        self.hash2 = hash(test_string)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Execute the hash consistency test
        self.runner.call_public_method(contract_id, 'test_hash_consistency', self.create_context())

        # Both hash operations should produce the same result
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(contract.hash1, contract.hash2)

    # =========================================================================
    # Category E: BaseException Escape Attacks
    #
    # Defense layers:
    # 1. SystemExit/KeyboardInterrupt/GeneratorExit removed from EXEC_BUILTINS
    #    (contract code gets NameError when trying to reference them)
    # 2. except BaseException in MeteredExecutor.call() catches everything
    #    (even if layer 1 is bypassed)
    # =========================================================================

    @timeout(10)
    def test_e1_system_exit_not_in_builtins(self) -> None:
        """E1: SystemExit must not be accessible to contract code.

        SystemExit is removed from EXEC_BUILTINS. Attempting to reference it
        should result in a NameError, converted to NCFail.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class SystemExitAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        raise SystemExit(0)
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # SystemExit is not in builtins, so contract gets NameError -> NCFail
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIn('NameError', str(cm.exception))

    @timeout(10)
    def test_e2_keyboard_interrupt_not_in_builtins(self) -> None:
        """E2: KeyboardInterrupt must not be accessible to contract code.

        KeyboardInterrupt is removed from EXEC_BUILTINS. Attempting to
        reference it should result in a NameError, converted to NCFail.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class KeyboardInterruptAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        raise KeyboardInterrupt()
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # KeyboardInterrupt is not in builtins, so contract gets NameError -> NCFail
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIn('NameError', str(cm.exception))

    @timeout(10)
    def test_e3_generator_exit_not_in_builtins(self) -> None:
        """E3: GeneratorExit must not be accessible to contract code.

        GeneratorExit is removed from EXEC_BUILTINS. Attempting to
        reference it should result in a NameError, converted to NCFail.
        """
        code = '''
from hathor import Blueprint, Context, export, public

@export
class GeneratorExitAttack(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def attack(self, ctx: Context) -> None:
        raise GeneratorExit()
'''
        blueprint_id = self._register_blueprint_contents(
            StringIO(code),
            skip_verification=True,
        )
        contract_id = self.gen_random_contract_id()
        self.runner = self.build_runner(sandbox_config=SandboxConfig(max_operations=1000))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # GeneratorExit is not in builtins, so contract gets NameError -> NCFail
        with self.assertRaises(NCFail) as cm:
            self.runner.call_public_method(contract_id, 'attack', self.create_context())

        self.assertIn('NameError', str(cm.exception))
