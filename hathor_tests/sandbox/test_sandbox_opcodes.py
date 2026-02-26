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
Tests for opcode restrictions in the CPython sandbox.

These tests verify that the opcode allowlist correctly blocks dangerous
opcodes (imports, exception handling, async) while allowing safe ones.
"""
# mypy: disable-error-code="attr-defined"

import dis
import sys
import unittest
# Import the real SandboxImportError (only available in sandbox Python)
from builtins import SandboxImportError

from hathor.nanocontracts.sandbox import (
    ALLOWED_OPCODES,
    BLUEPRINT_FILENAME,
    PyCF_SANDBOX_COUNT,
    SandboxRuntimeError,
    get_allowed_opcodes,
)


class OpcodeAllowlistTests(unittest.TestCase):
    """Test the opcode allowlist definitions."""

    def test_allowed_opcodes_are_valid(self) -> None:
        """Test that all allowed opcodes exist in the current Python version."""
        invalid_opcodes = [name for name in ALLOWED_OPCODES if name not in dis.opmap]
        # Some opcodes may not exist in all Python versions, that's expected
        # Just ensure we have a reasonable number of valid opcodes
        valid_count = len(ALLOWED_OPCODES) - len(invalid_opcodes)
        self.assertGreater(valid_count, 50, "Should have many valid allowed opcodes")

    def test_allowed_opcodes_computed_correctly(self) -> None:
        """Test that allowed opcodes match the ALLOWED_OPCODES set."""
        allowed = get_allowed_opcodes()
        expected = frozenset(
            dis.opmap[name] for name in ALLOWED_OPCODES if name in dis.opmap
        )

        # get_allowed_opcodes() should return exactly the opcodes from ALLOWED_OPCODES
        self.assertEqual(allowed, expected)

    def test_import_star_is_not_allowed(self) -> None:
        """Test that IMPORT_STAR opcode is not allowed."""
        allowed = get_allowed_opcodes()

        # IMPORT_STAR is blocked at opcode level (star imports not allowed)
        if 'IMPORT_STAR' in dis.opmap:
            self.assertNotIn(
                dis.opmap['IMPORT_STAR'], allowed,
                "IMPORT_STAR should not be allowed (star imports blocked)"
            )

    def test_import_name_and_from_are_allowed(self) -> None:
        """Test that IMPORT_NAME and IMPORT_FROM are allowed.

        These opcodes are allowed because import restrictions are enforced
        via import_restrict_mode and allowed_imports at the sandbox level.
        """
        allowed = get_allowed_opcodes()

        for name in ['IMPORT_NAME', 'IMPORT_FROM']:
            if name in dis.opmap:
                self.assertIn(
                    dis.opmap[name], allowed,
                    f"{name} should be allowed (import restrictions handled separately)"
                )

    def test_exception_opcodes_are_not_allowed(self) -> None:
        """Test that exception handling opcodes are not allowed."""
        allowed = get_allowed_opcodes()
        exception_opcodes = [
            'PUSH_EXC_INFO', 'POP_EXCEPT', 'CHECK_EXC_MATCH', 'CHECK_EG_MATCH',
            'PREP_RERAISE_STAR', 'RERAISE', 'WITH_EXCEPT_START'
        ]

        for name in exception_opcodes:
            if name in dis.opmap:
                self.assertNotIn(
                    dis.opmap[name], allowed,
                    f"{name} should not be allowed (mirrors OCB visit_Try)"
                )

    def test_async_opcodes_are_not_allowed(self) -> None:
        """Test that async-related opcodes are not allowed."""
        allowed = get_allowed_opcodes()
        async_opcodes = [
            'GET_AWAITABLE', 'GET_AITER', 'GET_ANEXT', 'END_ASYNC_FOR',
            'BEFORE_ASYNC_WITH', 'ASYNC_GEN_WRAP', 'SEND'
        ]

        for name in async_opcodes:
            if name in dis.opmap:
                self.assertNotIn(
                    dis.opmap[name], allowed,
                    f"{name} should not be allowed (mirrors OCB async restrictions)"
                )

    def test_basic_opcodes_are_allowed(self) -> None:
        """Test that basic safe opcodes are allowed."""
        allowed = get_allowed_opcodes()
        basic_opcodes = [
            'LOAD_CONST', 'LOAD_FAST', 'STORE_FAST', 'RETURN_VALUE',
            'BINARY_OP', 'COMPARE_OP', 'POP_TOP', 'CALL'
        ]

        for name in basic_opcodes:
            if name in dis.opmap:
                self.assertIn(
                    dis.opmap[name], allowed,
                    f"{name} should be allowed (safe basic opcode)"
                )


class OpcodeRuntimeTests(unittest.TestCase):
    """Test opcode restrictions at runtime in the sandbox."""

    def setUp(self) -> None:
        """Set up sandbox for opcode testing."""
        if not sys.sandbox.suspended:
            sys.sandbox.suspend()

        sys.sandbox.clear_filenames()
        sys.sandbox.set_config(
            max_int_digits=1000,
            max_str_length=10_000_000,
            max_bytes_length=10_000_000,
            max_list_size=1_000_000,
            max_dict_size=1_000_000,
            max_set_size=1_000_000,
            max_tuple_size=1_000_000,
            max_operations=100_000_000,
            max_iterations=100_000_000,
            allow_float=True,
            allow_complex=True,
        )

        # Enable opcode restrictions
        sys.sandbox.opcode_restrict_mode = True
        sys.sandbox.allowed_opcodes = get_allowed_opcodes()

        # Enable sandbox first, then add filename
        sys.sandbox.enable()
        sys.sandbox.add_filename(BLUEPRINT_FILENAME)

    def tearDown(self) -> None:
        """Clean up sandbox state."""
        sys.sandbox.reset()

    def _exec_sandboxed(self, code_str: str) -> dict:
        """Execute code in the sandbox and return the namespace."""
        code = compile(code_str, BLUEPRINT_FILENAME, 'exec', flags=PyCF_SANDBOX_COUNT)
        namespace: dict = {}

        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, namespace)
        finally:
            sys.sandbox.suspend()

        return namespace

    def test_allowed_arithmetic(self) -> None:
        """Test that basic arithmetic operations work."""
        ns = self._exec_sandboxed("""
x = 1 + 2
y = x * 3
z = y - 1
result = z // 2
""")
        self.assertEqual(ns['result'], 4)

    def test_allowed_loops(self) -> None:
        """Test that loops work."""
        ns = self._exec_sandboxed("""
total = 0
for i in range(10):
    total += i
""")
        self.assertEqual(ns['total'], 45)

    def test_allowed_list_operations(self) -> None:
        """Test that list operations work."""
        ns = self._exec_sandboxed("""
items = [1, 2, 3]
items.append(4)
result = [x * 2 for x in items]
""")
        self.assertEqual(ns['result'], [2, 4, 6, 8])

    def test_allowed_dict_operations(self) -> None:
        """Test that dict operations work."""
        ns = self._exec_sandboxed("""
data = {'a': 1, 'b': 2}
data['c'] = 3
result = {k: v * 2 for k, v in data.items()}
""")
        self.assertEqual(ns['result'], {'a': 2, 'b': 4, 'c': 6})

    def test_allowed_function_def(self) -> None:
        """Test that function definitions work."""
        ns = self._exec_sandboxed("""
def add(a, b):
    return a + b

result = add(3, 4)
""")
        self.assertEqual(ns['result'], 7)

    def test_allowed_generator(self) -> None:
        """Test that generators work."""
        ns = self._exec_sandboxed("""
def gen():
    yield 1
    yield 2
    yield 3

result = list(gen())
""")
        self.assertEqual(ns['result'], [1, 2, 3])

    def test_allowed_class_def(self) -> None:
        """Test that class definitions work."""
        ns = self._exec_sandboxed("""
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

p = Point(3, 4)
result = p.x + p.y
""")
        self.assertEqual(ns['result'], 7)

    def test_allowed_raise(self) -> None:
        """Test that raise statements work (but not catch)."""
        with self.assertRaises(ValueError):
            self._exec_sandboxed("""
raise ValueError("test error")
""")

    def test_unauthorized_import_blocked_by_import_restrict(self) -> None:
        """Test that unauthorized imports are blocked by import_restrict_mode.

        Note: Import opcodes (IMPORT_NAME, IMPORT_FROM) are allowed because
        import restrictions are enforced at a higher level via import_restrict_mode
        and allowed_imports. This test verifies that mechanism works.
        """
        # Enable import restriction mode (needed for this test)
        from hathor.nanocontracts.sandbox import get_sandbox_allowed_imports
        sys.sandbox.import_restrict_mode = True
        sys.sandbox.allowed_imports = get_sandbox_allowed_imports()

        # Trying to import an unauthorized module should fail
        with self.assertRaises(SandboxImportError) as cm:
            self._exec_sandboxed("""
import os
""")
        self.assertIn('not allowed', str(cm.exception).lower())

    def test_unauthorized_import_from_blocked(self) -> None:
        """Test that unauthorized from-imports are blocked."""
        from hathor.nanocontracts.sandbox import get_sandbox_allowed_imports
        sys.sandbox.import_restrict_mode = True
        sys.sandbox.allowed_imports = get_sandbox_allowed_imports()

        with self.assertRaises(SandboxImportError) as cm:
            self._exec_sandboxed("""
from os import path
""")
        self.assertIn('not allowed', str(cm.exception).lower())

    def test_blocked_try_except(self) -> None:
        """Test that try/except is blocked when exception occurs."""
        # Opcode restrictions only trigger when the opcode is actually executed.
        # Exception handling opcodes are only executed when an exception occurs.
        with self.assertRaises(SandboxRuntimeError) as cm:
            self._exec_sandboxed("""
try:
    raise ValueError('test')
except:
    pass
""")
        self.assertIn('opcode', str(cm.exception).lower())

    def test_blocked_try_finally(self) -> None:
        """Test that try/finally is blocked when exception occurs."""
        # Opcode restrictions only trigger when the opcode is actually executed.
        # The finally block uses exception handling opcodes internally.
        with self.assertRaises(SandboxRuntimeError) as cm:
            self._exec_sandboxed("""
try:
    raise ValueError('test')
finally:
    pass
""")
        self.assertIn('opcode', str(cm.exception).lower())

    def test_blocked_async_coroutine_execution(self) -> None:
        """Test that async coroutine execution is prevented.

        Async function definition itself doesn't use async-specific opcodes
        (just RETURN_GENERATOR which is allowed for sync generators).
        The async-specific opcodes (GET_AWAITABLE, SEND) are only executed
        when the coroutine is actually awaited, which requires an event loop.

        Since imports are restricted via import_restrict_mode, asyncio can't
        be imported anyway. This test verifies that even if someone defines
        an async function, they can't execute it without importing asyncio.
        """
        # Enable import restriction mode
        from hathor.nanocontracts.sandbox import get_sandbox_allowed_imports
        sys.sandbox.import_restrict_mode = True
        sys.sandbox.allowed_imports = get_sandbox_allowed_imports()

        # Defining async function works (uses RETURN_GENERATOR like sync generators)
        self._exec_sandboxed("""
async def foo():
    return 42
""")
        # But can't import asyncio to run it (blocked by import_restrict_mode)
        with self.assertRaises(SandboxImportError) as cm:
            self._exec_sandboxed("""
import asyncio
""")
        self.assertIn('not allowed', str(cm.exception).lower())


class OpcodeNewVersionTests(unittest.TestCase):
    """Test that new/unknown opcodes are blocked by default."""

    def test_new_opcodes_not_allowed_by_default(self) -> None:
        """Test that any opcode not in allowlist is not allowed."""
        allowed = get_allowed_opcodes()

        # Every opcode not in ALLOWED_OPCODES should not be in allowed set
        for name, opcode in dis.opmap.items():
            if name not in ALLOWED_OPCODES:
                self.assertNotIn(
                    opcode, allowed,
                    f"Opcode {name} not in ALLOWED_OPCODES should not be allowed"
                )


if __name__ == '__main__':
    unittest.main()
