#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import builtins
from io import StringIO
from textwrap import dedent
from unittest import TestCase
from unittest.mock import ANY, Mock, call, patch

from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS
from hathor.nanocontracts.sandbox import ALLOWED_IMPORTS, get_sandbox_allowed_imports, get_sandbox_allowed_modules
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TestCustomImport(BlueprintTestCase):
    def test_custom_import_is_used(self) -> None:
        """Guarantee our custom import function is being called, instead of the builtin one."""
        contract_id = self.gen_random_contract_id()
        blueprint = '''
            from hathor import Blueprint, Context, export, public

            @export
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    from math import ceil, floor
                    from collections import OrderedDict
                    from hathor import NCFail, NCAction, NCActionType
        '''

        # Wrap our custom builtin so we can spy its calls
        wrapped_import_function = Mock(wraps=EXEC_BUILTINS['__import__'])
        EXEC_BUILTINS['__import__'] = wrapped_import_function

        # Before being used, the function is uncalled
        wrapped_import_function.assert_not_called()

        # During blueprint registration, the function is called for each import at the module level.
        # This happens twice, once during verification and once during the actual registration.
        blueprint_id = self._register_blueprint_contents(StringIO(dedent(blueprint)))
        module_level_calls = [
            call('hathor', ANY, ANY, ('Blueprint', 'Context', 'export', 'public'), 0),
        ]
        assert wrapped_import_function.call_count == 2 * len(module_level_calls)
        wrapped_import_function.assert_has_calls(2 * module_level_calls)
        wrapped_import_function.reset_mock()

        # During the call to initialize(), the function is called for each import on that method.
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())
        method_level_imports = [
            call('math', ANY, ANY, ('ceil', 'floor'), 0),
            call('collections', ANY, ANY, ('OrderedDict',), 0),
            call('hathor', ANY, ANY, ('NCFail', 'NCAction', 'NCActionType'), 0),
        ]
        assert wrapped_import_function.call_count == len(method_level_imports)
        wrapped_import_function.assert_has_calls(method_level_imports)

    def test_builtin_import_is_not_used(self) -> None:
        """
        Guarantee the builtin import function is never called in the contract runtime.

        To implement this test we need to use source code instead of a class directly, otherwise
        the imports wouldn't run during nano runtime, but before. Because of that, we also need to
        use `inject_in_class` to provide the blueprint with objects it cannot normally import.
        """
        contract_id = self.gen_random_contract_id()
        blueprint = '''
            from hathor import Blueprint, Context, export, public

            @export
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    wrapped_builtin_import = self.Mock(wraps=self.builtins.__import__)
                    wrapped_builtin_import.assert_not_called()

                    with self.patch.object(self.builtins, '__import__', wrapped_builtin_import):
                        from math import ceil, floor
                        from collections import OrderedDict
                        from hathor import NCFail, NCAction, NCActionType

                    wrapped_builtin_import.assert_not_called()
        '''

        blueprint_id = self._register_blueprint_contents(
            contents=StringIO(dedent(blueprint)),
            skip_verification=True,
            inject_in_class=dict(
                builtins=builtins,
                Mock=Mock,
                patch=patch,
            )
        )
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())


class TestSandboxAllowedImports(TestCase):
    """Tests for the get_sandbox_allowed_imports() helper function."""

    def test_returns_frozenset(self) -> None:
        """Verify the function returns a frozenset."""
        result = get_sandbox_allowed_imports()
        self.assertIsInstance(result, frozenset)

    def test_contains_dotted_strings(self) -> None:
        """Verify all elements are dotted module.attribute strings."""
        result = get_sandbox_allowed_imports()
        for item in result:
            self.assertIsInstance(item, str)
            self.assertIn('.', item, f"Expected dotted string, got: {item}")

    def test_contains_math_imports(self) -> None:
        """Verify math module imports are included."""
        result = get_sandbox_allowed_imports()
        self.assertIn('math.ceil', result)
        self.assertIn('math.floor', result)

    def test_contains_typing_imports(self) -> None:
        """Verify typing module imports are included."""
        result = get_sandbox_allowed_imports()
        self.assertIn('typing.Optional', result)
        self.assertIn('typing.NamedTuple', result)
        self.assertIn('typing.TypeAlias', result)
        self.assertIn('typing.Union', result)

    def test_contains_collections_imports(self) -> None:
        """Verify collections module imports are included."""
        result = get_sandbox_allowed_imports()
        self.assertIn('collections.OrderedDict', result)

    def test_contains_hathor_imports(self) -> None:
        """Verify hathor module imports are included."""
        result = get_sandbox_allowed_imports()
        self.assertIn('hathor.Blueprint', result)
        self.assertIn('hathor.NCFail', result)
        self.assertIn('hathor.public', result)
        self.assertIn('hathor.view', result)
        self.assertIn('hathor.export', result)

    def test_matches_allowed_imports_count(self) -> None:
        """Verify the result has the same number of entries as ALLOWED_IMPORTS."""
        result = get_sandbox_allowed_imports()
        expected_count = sum(len(attrs) for attrs in ALLOWED_IMPORTS.values())
        self.assertEqual(len(result), expected_count)

    def test_all_allowed_imports_are_present(self) -> None:
        """Verify every entry in ALLOWED_IMPORTS is present in the result."""
        result = get_sandbox_allowed_imports()
        for module_name, attributes in ALLOWED_IMPORTS.items():
            for attr_name in attributes:
                self.assertIn(
                    f'{module_name}.{attr_name}',
                    result,
                    f"Missing {module_name}.{attr_name} in sandbox allowed imports"
                )


class TestSandboxAllowedModules(TestCase):
    """Tests for the get_sandbox_allowed_modules() helper function."""

    def test_returns_frozenset(self) -> None:
        """Verify the function returns a frozenset."""
        result = get_sandbox_allowed_modules()
        self.assertIsInstance(result, frozenset)

    def test_contains_expected_modules(self) -> None:
        """Verify expected modules are included."""
        result = get_sandbox_allowed_modules()
        self.assertIn('math', result)
        self.assertIn('typing', result)
        self.assertIn('collections', result)
        self.assertIn('hathor', result)

    def test_matches_allowed_imports_keys(self) -> None:
        """Verify the result matches the keys of ALLOWED_IMPORTS."""
        result = get_sandbox_allowed_modules()
        self.assertEqual(result, frozenset(ALLOWED_IMPORTS.keys()))


class TestSandboxImportRestrictionsIntegration(BlueprintTestCase):
    """Integration tests that verify sandbox import restrictions are correctly applied via Runner."""

    def test_allowed_import_works_via_runner(self) -> None:
        """Verify that allowed imports (e.g., from math) work correctly via the Runner."""
        contract_id = self.gen_random_contract_id()
        blueprint = '''
            from hathor import Blueprint, Context, export, public

            @export
            class MyBlueprint(Blueprint):
                result: int

                @public
                def initialize(self, ctx: Context) -> None:
                    from math import ceil
                    self.result = ceil(1)
        '''

        blueprint_id = self._register_blueprint_contents(StringIO(dedent(blueprint)))
        self.runner.create_contract(contract_id, blueprint_id, self.create_context())

        # Verify the contract was created successfully and math.ceil worked
        contract = self.get_readonly_contract(contract_id)
        self.assertEqual(getattr(contract, 'result'), 1)

    def test_disallowed_import_blocked_by_custom_import(self) -> None:
        """Verify that disallowed imports are blocked by our custom __import__ builtin.

        Note: The error is wrapped in NCFail by the metered executor.
        """
        from hathor.nanocontracts.exception import NCFail

        contract_id = self.gen_random_contract_id()
        blueprint = '''
            from hathor import Blueprint, Context, export, public

            @export
            class MyBlueprint(Blueprint):
                @public
                def initialize(self, ctx: Context) -> None:
                    from os import getcwd  # os is not in ALLOWED_IMPORTS
        '''

        blueprint_id = self._register_blueprint_contents(
            StringIO(dedent(blueprint)),
            skip_verification=True,  # Skip AST verification to test runtime behavior
        )

        # Should raise NCFail wrapping ImportError from our custom __import__ builtin
        with self.assertRaises(NCFail) as cm:
            self.runner.create_contract(contract_id, blueprint_id, self.create_context())
        self.assertIn('ImportError', str(cm.exception))
        self.assertIn('os', str(cm.exception))


class TestSandboxConfigAppliesRestrictions(TestCase):
    """Tests that verify SandboxConfig.apply() correctly configures sandbox restrictions."""

    def setUp(self) -> None:
        """Reset sandbox state before each test."""
        import sys
        if hasattr(sys, 'sandbox'):
            sys.sandbox.reset()

    def tearDown(self) -> None:
        """Clean up sandbox state after each test."""
        import sys
        if hasattr(sys, 'sandbox'):
            sys.sandbox.reset()

    def test_sandbox_config_sets_import_restrict_mode(self) -> None:
        """Verify that SandboxConfig.apply() enables import_restrict_mode."""
        import sys

        from hathor.nanocontracts.sandbox import SandboxConfig

        config = SandboxConfig()
        sys.sandbox.enable()  # type: ignore[attr-defined]
        config.apply()

        self.assertTrue(sys.sandbox.import_restrict_mode)  # type: ignore[attr-defined]

    def test_sandbox_config_sets_allowed_imports(self) -> None:
        """Verify that SandboxConfig.apply() sets allowed_imports correctly."""
        import sys

        from hathor.nanocontracts.sandbox import SandboxConfig

        config = SandboxConfig()
        sys.sandbox.enable()  # type: ignore[attr-defined]
        config.apply()

        allowed_imports = sys.sandbox.allowed_imports  # type: ignore[attr-defined]
        self.assertIsInstance(allowed_imports, frozenset)
        # Verify some expected imports are present (dotted strings)
        self.assertIn('math.ceil', allowed_imports)
        self.assertIn('hathor.Blueprint', allowed_imports)
        # Verify it matches our get_sandbox_allowed_imports() function
        self.assertEqual(allowed_imports, get_sandbox_allowed_imports())

    def test_sandbox_config_sets_module_access_restrict_mode(self) -> None:
        """Verify that SandboxConfig.apply() enables module_access_restrict_mode."""
        import sys

        from hathor.nanocontracts.sandbox import SandboxConfig

        config = SandboxConfig()
        sys.sandbox.enable()  # type: ignore[attr-defined]
        config.apply()

        self.assertTrue(sys.sandbox.module_access_restrict_mode)  # type: ignore[attr-defined]

    def test_sandbox_config_sets_allowed_modules(self) -> None:
        """Verify that SandboxConfig.apply() sets allowed_modules correctly."""
        import sys

        from hathor.nanocontracts.sandbox import SandboxConfig

        config = SandboxConfig()
        sys.sandbox.enable()  # type: ignore[attr-defined]
        config.apply()

        allowed_modules = sys.sandbox.allowed_modules  # type: ignore[attr-defined]
        self.assertIsInstance(allowed_modules, frozenset)
        # Verify expected modules are present
        self.assertIn('math', allowed_modules)
        self.assertIn('typing', allowed_modules)
        self.assertIn('collections', allowed_modules)
        self.assertIn('hathor', allowed_modules)
        # Verify it matches our get_sandbox_allowed_modules() function
        self.assertEqual(allowed_modules, get_sandbox_allowed_modules())
