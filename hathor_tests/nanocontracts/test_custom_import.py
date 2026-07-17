# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import builtins
from io import StringIO
from textwrap import dedent
from unittest.mock import ANY, Mock, call, patch

from hathor.nanocontracts.custom_builtins import get_exec_builtins
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.token_amount_version import TokenAmountVersion


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
        exec_builtins = get_exec_builtins(TokenAmountVersion.V1)
        wrapped_import_function = Mock(wraps=exec_builtins['__import__'])
        exec_builtins['__import__'] = wrapped_import_function

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
