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

import pytest

from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TestBaseExceptionEscape(BlueprintTestCase):
    def _test_exception_escape(self, method: str) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        artifacts = dag_builder.build_from_str(f"""
            blockchain genesis b[1..12]
            b10 < dummy

            ocb.ocb_private_key = "{private_key}"
            ocb.ocb_password = "{password}"

            nc_init.nc_id = ocb
            nc_init.nc_method = initialize()

            nc_call.nc_id = nc_init
            nc_call.nc_method = {method}()

            ocb <-- b11
            b11 < nc_init
            nc_init <-- nc_call <-- b12

            ocb.ocb_code = ```
from hathor import Blueprint, Context, export, public

@export
class TestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def raise_system_exit(self, ctx: Context) -> None:
        raise SystemExit

    @public
    def raise_keyboard_interrupt(self, ctx: Context) -> None:
        raise KeyboardInterrupt

    @public
    def raise_base_exception(self, ctx: Context) -> None:
        raise BaseException

    @public
    def raise_generator_exit(self, ctx: Context) -> None:
        raise GeneratorExit
            ```
        """)

        artifacts.propagate_with(self.manager)

    def test_system_exit(self) -> None:
        # FIXME: Shouldn't crash!
        with pytest.raises(SystemExit, match='-1'):
            self._test_exception_escape('raise_system_exit')

    def test_keyboard_interrupt(self) -> None:
        # FIXME: Shouldn't crash!
        with pytest.raises(SystemExit, match='-1'):
            self._test_exception_escape('raise_keyboard_interrupt')

    def test_base_exception(self) -> None:
        # FIXME: Shouldn't crash!
        with pytest.raises(SystemExit, match='-1'):
            self._test_exception_escape('raise_base_exception')

    def test_generator_exit(self) -> None:
        # FIXME: Shouldn't crash!
        with pytest.raises(SystemExit, match='-1'):
            self._test_exception_escape('raise_generator_exit')
