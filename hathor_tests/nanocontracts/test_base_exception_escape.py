# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathor.exception import InvalidNewTransaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class TestBaseExceptionEscape(BlueprintTestCase):
    def _test_exception_escape(self, exc_name: str) -> None:
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
            nc_call.nc_method = raise_exc()

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
    def raise_exc(self, ctx: Context) -> None:
        raise {exc_name}
            ```
        """)

        artifacts.propagate_with(self.manager)

    def test_system_exit(self) -> None:
        with pytest.raises(Exception) as e:
            self._test_exception_escape('SystemExit')
        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            'full validation failed: forbidden syntax: Usage or reference to SystemExit is not allowed.'
        )

    def test_keyboard_interrupt(self) -> None:
        with pytest.raises(Exception) as e:
            self._test_exception_escape('KeyboardInterrupt')
        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            'full validation failed: forbidden syntax: Usage or reference to KeyboardInterrupt is not allowed.'
        )

    def test_base_exception(self) -> None:
        with pytest.raises(Exception) as e:
            self._test_exception_escape('BaseException')
        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            'full validation failed: forbidden syntax: Usage or reference to BaseException is not allowed.'
        )

    def test_generator_exit(self) -> None:
        with pytest.raises(Exception) as e:
            self._test_exception_escape('GeneratorExit')
        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == (
            'full validation failed: forbidden syntax: Usage or reference to GeneratorExit is not allowed.'
        )
