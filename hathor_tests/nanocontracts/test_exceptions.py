# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import unittest


class TestExceptions(unittest.TestCase):
    def test_inherit_from_nc_fail(self) -> None:
        from hathor.exception import HathorError
        from hathor.nanocontracts import exception as nano_exceptions

        skip = {
            HathorError,
            nano_exceptions.NCFail,
            nano_exceptions.TxValidationError,
        }

        for name, obj in nano_exceptions.__dict__.items():
            if isinstance(obj, type) and obj not in skip:
                assert issubclass(obj, nano_exceptions.NCFail), f'all nano exceptions must inherit from NCFail: {name}'
