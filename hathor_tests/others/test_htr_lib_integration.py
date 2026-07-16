# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import htr_lib


def test_sum_as_string() -> None:
    assert htr_lib.sum_as_string(2, 3) == '5'
