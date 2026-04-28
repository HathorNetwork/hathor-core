# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathor.utils.list import single_or_none


def test_single_or_none_empty():
    result = single_or_none([])

    assert result is None


@pytest.mark.parametrize('value', [None, 1, 10.4, 'test', b'test'])
def test_single_or_none_one(value):
    result = single_or_none([value])

    assert result == value


def test_single_or_none_more_than_one():
    with pytest.raises(AssertionError) as exc_info:
        single_or_none([1, 2, 3])

    assert exc_info.value.args[0] == 'expected one value at most'
