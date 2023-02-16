#  Copyright 2023 Hathor Labs
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
