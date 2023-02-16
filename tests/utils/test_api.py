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
from unittest.mock import Mock

from hathor.utils.api import QueryParams, ErrorResponse
from twisted.web.http import Request


def test_query_params_from_request():
    request = Mock(spec_set=Request)
    request.args = {b'a': [b'abc'], b'b': [b'123']}
    result = DummyQueryParams.from_request(request)

    assert isinstance(result, DummyQueryParams)
    assert result.a == 'abc'
    assert result.b == 123


def test_query_params_from_request_invalid():
    request = Mock(spec_set=Request)
    request.args = {b'a': [b'abc'], b'b': [b'123', b'456']}
    result = DummyQueryParams.from_request(request)

    assert isinstance(result, ErrorResponse)


class DummyQueryParams(QueryParams):
    a: str
    b: int
