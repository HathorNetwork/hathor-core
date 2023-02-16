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

from __future__ import annotations

from typing import List, Optional, TypeVar

from pydantic import Field, ValidationError, validator
from twisted.web.http import Request

from hathor.api_util import get_args
from hathor.utils.list import single_or_none
from hathor.utils.pydantic import BaseModel


class QueryParams(BaseModel):
    _list_to_single_item_validator = validator('*', pre=True, allow_reuse=True)(single_or_none)

    @classmethod
    def from_request(cls, request: Request) -> QueryParams | ErrorResponse:
        raw_args = get_args(request).items()
        args = {k.decode('utf8'): v for k, v in raw_args}

        try:
            return cls.parse_obj(args)
        except ValidationError as error:
            return ErrorResponse(error=str(error))


class Response(BaseModel):
    pass


class ErrorResponse(Response):
    success: bool = Field(default=False, const=True)
    error: str
