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

from email.message import Message
from typing import Literal, Type, TypeVar, Union

from pydantic import ValidationError
from twisted.web.http import Request

from hathor.api_util import get_args
from hathor.utils.list import single_or_none
from hathor.utils.pydantic import BaseModel

T = TypeVar('T', bound='QueryParams')


class QueryParams(BaseModel):
    """Class used to parse Twisted HTTP Request query parameters.

    Subclass this class defining your query parameters as attributes and their respective types, then call the
    from_request() class method to instantiate your class from the provided request.
    """

    @classmethod
    def from_request(cls: Type[T], request: Request) -> Union[T, 'ErrorResponse']:
        """Creates an instance from a Twisted Request."""
        encoding = 'utf8'

        if content_type_header := request.requestHeaders.getRawHeaders('content-type'):
            m = Message()
            m['content-type'] = content_type_header[0]
            encoding_raw = m.get_param('charset', encoding)
            assert isinstance(encoding_raw, str)
            encoding = encoding_raw

        raw_args = get_args(request).items()
        args: dict[str, str | None | list[str]] = {}
        for key, values in raw_args:
            decoded_key = key.decode(encoding)
            decoded_values: list[str] = [value.decode(encoding) for value in values]
            if not decoded_key.endswith('[]'):
                try:
                    args[decoded_key] = single_or_none(decoded_values)
                except Exception as error:
                    return ErrorResponse(error=str(error))
            else:
                args[decoded_key] = decoded_values

        try:
            return cls.model_validate(args)
        except ValidationError as error:
            return ErrorResponse(error=str(error))


class Response(BaseModel):
    pass


class ErrorResponse(Response):
    success: Literal[False] = False
    error: str
