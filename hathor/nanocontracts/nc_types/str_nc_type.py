#  Copyright 2025 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.consts import DEFAULT_BYTES_MAX_LENGTH
from hathor.serialization.encoding.utf8 import decode_utf8, encode_utf8


class StrNCType(NCType[str]):
    """ Represents builtin `str` values.
    """

    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[str], /, *, type_map: NCType.TypeMap) -> Self:
        if type_ is not str:
            raise TypeError('expected str type')
        return cls()

    @override
    def _check_value(self, value: str, /, *, deep: bool) -> None:
        if not isinstance(value, str):
            raise TypeError('expected str type')

    @override
    def _serialize(self, serializer: Serializer, value: str, /) -> None:
        encode_utf8(serializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH), value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> str:
        return decode_utf8(deserializer.with_max_bytes(DEFAULT_BYTES_MAX_LENGTH))

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> str:
        if not isinstance(json_value, str):
            raise ValueError('expected str')
        return json_value

    @override
    def _value_to_json(self, value: str, /) -> NCType.Json:
        return value
