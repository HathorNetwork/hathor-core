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
from hathor.serialization.encoding.bool import decode_bool, encode_bool
from hathor.serialization.exceptions import SerializationTypeError


class BoolNCType(NCType[bool]):
    """ Represents builtin `bool` values.
    """

    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[bool], /, *, type_map: NCType.TypeMap) -> Self:
        if type_ is not bool:
            raise NCTypeError('expected bool type')
        return cls()

    @override
    def _check_value(self, value: bool, /, *, deep: bool) -> None:
        if not isinstance(value, bool):
            raise NCTypeError('expected boolean')

    @override
    def _serialize(self, serializer: Serializer, value: bool, /) -> None:
        encode_bool(serializer, value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> bool:
        return decode_bool(deserializer)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> bool:
        if not isinstance(json_value, bool):
            raise NCValueError('expected bool')
        return json_value

    @override
    def _value_to_json(self, value: bool, /) -> NCType.Json:
        return value
