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

from types import NoneType

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.serialization import Deserializer, Serializer


class NullNCType(NCType[None]):
    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[None], /, *, type_map: NCType.TypeMap) -> Self:
        # XXX: usually we expect NoneType as type_, but in some cases it can come-in as None, and we take that too
        if type_ is None or type_ is NoneType:
            return cls()
        raise TypeError('expected None type')

    @override
    def _check_value(self, value: None, /, *, deep: bool) -> None:
        if value is not None:
            raise TypeError('expected None')

    @override
    def _serialize(self, serializer: Serializer, value: None, /) -> None:
        # XXX: zero sized serialization, nothing to do
        pass

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> None:
        # XXX: zero sized serialization, nothing to do
        pass

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> None:
        if json_value is not None:
            raise ValueError('expected None/null')
        return None

    @override
    def _value_to_json(self, value: None, /) -> NCType.Json:
        return None
