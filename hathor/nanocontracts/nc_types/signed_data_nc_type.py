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

from typing import TypeVar

from typing_extensions import Self, override

from hathor.nanocontracts.nc_types.nc_type import NCType
from hathor.nanocontracts.types import SignedData
from hathor.serialization import Deserializer, Serializer
from hathor.serialization.compound_encoding.signed_data import decode_signed_data, encode_signed_data
from hathor.utils.typing import get_args, get_origin

V = TypeVar('V', bound=NCType)


class SignedDataNCType(NCType[SignedData[V]]):
    """ Represents a SignedData[*] values.
    """
    __slots__ = ('_is_hashable', '_value', '_inner_type')

    _value: NCType[V]
    _inner_type: type[V]

    def __init__(self, inner_nc_type: NCType[V], inner_type: type[V], /) -> None:
        self._value = inner_nc_type
        self._is_hashable = inner_nc_type.is_hashable()
        self._inner_type = inner_type

    @override
    @classmethod
    def _from_type(cls, type_: type[SignedData[V]], /, *, type_map: NCType.TypeMap) -> Self:
        origin_type = get_origin(type_) or type_
        if not issubclass(origin_type, SignedData):
            raise TypeError('expected SignedData type')
        args: tuple[type, ...] = get_args(type_) or tuple()
        if len(args) != 1:
            raise TypeError('expected one type argument')
        inner_type, = args
        return cls(NCType.from_type(inner_type, type_map=type_map), inner_type)

    @override
    def _check_value(self, value: SignedData[V], /, *, deep: bool) -> None:
        if not isinstance(value, SignedData):
            raise TypeError('expected SignedData')
        if deep:
            self._value._check_value(value.data, deep=True)

    @override
    def _serialize(self, serializer: Serializer, value: SignedData[V], /) -> None:
        encode_signed_data(serializer, value, self._value.serialize)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> SignedData[V]:
        return decode_signed_data(deserializer, self._value.deserialize, self._inner_type)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> SignedData[V]:
        if not isinstance(json_value, list):
            raise ValueError('expected list')
        if len(json_value) != 2:
            raise ValueError('expected list of 2 elements')
        inner_json_value, signature_json_value = json_value
        data = self._value.json_to_value(inner_json_value)
        if not isinstance(signature_json_value, str):
            raise ValueError('expected str for signature')
        script_input = bytes.fromhex(signature_json_value)
        # XXX: ignore named-defined because mypy doesn't recognize self._inner_type
        # NOTE: strangely enough it gives a name-defined error but in some nearly identical situations it gives a
        #       valid-type error
        return SignedData[self._inner_type](data, script_input)  # type: ignore[name-defined]

    @override
    def _value_to_json(self, value: SignedData[V], /) -> NCType.Json:
        inner_json_value = self._value.value_to_json(value.data)
        signature_json_value = value.script_input.hex()
        return [inner_json_value, signature_json_value]
