# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing_extensions import Self, override

from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.encoding.bool import decode_bool, encode_bool


class BoolNCType(NCType[bool]):
    """ Represents builtin `bool` values.
    """

    _is_hashable = True

    @override
    @classmethod
    def _from_type(cls, type_: type[bool], /, *, type_map: NCType.TypeMap) -> Self:
        if type_ is not bool:
            raise TypeError('expected bool type')
        return cls()

    @override
    def _check_value(self, value: bool, /, *, deep: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError('expected boolean')

    @override
    def _serialize(self, serializer: Serializer, value: bool, /) -> None:
        encode_bool(serializer, value)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> bool:
        return decode_bool(deserializer)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> bool:
        if not isinstance(json_value, bool):
            raise ValueError('expected bool')
        return json_value

    @override
    def _value_to_json(self, value: bool, /) -> NCType.Json:
        return value
