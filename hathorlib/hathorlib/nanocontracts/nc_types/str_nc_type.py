# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing_extensions import Self, override

from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.consts import DEFAULT_BYTES_MAX_LENGTH
from hathorlib.serialization.encoding.utf8 import decode_utf8, encode_utf8


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
