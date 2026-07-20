# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar

from typing_extensions import Self, override

from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.adapters import MaxBytesExceededError
from hathorlib.serialization.encoding.leb128 import decode_leb128, encode_leb128
from hathorlib.serialization.encoding.output_value import decode_length_prefix_varint, encode_length_prefix_varint
from hathorlib.utils.typing import is_subclass


class _VarIntNCType(NCType[int]):
    _is_hashable = True
    # XXX: subclass must define these values:
    _signed: ClassVar[bool]
    _max_byte_size: ClassVar[int | None]

    @classmethod
    @abstractmethod
    def _upper_bound_value(cls) -> int | None:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def _lower_bound_value(cls) -> int | None:
        raise NotImplementedError

    @override
    @classmethod
    def _from_type(cls, type_: type[int], /, *, type_map: NCType.TypeMap) -> Self:
        if not is_subclass(type_, int):
            raise TypeError('expected int type')
        return cls()

    @override
    def _check_value(self, value: int, /, *, deep: bool) -> None:
        if not isinstance(value, int):
            raise TypeError('expected integer')
        self._check_range(value)

    def _check_range(self, value: int) -> None:
        upper_bound = self._upper_bound_value()
        lower_bound = self._lower_bound_value()
        if upper_bound is not None and value > upper_bound:
            raise ValueError('above upper bound')
        if lower_bound is not None and value < lower_bound:
            raise ValueError('below lower bound')

    @override
    def _serialize(self, serializer: Serializer, value: int, /) -> None:
        if self._max_byte_size is not None:
            serializer = serializer.with_max_bytes(self._max_byte_size)
        try:
            self._encode(serializer, value, signed=self._signed)
        except MaxBytesExceededError as e:
            raise ValueError('value too long') from e

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> int:
        if self._max_byte_size is not None:
            deserializer = deserializer.with_max_bytes(self._max_byte_size)
        try:
            value = self._decode(deserializer, signed=self._signed)
        except MaxBytesExceededError as e:
            raise ValueError('value too long') from e
        return value

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> int:
        # XXX: should we drop support for int?
        if not isinstance(json_value, (int, str)):
            raise ValueError('expected int or str')
        return int(json_value)

    @override
    def _value_to_json(self, value: int, /) -> NCType.Json:
        # XXX: should we use str instead?
        return value

    @abstractmethod
    def _encode(self, serializer: Serializer, value: int, *, signed: bool) -> None:
        raise NotImplementedError

    @abstractmethod
    def _decode(self, deserializer: Deserializer, *, signed: bool) -> int:
        raise NotImplementedError


class _LEB128NCType(_VarIntNCType):
    """Variable-size integer using LEB128 encoding (`TokenAmountVersion.V1`).

    `_max_byte_size` bounds the full LEB128 encoding, which carries 7 value bits per byte.
    """

    @override
    @classmethod
    def _upper_bound_value(cls) -> int | None:
        if cls._max_byte_size is None:
            return None
        if cls._signed:
            return int(2**(cls._max_byte_size * 7 - 1) - 1)
        else:
            return int(2**(cls._max_byte_size * 7) - 1)

    @override
    @classmethod
    def _lower_bound_value(cls) -> int | None:
        if not cls._signed:
            return 0
        if cls._max_byte_size is not None:
            return int(-(2**(cls._max_byte_size * 7 - 1)))
        else:
            return None

    @override
    def _encode(self, serializer: Serializer, value: int, *, signed: bool) -> None:
        encode_leb128(serializer, value, signed=signed)

    @override
    def _decode(self, deserializer: Deserializer, *, signed: bool) -> int:
        return decode_leb128(deserializer, signed=signed)


class _LPENCType(_VarIntNCType):
    """Variable-size integer using length-prefix encoding (`TokenAmountVersion.V2`).

    `_max_byte_size` bounds the full encoding: one length byte plus a minimal big-endian payload.
    """

    @override
    @classmethod
    def _upper_bound_value(cls) -> int | None:
        if cls._max_byte_size is None:
            return None
        payload_bits = (cls._max_byte_size - 1) * 8
        if cls._signed:
            return int(2**(payload_bits - 1) - 1)
        else:
            return int(2**payload_bits - 1)

    @override
    @classmethod
    def _lower_bound_value(cls) -> int | None:
        if not cls._signed:
            return 0
        if cls._max_byte_size is None:
            return None
        payload_bits = (cls._max_byte_size - 1) * 8
        return int(-(2**(payload_bits - 1)))

    @override
    def _encode(self, serializer: Serializer, value: int, *, signed: bool) -> None:
        encode_length_prefix_varint(serializer, value, signed=signed)

    @override
    def _decode(self, deserializer: Deserializer, *, signed: bool) -> int:
        return decode_length_prefix_varint(deserializer, signed=signed)


class VarInt32NCType(_LEB128NCType):
    """Variable-size signed integer with at most 32 bytes, effectively 223 bits + sign bit.
    """

    _signed = True
    _max_byte_size = 32


class VarUint32NCType(_LEB128NCType):
    """Variable-size unsigned integer with at most 32 bytes.
    """

    _signed = False
    _max_byte_size = 32


class VarInt32V2NCType(_LPENCType):
    """Variable-size signed integer with at most 32 bytes: 1 length byte + 31 payload bytes.
    """

    _signed = True
    _max_byte_size = 32


class VarUint32V2NCType(_LPENCType):
    """Variable-size unsigned integer with at most 32 bytes: 1 length byte + 31 payload bytes.
    """

    _signed = False
    _max_byte_size = 32
