# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TypeVar

from typing_extensions import Self, override

from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.nanocontracts.types import SignedData
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.compound_encoding.signed_data import decode_signed_data, encode_signed_data
from hathorlib.utils.typing import get_args, get_origin

V = TypeVar('V', bound=NCType)


class SignedDataNCType(NCType[SignedData[V]]):
    """ Represents `SignedData[*]` values.

    The wire format is version-independent, but deserialization must produce a concrete `SignedData`
    subclass, which determines the payload-signing version. Annotations must name a concrete class
    (`SignedDataV1[T]`, `SignedDataV2[T]`), which is the class deserialization produces.
    """
    __slots__ = ('_is_hashable', '_value', '_signed_data_type')

    _value: NCType[V]
    _signed_data_type: type[SignedData[V]]

    def __init__(self, inner_nc_type: NCType[V], signed_data_type: type[SignedData[V]], /) -> None:
        self._value = inner_nc_type
        self._is_hashable = inner_nc_type.is_hashable()
        self._signed_data_type = signed_data_type

    @override
    @classmethod
    def _from_type(cls, type_: type[SignedData[V]], /, *, type_map: NCType.TypeMap) -> Self:
        origin_type = get_origin(type_) or type_
        if not issubclass(origin_type, SignedData):
            raise TypeError('expected SignedData type')
        if origin_type is SignedData:
            raise TypeError('SignedData is version-abstract; annotate with SignedDataV1 or SignedDataV2')
        signed_data_cls = origin_type
        args: tuple[type, ...] = get_args(type_) or tuple()
        if len(args) != 1:
            raise TypeError('expected one type argument')
        inner_type, = args
        # XXX: ignore index because mypy doesn't recognize dynamic class subscription, but it's correct
        signed_data_type = signed_data_cls[inner_type]  # type: ignore[index]
        return cls(NCType.from_type(inner_type, type_map=type_map), signed_data_type)

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
        return decode_signed_data(deserializer, self._value.deserialize, self._signed_data_type)

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
        return self._signed_data_type(data, script_input)

    @override
    def _value_to_json(self, value: SignedData[V], /) -> NCType.Json:
        inner_json_value = self._value.value_to_json(value.data)
        signature_json_value = value.script_input.hex()
        return [inner_json_value, signature_json_value]
