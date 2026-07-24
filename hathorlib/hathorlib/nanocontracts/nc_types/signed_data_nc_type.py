# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import ClassVar, TypeVar

from typing_extensions import Self, override

from hathorlib.nanocontracts.nc_types.nc_type import NCType
from hathorlib.nanocontracts.types import SignedData
from hathorlib.serialization import Deserializer, Serializer
from hathorlib.serialization.compound_encoding.signed_data import decode_signed_data, encode_signed_data
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.utils.typing import get_args, get_origin

V = TypeVar('V', bound=NCType)


class SignedDataNCType(NCType[SignedData[V]]):
    """ Represents a SignedData[*] values.

    Values produced by deserialization are stamped with `_token_amount_version`, so that serializing their
    signed payload (`SignedData.get_data_bytes`/`checksig`) uses the same encodings that produced them.
    """
    __slots__ = ('_is_hashable', '_value', '_inner_type')

    _token_amount_version: ClassVar[TokenAmountVersion] = TokenAmountVersion.V1

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
        value = decode_signed_data(deserializer, self._value.deserialize, self._inner_type)
        value._token_amount_version = self._token_amount_version
        return value

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
        signed_data_type = SignedData[self._inner_type]  # type: ignore[name-defined]
        return signed_data_type(data, script_input, self._token_amount_version)

    @override
    def _value_to_json(self, value: SignedData[V], /) -> NCType.Json:
        inner_json_value = self._value.value_to_json(value.data)
        signature_json_value = value.script_input.hex()
        return [inner_json_value, signature_json_value]


class SignedDataV2NCType(SignedDataNCType):
    """ A `SignedDataNCType` that stamps values with `TokenAmountVersion.V2`.

    Swapped into type maps by `update_type_map`, mirroring the version-specific `int`/`Amount` NCTypes.
    """
    __slots__ = ()

    _token_amount_version: ClassVar[TokenAmountVersion] = TokenAmountVersion.V2
