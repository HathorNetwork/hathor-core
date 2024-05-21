# Copyright 2023 Hathor Labs
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

from collections import deque
from typing import Any, Type, Union, get_args, get_origin

from hathor.nanocontracts.exception import UnknownFieldType
from hathor.nanocontracts.fields.base import Field
from hathor.nanocontracts.fields.deque_field import DequeField
from hathor.nanocontracts.fields.dict_field import DictField
from hathor.nanocontracts.fields.others import OptionalField, SignedDataField, TupleField
from hathor.nanocontracts.fields.set_field import SetField
from hathor.nanocontracts.fields.singles import (
    BooleanField,
    BytesField,
    Int32Field,
    SingleValueField,
    StrField,
    VarIntField,
)
from hathor.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VarInt,
    VertexId,
)

# Mapping between types and field classes.
# TODO: Before going to public testnet, the `int` type should be mapped
#  to `VarIntField` and the `VarInt` type should be removed. Also, the
#  `Amount` type should be mapped to the `AmountField`.
_field_mapping: dict[Any, Type[Field]] = {
    str: StrField,
    bytes: BytesField,
    int: Int32Field,
    VarInt: VarIntField,
    bool: BooleanField,
    dict: DictField,
    list: DequeField,
    set: SetField,
    deque: DequeField,
    BlueprintId: BytesField,
    ContractId: BytesField,
    Address: BytesField,
    Amount: Int32Field,
    TokenUid: BytesField,
    Timestamp: Int32Field,
    TxOutputScript: BytesField,
    VertexId: BytesField,
}


def get_special_field_class_for_attr(_type: Type[Any]) -> Type[Field]:
    origin = get_origin(_type)
    args = get_args(_type)
    if origin is Union:
        if len(args) == 2 and type(None) in args:
            return OptionalField
        else:
            # all args must map to the same field
            args_fields: set[Type[Field] | None] = set(_field_mapping.get(x) for x in args)
            if len(args_fields) == 1:
                field_class = list(args_fields)[0]
                if field_class is not None:
                    return field_class
    elif origin is SignedData:
        return SignedDataField
    elif origin is tuple:
        return TupleField
    raise UnknownFieldType(_type)


def get_field_class_for_attr(_type: Type[Any]) -> Type[Field]:
    """Return the field class for a given type."""
    origin = getattr(_type, '__origin__', _type)
    field_klass = _field_mapping.get(origin)
    if field_klass is not None:
        return field_klass
    return get_special_field_class_for_attr(_type)


def get_field_for_attr(name: str, _type: Type[Any]) -> Field:
    """Return the field instance for a given type."""
    field_klass = get_field_class_for_attr(_type)
    field = field_klass.create_from_type(name, _type)
    return field


__all__ = (
    'Field',
    'SingleValueField',
    'DictField',
    'get_field_for_attr',
)
