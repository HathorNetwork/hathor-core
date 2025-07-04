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

from abc import ABC, abstractmethod
from typing import Generic, NamedTuple, TypeAlias, TypeVar, final

from typing_extensions import Self

from hathor.nanocontracts.nc_types.utils import TypeAliasMap, TypeToNCTypeMap, get_aliased_type, get_usable_origin_type
from hathor.serialization import Deserializer, Serializer

T = TypeVar('T')


class NCType(ABC, Generic[T]):
    """ This class is used to model a type with a known type signature and how it will be (de)serialized.

    It's used for modeling the serialization of NC method calls (the method signature defines the NCType), and also
    used for modeling a the values that can go in immutable NC properties, and as key/value/members of mutable NC
    properties (NC properties are modeled with the Field class, most of which make use of NCType classes).

    Instances of this class are not visible to blueprints, so don't need strong protections against private properties.
    """

    # These are all the values that can be observed when parsing a JSON with the builtin json module
    # See: https://docs.python.org/3/library/json.html#encoders-and-decoders
    # It is a shortcut to allow methods to talk about values that can be used with the json module
    Json: TypeAlias = dict | list | str | int | float | bool | None

    class TypeMap(NamedTuple):
        alias_map: TypeAliasMap
        nc_types_map: TypeToNCTypeMap

    # XXX: subclasses must override this if they need any properties
    __slots__ = ()

    # XXX: subclasses must initialize this property
    _is_hashable: bool

    @final
    @staticmethod
    def from_type(type_: type[T], /, *, type_map: TypeMap) -> NCType[T]:
        """ Instantiate a NCType instance from a type signature using the given maps.

        A `type_nc_type_map` associates concrete types to concrete NCType classes, while a `type_alias_map` associate
        types with substitute types to use instead.
        """
        usable_origin = get_usable_origin_type(type_, type_map=type_map)
        nc_type = type_map.nc_types_map[usable_origin]
        # XXX: first we try to create the nc_type without making an alias, this ensures that an invalid annotation
        #      would not be accepted
        _ = nc_type._from_type(type_, type_map=type_map)
        # XXX: then we create the actual nc_type with type-alias
        aliased_type = get_aliased_type(type_, type_map.alias_map)
        return nc_type._from_type(aliased_type, type_map=type_map)

    @final
    @staticmethod
    def check_type(type_: type[T], /, *, type_map: TypeMap) -> None:
        usable_origin = get_usable_origin_type(type_, type_map=type_map)
        nc_type = type_map.nc_types_map[usable_origin]
        # XXX: first we try to create the nc_type without making an alias, this ensures that an invalid annotation
        #      would not be accepted
        _ = nc_type._from_type(type_, type_map=type_map)
        # XXX: then we create the actual nc_type with type-alias
        aliased_type = get_aliased_type(type_, type_map.alias_map)
        # XXX: currently this is identical to from_type() but doesn't return the nc_type
        nc_type._from_type(aliased_type, type_map=type_map)

    @classmethod
    def _from_type(cls, type_: type[T], /, *, type_map: TypeMap) -> Self:
        """ Instantiate a NCType instance from a type signature.

        The implementation is expected to inspect the given type's origin and args to check for compatibility and to
        decide on using `NCType.from_type`, forwarding the given `type_map` to continue instantiating NCType
        specializations, this is the case particularly for compount NCTypes, like OptionalNCType or DictNCType.
        """
        # XXX: a NCType that is only meant for local use does not need to implement _from_type
        raise TypeError(f'{cls} is not compatible with use in a NCType.TypeMap')

    @final
    def is_hashable(self) -> bool:
        """ Indicates whether the type being abstracted over is expected to be hashable.

        This is used to help maintain prevent unhashable types from being used as keys in dicts or members in sets."""
        return self._is_hashable

    @final
    def check_value(self, value: T, /) -> None:
        """ Implementation should raise a TypeError if the value's type is not compatible.

        If `deep=True` then the check should recurse for compound types (like lists/maps) to check each value. It is
        expected that `deep=False` is used in a context where the recursion would be made externally, so to avoid
        checking the same value multiple times `deep=False` is used.

        A value being compatible is more than just having the correct instance, for example if the value is a dict, all
        the dict's keys and values must be checked for compatibility.
        """
        # XXX: subclasses must implement NCType._check_value, not NCType.check_value
        self._check_value(value, deep=True)

    @final
    def serialize(self, serializer: Serializer, value: T, /) -> None:
        """ Serialize a value instance according to the signature that was abstracted.

        Serialization includes calling check_value while the value is being serialized, so calling check_value before
        calling serialize is not needed.
        """
        # XXX: subclasses must implement NCType._serialize, not NCType.serialize
        self._check_value(value, deep=False)
        self._serialize(serializer, value)

    @final
    def deserialize(self, deserializer: Deserializer, /) -> T:
        """ Deserialize a value instance according to the signature that was abstracted.

        Deserialization includes asserting check_value while the value is being deserialized, so calling check_value
        after calling deserialize is not needed. Moreover, deserialization is already expected to produce valid values,
        so checking is only made as a double check and results in AssertionError (no TypeError).
        """
        # XXX: subclasses must implement NCType._deserialize, not NCType.deserialize
        value = self._deserialize(deserializer)
        self._check_value(value, deep=False)
        return value

    @final
    def to_bytes(self, value: T, /) -> bytes:
        """ Shortcut to quickly convert a value T to `bytes` and avoid using the serialization system.
        """
        serializer = Serializer.build_bytes_serializer()
        self.serialize(serializer, value)
        return bytes(serializer.finalize())

    @final
    def from_bytes(self, data: bytes, /) -> T:
        """ Shortcut to quickly parse a value T from `bytes` and avoid using the serialization system.
        """
        deserializer = Deserializer.build_bytes_deserializer(data)
        value = self.deserialize(deserializer)
        deserializer.finalize()
        return value

    @final
    def json_to_value(self, json_value: Json, /) -> T:
        """ Use this to convert a value that comes out from `json.load` into the value that this class expects.

        Will raise a ValueError if the given `json_value` is not compatible.
        """
        # XXX: subclasses must implement NCType._json_to_value, not NCType.json_to_value
        value = self._json_to_value(json_value)
        self._check_value(value, deep=False)
        return value

    @final
    def value_to_json(self, value: T, /) -> Json:
        """ Use this to convert a value to an object compatible with `json.dump`.

        Will raise a ValueError if the given `value` is not compatible.
        """
        # XXX: subclasses must implement NCType._value_to_json, not NCType.value_to_json
        self._check_value(value, deep=False)
        json_value = self._value_to_json(value)
        return json_value

    @abstractmethod
    def _check_value(self, value: T, /, *, deep: bool) -> None:
        """ Inner implementation of `NCType.check_value`, should return True is the given value is valid.

        Compound values should use `NCType._check_value` on the inner type(s) instead of `NCType.check_value` and pass
        the appropriate deep argument.
        """
        raise NotImplementedError

    @abstractmethod
    def _serialize(self, serializer: Serializer, value: T, /) -> None:
        """ Inner implementation of `serialize`, you can assume that the give value has been "shallow checked".

        When implementing the serialization with compound encoders, `NCType.serialize` should be passed as an `Encoder`
        instead of `NCType._serialize`, by passing `NCType.serialize` the next `Vallue._serialize` implementation will
        be able to assume that the value was checked.
        """
        raise NotImplementedError

    @abstractmethod
    def _deserialize(self, deserializer: Deserializer, /) -> T:
        """ Inner implementation of `deserialize`, it is expected that deserializers always produce valid values.

        Even then, `NCType.deserialize` should be passed as a `Decoder`, that way it's possible to do a "shallow check"
        for asserting that a valid value was produced.
        """
        raise NotImplementedError

    # this are optional to implement, but provide the ability to convert to/from JSON

    def _json_to_value(self, json: Json, /) -> T:
        """ Inner implementation of `NCType.json_to_value`."""
        raise ValueError('this class does not support JSON conversion')

    def _value_to_json(self, value: T, /) -> Json:
        """ Inner implementation of `NCType.value_to_json`."""
        raise ValueError('this class does not support JSON conversion')
