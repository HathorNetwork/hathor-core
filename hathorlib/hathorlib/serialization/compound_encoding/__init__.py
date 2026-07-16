# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""
This module was made to hold compound encoding implementations.

Compound encoders are encoders that are generic in some way and will delegate the encoding of some portion to another
encoder. For example a `value: Optional[T]` encoder is prepared to encode the value and delegate the rest to an encoder
that knows how to encode `T`.

The general organization should be that each submodule `x` deals with a single type and look like this:

    def encode_x(serializer: Serializer, value: ValueType, ...config params...) -> None:
        ...

    def decode_x(deserializer: Deserializer, ...config params...) -> ValueType:
        ...

The "config params" are optional and specific to each encoder. Submodules should not have to take into consideration
how types are mapped to encoders.
"""

from typing import Protocol, TypeVar

from hathorlib.serialization.deserializer import Deserializer
from hathorlib.serialization.serializer import Serializer

T_co = TypeVar('T_co', covariant=True)
T_contra = TypeVar('T_contra', contravariant=True)


class Decoder(Protocol[T_co]):
    def __call__(self, deserializer: Deserializer, /) -> T_co:
        ...


class Encoder(Protocol[T_contra]):
    def __call__(self, serializer: Serializer, value: T_contra, /) -> None:
        ...
