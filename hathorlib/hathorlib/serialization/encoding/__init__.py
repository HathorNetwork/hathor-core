# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""
This module was made to hold simple encoding implementations.

Simple in this context means "not compound". For example a fixed-size int encoding can have sized/signed parameters,
but not a have a generic function or type as a parameter. For compound types (optionals, lists, dicts, ...) the encoder
should be in the `encoding_compound` module.

The general organization should be that each submodule `x` deals with a single type and look like this:

    def encode_x(serializer: Serializer, value: ValueType, ...config params...) -> None:
        ...

    def decode_x(deserializer: Deserializer, ...config params...) -> ValueType:
        ...

The "config params" are optional and specific to each encoder. Submodules should not have to take into consideration
how types are mapped to encoders.
"""
