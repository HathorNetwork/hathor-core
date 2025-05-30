# Copyright 2025 Hathor Labs
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
