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

import inspect
import struct
from typing import Any, Callable, Type

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.nanocontracts.exception import NCSerializationArgTooLong, NCSerializationError
from hathor.nanocontracts.serializers import Deserializer, Serializer
from hathor.nanocontracts.types import Context
from hathor.transaction.util import unpack

logger = get_logger()
settings = HathorSettings()


class NCMethodParser:
    """Utility class to serialize and deserialize method arguments."""
    def __init__(self, method: Callable) -> None:
        self.method = method

    def get_method_args(self) -> list[tuple[str, Type[Any]]]:
        """Return the list of arguments for the method, including the types."""
        from hathor.nanocontracts.utils import is_nc_public_method
        argspec = inspect.getfullargspec(self.method)
        assert argspec.args[0] == 'self'
        if is_nc_public_method(self.method):
            begin_idx = 2
            assert argspec.args[1] == 'ctx'
            if argspec.annotations['ctx'] is not Context:
                raise TypeError('ctx must be of type Context')
        else:
            begin_idx = 1
        args = []
        for arg_name in argspec.args[begin_idx:]:
            arg_type = argspec.annotations[arg_name]
            args.append((arg_name, arg_type))
        return args

    def serialize_args(self, args: list[Any]) -> bytes:
        """Serialize a list of arguments into bytes according to the types."""
        method_args = self.get_method_args()
        serializer = Serializer()
        ret = []
        assert len(args) == len(method_args), f'{len(args)} != {len(method_args)} ({method_args})'
        for (arg_name, arg_type), arg_value in zip(method_args, args):
            arg_bytes = serializer.from_type(arg_type, arg_value)
            if len(arg_bytes) > settings.NC_MAX_LENGTH_SERIALIZED_ARG:
                raise NCSerializationArgTooLong
            ret.append(struct.pack('!H', len(arg_bytes)))
            ret.append(arg_bytes)
        return b''.join(ret)

    def parse_args_bytes(self, args_bytes: bytes) -> list[Any]:
        """Parse bytes into a list of arguments according to the types."""
        method_args = self.get_method_args()
        deserializer = Deserializer()
        cur = args_bytes
        ret = []
        for arg_name, arg_type in method_args:
            (n,), cur = unpack('!H', cur)
            arg_value = deserializer.from_type(arg_type, cur[:n])
            ret.append(arg_value)
            cur = cur[n:]
        if cur:
            raise NCSerializationError('Unable to parse')
        if len(ret) != len(method_args):
            raise NCSerializationError('Unable to parse: different number of arguments')
        return ret
