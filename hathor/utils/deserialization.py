#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from functools import wraps
from typing import Callable, Concatenate, ParamSpec, TypeVar, cast

from hathor.transaction import BaseTransaction

T = TypeVar('T')
P = ParamSpec('P')
VertexT = TypeVar('VertexT', bound=BaseTransaction)

FnReceivingVertex = Callable[Concatenate[VertexT, P], T]
FnReceivingBytes = Callable[Concatenate[bytes | VertexT, P], T]


def deserialize_vertex(vertex_type):
    def decorator(fn):
        @wraps(fn)
        def wrapped_fn(vertex, *args, **kwargs):
            if isinstance(vertex, bytes):
                deserialized_vertex = vertex_type.create_from_struct(vertex)
                return fn(cast(VertexT, deserialized_vertex), *args, **kwargs)

            if isinstance(vertex, vertex_type):
                return fn(vertex, *args, **kwargs)

            raise AssertionError

        return wrapped_fn
    return decorator
