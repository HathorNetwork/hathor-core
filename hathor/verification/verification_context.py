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

from contextlib import contextmanager
from typing import Generator

from hathor.transaction.vertex import Vertex


@contextmanager
def verification_context(vertex: Vertex) -> Generator[None, None, None]:
    """
    Create a verification context in which the storage is removed from the vertex being verified.
    This guarantees that no verification method can use the storage directly or indirectly, and instead must use
    pre-calculated verification dependencies.
    Eventually, when the storage is removed from BaseTransaction, we can delete this.
    """
    storage = vertex.base_tx.storage
    vertex.base_tx.storage = None
    try:
        yield
    finally:
        vertex.base_tx.storage = storage
