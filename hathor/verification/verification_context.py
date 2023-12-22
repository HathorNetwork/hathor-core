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

import functools
from typing import Callable, ParamSpec, TypeVar

from hathor.transaction import BaseTransaction

T = TypeVar('T')
P = ParamSpec('P')


def verification_context(fn: Callable[P, T]) -> Callable[P, T]:
    """
    A verification context decorator in which the storage is removed from the vertex being verified. This guarantees
    that no verification method can use the storage directly or indirectly, and instead must use pre-calculated
    verification dependencies. This is to prevent human error when changing verification code. Eventually,
    when the storage is removed from BaseTransaction, we can delete this.

    This decorator requires that the decorated function has exactly one argument that is a BaseTransaction.
    """
    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        all_args = [*args, *kwargs.values()]
        base_tx_args = [arg for arg in all_args if isinstance(arg, BaseTransaction)]
        assert len(base_tx_args) == 1, 'The decorated function must have exactly 1 BaseTransaction parameter.'
        base_tx = base_tx_args[0]
        storage = base_tx.storage
        base_tx.storage = None

        try:
            return fn(*args, **kwargs)
        finally:
            base_tx.storage = storage

    return wrapper
