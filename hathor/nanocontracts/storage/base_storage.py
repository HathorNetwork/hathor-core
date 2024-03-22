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

from abc import ABC, abstractmethod
from typing import Any


class NCBaseStorage(ABC):
    """This is the storage used by NanoContracts.
    """

    @abstractmethod
    def get(self, key: str) -> Any:
        """Return the value of the provided `key`.

        It raises KeyError if key is not found.
        """
        raise NotImplementedError

    @abstractmethod
    def put(self, key: str, value: Any) -> None:
        """Store the `value` for the provided `key`.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete `key` from storage.
        """
        raise NotImplementedError

    @abstractmethod
    def get_balance(self, token_uid: bytes) -> int:
        """Return the contract balance for a token."""
        raise NotImplementedError

    @abstractmethod
    def add_balance(self, token_uid: bytes, amount: int) -> None:
        """Change the contract balance for a token. The amount will be added to the previous balance.

        Note that the amount might be negative."""
        raise NotImplementedError


class NCStorageFactory(ABC):
    def __call__(self, nano_contract_id: bytes) -> NCBaseStorage:
        """Return a storage object for a given nano contract."""
        raise NotImplementedError
