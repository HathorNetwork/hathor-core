# Copyright 2021 Hathor Labs
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
from typing import Optional

from hathor.transaction.base_transaction import BaseTransaction


class BaseIndex(ABC):
    """ All indexes must inherit from this index.

    This class exists so we can interact with indexes without knowing anything specific to its implemented. It was
    created to generalize how we initialize indexes and keep track of which ones are up-to-date.
    """

    def init_start(self) -> None:
        """ This method will always be called when starting the index manager, regardless of initialization state.

        It comes with a no-op implementation by default because usually indexes will not need this.
        """
        pass

    @abstractmethod
    def get_db_name(self) -> Optional[str]:
        """ The returned string is used to generate the relevant attributes for storing an indexe's state in the db.

        If None is returned, the database will not store the index initialization state and they will always be
        initialized. This is the expected mode that memory-only indexes will use.
        """
        raise NotImplementedError

    @abstractmethod
    def init_loop_step(self, tx: BaseTransaction) -> None:
        """ When the index needs to be initialized, this function will be called for every tx in topological order.
        """
        raise NotImplementedError

    @abstractmethod
    def force_clear(self) -> None:
        """ Clear any existing data in the index.
        """
        raise NotImplementedError
