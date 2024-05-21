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

from typing import Callable

from hathor.nanocontracts.exception import NCContractCreationNotFound
from hathor.nanocontracts.nanocontract import NC_INITIALIZE_METHOD, NanoContract
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId


def is_nc_public_method(method: Callable) -> bool:
    """Return True if the method is nc_public."""
    return getattr(method, '_is_nc_public', False)


def get_nano_contract_creation(tx_storage: TransactionStorage, tx_id: VertexId) -> NanoContract:
    """Return a NanoContract creation vertex. Raise NCContractCreationNotFound otherwise."""
    try:
        nc = tx_storage.get_transaction(tx_id)
    except TransactionDoesNotExist as e:
        raise NCContractCreationNotFound from e

    if not isinstance(nc, NanoContract):
        raise NCContractCreationNotFound

    if nc.nc_method != NC_INITIALIZE_METHOD:
        raise NCContractCreationNotFound

    return nc
