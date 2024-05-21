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

from __future__ import annotations

from types import ModuleType
from typing import Callable

from hathor.transaction import Transaction
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.types import VertexId
from hathor.util import not_none


def is_nc_public_method(method: Callable) -> bool:
    """Return True if the method is nc_public."""
    return getattr(method, '_nc_method_type', None) == 'public'


def is_nc_view_method(method: Callable) -> bool:
    """Return True if the method is nc_view."""
    return getattr(method, '_nc_method_type', None) == 'view'


def get_nano_contract_creation(tx_storage: TransactionStorage,
                               tx_id: VertexId,
                               *,
                               allow_mempool: bool = False,
                               allow_voided: bool = False) -> Transaction:
    """Return a NanoContract creation vertex. Raise NCContractCreationNotFound otherwise."""
    from hathor.nanocontracts.exception import (
        NCContractCreationAtMempool,
        NCContractCreationNotFound,
        NCContractCreationVoided,
    )
    from hathor.transaction.headers import NC_INITIALIZE_METHOD

    try:
        nc = tx_storage.get_transaction(tx_id)
    except TransactionDoesNotExist as e:
        raise NCContractCreationNotFound from e

    if not nc.is_nano_contract():
        raise NCContractCreationNotFound(f'not a nano contract tx: {tx_id.hex()}')

    assert isinstance(nc, Transaction)
    nano_header = nc.get_nano_header()

    if nano_header.nc_method != NC_INITIALIZE_METHOD:
        raise NCContractCreationNotFound(f'not a contract creation tx: {tx_id.hex()}')

    if not allow_mempool:
        meta = nc.get_metadata()
        if meta.first_block is None:
            raise NCContractCreationAtMempool('nano contract creation is at the mempool: {tx_id.hex()}')

    if not allow_voided:
        meta = nc.get_metadata()
        if meta.voided_by:
            raise NCContractCreationVoided('nano contract creation is voided: {tx_id.hex()}')

    return nc


def load_builtin_blueprint_for_ocb(filename: str, blueprint_name: str, module: ModuleType | None = None) -> str:
    """Get blueprint code from a file."""
    import io
    import os

    from hathor.nanocontracts import blueprints

    module = module or blueprints
    cur_dir = os.path.dirname(not_none(module.__file__))
    filepath = os.path.join(not_none(cur_dir), filename)
    code_text = io.StringIO()
    with open(filepath, 'r') as nc_file:
        for line in nc_file.readlines():
            code_text.write(line)
    code_text.write(f'__blueprint__ = {blueprint_name}\n')
    res = code_text.getvalue()
    code_text.close()
    return res
