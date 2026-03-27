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

# Re-export from hathorlib for backward compatibility
from hathor.transaction import Transaction
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.runner.runner import (  # noqa: F401
    MAX_SEQNUM_JUMP_SIZE,
    Runner,
    RunnerFactory,
    _forbid_syscall_from_view,
)
from hathorlib.nanocontracts.types import Address, BlueprintId, ContractId, NCRawArgs, VertexId


def execute_from_tx(runner: Runner, tx: Transaction) -> None:
    """Execute the contract's method call. Requires hathor-core Transaction."""
    assert isinstance(tx, Transaction)

    # Check seqnum.
    nano_header = tx.get_nano_header()

    if nano_header.is_creating_a_new_contract():
        contract_id = ContractId(VertexId(tx.hash))
    else:
        contract_id = ContractId(VertexId(nano_header.nc_id))

    assert nano_header.nc_seqnum >= 0
    current_seqnum = runner.block_storage.get_address_seqnum(Address(nano_header.nc_address))
    diff = nano_header.nc_seqnum - current_seqnum
    if diff <= 0 or diff > MAX_SEQNUM_JUMP_SIZE:
        # Fail execution if seqnum is invalid.
        runner._last_call_info = runner._build_call_info(contract_id)
        # TODO: Set the seqnum in this case?
        raise NCFail(f'invalid seqnum (diff={diff})')
    runner.block_storage.set_address_seqnum(Address(nano_header.nc_address), nano_header.nc_seqnum)

    vertex_metadata = tx.get_metadata()
    assert vertex_metadata.first_block is not None, 'execute must only be called after first_block is updated'

    context = nano_header.get_context()
    assert context.block.hash == vertex_metadata.first_block

    nc_args = NCRawArgs(nano_header.nc_args_bytes)
    if nano_header.is_creating_a_new_contract():
        blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
        runner.create_contract_with_nc_args(contract_id, blueprint_id, context, nc_args)
    else:
        runner.call_public_method_with_nc_args(contract_id, nano_header.nc_method, context, nc_args)
