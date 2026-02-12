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

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from typing_extensions import assert_never

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.util import VerboseCallback
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.nanocontracts.context import Context
    from hathor.nanocontracts.types import BlueprintId, ContractId, NCAction, NCActionType, TokenUid
    from hathor.transaction import Transaction
    from hathor.transaction.base_transaction import BaseTransaction
    from hathor.transaction.block import Block

ADDRESS_LEN_BYTES: int = 25
ADDRESS_SEQNUM_SIZE: int = 8  # bytes
_NC_SCRIPT_LEN_MAX_BYTES: int = 2


@dataclass(slots=True, kw_only=True, frozen=True)
class NanoHeaderAction:
    type: NCActionType
    token_index: int
    amount: int

    def to_nc_action(self, tx: Transaction) -> NCAction:
        """Create a NCAction from this NanoHeaderAction"""
        from hathor.nanocontracts.types import (
            NCAcquireAuthorityAction,
            NCActionType,
            NCDepositAction,
            NCGrantAuthorityAction,
            NCWithdrawalAction,
            TokenUid,
        )
        from hathor.transaction.base_transaction import TxOutput

        try:
            token_uid = TokenUid(tx.get_token_uid(self.token_index))
        except IndexError:
            from hathor.nanocontracts.exception import NCInvalidAction
            raise NCInvalidAction(f'{self.type.name} token index {self.token_index} not found')

        match self.type:
            case NCActionType.DEPOSIT:
                return NCDepositAction(token_uid=token_uid, amount=self.amount)
            case NCActionType.WITHDRAWAL:
                return NCWithdrawalAction(token_uid=token_uid, amount=self.amount)
            case NCActionType.GRANT_AUTHORITY:
                mint = self.amount & TxOutput.TOKEN_MINT_MASK > 0
                melt = self.amount & TxOutput.TOKEN_MELT_MASK > 0
                self._validate_authorities(token_uid)
                return NCGrantAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)
            case NCActionType.ACQUIRE_AUTHORITY:
                mint = self.amount & TxOutput.TOKEN_MINT_MASK > 0
                melt = self.amount & TxOutput.TOKEN_MELT_MASK > 0
                self._validate_authorities(token_uid)
                return NCAcquireAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)
            case _:
                assert_never(self.type)

    def _validate_authorities(self, token_uid: TokenUid) -> None:
        """Check that the authorities in the `amount` are valid."""
        from hathor.transaction.base_transaction import TxOutput
        if self.amount > TxOutput.ALL_AUTHORITIES:
            from hathor.nanocontracts.exception import NCInvalidAction
            raise NCInvalidAction(
                f'action {self.type.name} token {token_uid.hex()} invalid authorities: 0b{self.amount:b}'
            )


@dataclass(slots=True, kw_only=True)
class NanoHeader(VertexBaseHeader):
    tx: Transaction

    # Sequence number for the caller.
    nc_seqnum: int

    # nc_id equals to the blueprint_id when a Nano Contract is being created.
    # nc_id equals to the contract_id when a method is being called.
    nc_id: VertexId

    # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
    nc_method: str

    # Serialized arguments to nc_method.
    nc_args_bytes: bytes

    nc_actions: list[NanoHeaderAction]

    # Address and script with signature(s) of the transaction owner(s)/caller(s). Supports P2PKH and P2SH.
    nc_address: bytes
    nc_script: bytes

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[NanoHeader, bytes]:
        from hathor.serialization import Deserializer
        from hathor.transaction.vertex_parser._nano_header import deserialize_nano_header
        deserializer = Deserializer.build_bytes_deserializer(buf)
        header = deserialize_nano_header(deserializer, tx, verbose=verbose)
        return header, bytes(deserializer.read_all())

    def serialize(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
        serializer = Serializer.build_bytes_serializer()
        serialize_nano_header(serializer, self)
        return bytes(serializer.finalize())

    def get_sighash_bytes(self) -> bytes:
        from hathor.serialization import Serializer
        from hathor.transaction.vertex_parser._nano_header import serialize_nano_header
        serializer = Serializer.build_bytes_serializer()
        serialize_nano_header(serializer, self, skip_signature=True)
        return bytes(serializer.finalize())

    def is_creating_a_new_contract(self) -> bool:
        """Return true if this transaction is creating a new contract."""
        from hathor.nanocontracts.types import NC_INITIALIZE_METHOD
        return self.nc_method == NC_INITIALIZE_METHOD

    def get_contract_id(self) -> ContractId:
        """Return the contract id."""
        from hathor.nanocontracts.types import NC_INITIALIZE_METHOD, ContractId, VertexId
        if self.nc_method == NC_INITIALIZE_METHOD:
            return ContractId(VertexId(self.tx.hash))
        return ContractId(VertexId(self.nc_id))

    def get_blueprint_id(self, block: Block | None = None) -> BlueprintId:
        """Return the blueprint id."""
        from hathor.nanocontracts.exception import NanoContractDoesNotExist
        from hathor.nanocontracts.types import BlueprintId, ContractId, VertexId as NCVertexId
        from hathor.transaction import Transaction
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        assert self.tx.storage is not None

        if self.is_creating_a_new_contract():
            blueprint_id = BlueprintId(NCVertexId(self.nc_id))
            return blueprint_id

        if block is None:
            block = self.tx.storage.get_best_block()

        try:
            nc_storage = self.tx.storage.get_nc_storage(block, ContractId(NCVertexId(self.nc_id)))
            blueprint_id = nc_storage.get_blueprint_id()
            return blueprint_id
        except NanoContractDoesNotExist:
            # If the NC storage doesn't exist, the contract must be created by a tx in the mempool
            pass

        try:
            nc_creation = self.tx.storage.get_transaction(self.nc_id)
        except TransactionDoesNotExist as e:
            raise NanoContractDoesNotExist from e

        if not nc_creation.is_nano_contract():
            raise NanoContractDoesNotExist(f'not a nano contract tx: {self.nc_id.hex()}')

        assert isinstance(nc_creation, Transaction)
        nano_header = nc_creation.get_nano_header()

        if not nano_header.is_creating_a_new_contract():
            raise NanoContractDoesNotExist(f'not a contract creation tx: {self.nc_id.hex()}')

        # must be in the mempool
        nc_creation_meta = nc_creation.get_metadata()
        if nc_creation_meta.first_block is not None:
            # otherwise, it failed or skipped execution
            from hathor.transaction.nc_execution_state import NCExecutionState
            assert nc_creation_meta.nc_execution in (NCExecutionState.FAILURE, NCExecutionState.SKIPPED)
            raise NanoContractDoesNotExist(f'contract creation is not executed: {self.nc_id.hex()}')

        blueprint_id = BlueprintId(NCVertexId(nc_creation.get_nano_header().nc_id))
        return blueprint_id

    def get_blueprint_id_for_json(self, block: Block | None = None) -> BlueprintId:
        """
        Return the blueprint id for json use.
        This is equivalent to `get_blueprint_id`, but on error it returns an empty id instead of failing.
        """
        from hathor.nanocontracts.exception import NanoContractDoesNotExist
        from hathor.nanocontracts.types import BlueprintId
        try:
            return self.get_blueprint_id(block)
        except NanoContractDoesNotExist:
            return BlueprintId(b'')

    def get_actions(self) -> list[NCAction]:
        """Get a list of NCActions from the header actions."""
        return [header_action.to_nc_action(self.tx) for header_action in self.nc_actions]

    def get_context(self) -> Context:
        """Return a context to be used in a method call."""
        from hathor.nanocontracts.context import Context
        from hathor.nanocontracts.types import Address
        return Context.create_from_vertex(
            caller_id=Address(self.nc_address),
            vertex=self.tx,
            actions=self.get_actions(),
        )
