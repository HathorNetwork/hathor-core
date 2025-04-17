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

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Type

from hathor.crypto.util import get_address_from_public_key_bytes
from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import (
    VerboseCallback,
    bytes_to_output_value,
    int_to_bytes,
    output_value_to_bytes,
    unpack,
    unpack_len,
)
from hathor.types import VertexId

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint
    from hathor.nanocontracts.context import Context
    from hathor.nanocontracts.nanocontract import DeprecatedNanoContract
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.types import BlueprintId, ContractId, NCAction, NCActionType
    from hathor.transaction.base_transaction import BaseTransaction

NC_VERSION = 1
NC_INITIALIZE_METHOD = 'initialize'


@dataclass(slots=True, kw_only=True, frozen=True)
class NanoHeaderAction:
    type: NCActionType
    token_index: int
    amount: int


@dataclass(slots=True, kw_only=True)
class NanoHeader(VertexBaseHeader):
    tx: BaseTransaction

    nc_version: int = NC_VERSION

    # nc_id equals to the blueprint_id when a Nano Contract is being created.
    # nc_id equals to the nanocontract_id when a method is being called.
    nc_id: VertexId

    # Name of the method to be called. When creating a new Nano Contract, it must be equal to 'initialize'.
    nc_method: str

    # Serialized arguments to nc_method.
    nc_args_bytes: bytes

    nc_actions: list[NanoHeaderAction]

    # Pubkey and signature of the transaction owner / caller.
    nc_pubkey: bytes
    nc_signature: bytes

    _blueprint_class: Optional[Type[Blueprint]] = None

    @classmethod
    def _deserialize_action(cls, buf: bytes) -> tuple[NanoHeaderAction, bytes]:
        from hathor.nanocontracts.types import NCActionType
        type_bytes, buf = buf[:1], buf[1:]
        action_type = NCActionType.from_bytes(type_bytes)
        (token_index,), buf = unpack('!B', buf)
        amount, buf = bytes_to_output_value(buf)
        return NanoHeaderAction(
            type=action_type,
            token_index=token_index,
            amount=amount,
        ), buf

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[NanoHeader, bytes]:
        buf = memoryview(buf)

        header_id, buf = buf[:1], buf[1:]
        if verbose:
            verbose('header_id', header_id)
        assert header_id == VertexHeaderId.NANO_HEADER.value
        (nc_version,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_version', nc_version)
        if nc_version != NC_VERSION:
            raise ValueError('unknown nanocontract version: {}'.format(nc_version))

        nc_id, buf = unpack_len(32, buf)
        if verbose:
            verbose('nc_id', nc_id)
        (nc_method_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_method_len', nc_method_len)
        nc_method, buf = unpack_len(nc_method_len, buf)
        if verbose:
            verbose('nc_method', nc_method)
        (nc_args_bytes_len,), buf = unpack('!H', buf)
        if verbose:
            verbose('nc_args_bytes_len', nc_args_bytes_len)
        nc_args_bytes, buf = unpack_len(nc_args_bytes_len, buf)
        if verbose:
            verbose('nc_args_bytes', nc_args_bytes)

        from hathor.nanocontracts.nanocontract import DeprecatedNanoContract
        if isinstance(tx, DeprecatedNanoContract):
            nc_actions = cls._deprecated_get_actions(tx)
        else:
            (nc_actions_len,), buf = unpack('!B', buf)
            if verbose:
                verbose('nc_actions_len', nc_actions_len)
            nc_actions = []
            for _ in range(nc_actions_len):
                action, buf = cls._deserialize_action(buf)
                nc_actions.append(action)

        (nc_pubkey_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_pubkey_len', nc_pubkey_len)
        nc_pubkey, buf = unpack_len(nc_pubkey_len, buf)
        if verbose:
            verbose('nc_pubkey', nc_pubkey)
        (nc_signature_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('nc_signature_len', nc_signature_len)
        nc_signature, buf = unpack_len(nc_signature_len, buf)
        if verbose:
            verbose('nc_signature', nc_signature)

        decoded_nc_method = nc_method.decode('ascii')

        return cls(
            tx=tx,
            nc_version=nc_version,
            nc_id=nc_id,
            nc_method=decoded_nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_actions=nc_actions,
            nc_pubkey=nc_pubkey,
            nc_signature=nc_signature,
        ), bytes(buf)

    def _serialize_action(self, action: NanoHeaderAction) -> bytes:
        ret = [
            action.type.to_bytes(),
            int_to_bytes(action.token_index, 1),
            output_value_to_bytes(action.amount),
        ]
        return b''.join(ret)

    def _serialize_without_header_id(self, *, skip_signature: bool) -> deque[bytes]:
        """Serialize the header with the option to skip the signature."""
        encoded_method = self.nc_method.encode('ascii')

        ret: deque[bytes] = deque()
        ret.append(int_to_bytes(NC_VERSION, 1))
        ret.append(self.nc_id)
        ret.append(int_to_bytes(len(encoded_method), 1))
        ret.append(encoded_method)
        ret.append(int_to_bytes(len(self.nc_args_bytes), 2))
        ret.append(self.nc_args_bytes)

        from hathor.nanocontracts.nanocontract import DeprecatedNanoContract
        if not isinstance(self.tx, DeprecatedNanoContract):
            ret.append(int_to_bytes(len(self.nc_actions), 1))
            for action in self.nc_actions:
                ret.append(self._serialize_action(action))

        ret.append(int_to_bytes(len(self.nc_pubkey), 1))
        ret.append(self.nc_pubkey)
        if not skip_signature:
            ret.append(int_to_bytes(len(self.nc_signature), 1))
            ret.append(self.nc_signature)
        else:
            ret.append(int_to_bytes(0, 1))
        return ret

    def serialize(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=False)
        ret.appendleft(VertexHeaderId.NANO_HEADER.value)
        return b''.join(ret)

    def get_sighash_bytes(self) -> bytes:
        ret = self._serialize_without_header_id(skip_signature=True)
        return b''.join(ret)

    def is_creating_a_new_contract(self) -> bool:
        """Return true if this transaction is creating a new contract."""
        return self.nc_method == NC_INITIALIZE_METHOD

    def get_nanocontract_id(self) -> ContractId:
        """Return the contract id."""
        from hathor.nanocontracts.types import ContractId, VertexId
        if self.nc_method == NC_INITIALIZE_METHOD:
            return ContractId(VertexId(self.tx.hash))
        return ContractId(VertexId(self.nc_id))

    def get_blueprint_id(self) -> BlueprintId:
        """Return the blueprint id."""
        from hathor.nanocontracts.types import blueprint_id_from_bytes
        from hathor.transaction import Transaction

        assert self.tx.storage is not None
        assert self.tx.storage.nc_catalog is not None
        if self.nc_method == NC_INITIALIZE_METHOD:
            return blueprint_id_from_bytes(self.nc_id)
        else:
            nanocontract_id = self.nc_id
            nanocontract = self.tx.storage.get_transaction(nanocontract_id)
            assert isinstance(nanocontract, Transaction)
            nanocontract_nano_header = nanocontract.get_nano_header()
            assert nanocontract.is_nano_contract()
            assert nanocontract_nano_header.nc_method == NC_INITIALIZE_METHOD
            return blueprint_id_from_bytes(nanocontract_nano_header.nc_id)

    def get_blueprint_class(self) -> Type[Blueprint]:
        """Return the blueprint class of the contract."""
        assert self.tx.storage is not None
        if self._blueprint_class is not None:
            return self._blueprint_class
        blueprint_id = self.get_blueprint_id()
        blueprint_class = self.tx.storage.get_blueprint_class(blueprint_id)
        self._blueprint_class = blueprint_class
        return blueprint_class

    def execute(self, runner: Runner) -> None:
        """Execute the contract's method call."""
        from hathor.nanocontracts.method_parser import NCMethodParser

        blueprint_class = self.get_blueprint_class()
        method = getattr(blueprint_class, self.nc_method)
        parser = NCMethodParser(method)
        args = parser.parse_args_bytes(self.nc_args_bytes)

        context = self.get_context()
        runner.call_public_method(self.get_nanocontract_id(), self.nc_method, context, *args)

    def get_actions(self) -> list[NCAction]:
        """Calculate the actions based on the differences between inputs and outputs."""
        from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid

        ret = []
        for action in self.nc_actions:
            token_uid = self.tx.get_token_uid(action.token_index)
            ret.append(NCAction(
                type=NCActionType[action.type.name],
                token_uid=TokenUid(token_uid),
                amount=action.amount,
            ))
        return ret

    @staticmethod
    def _deprecated_get_actions(tx: DeprecatedNanoContract) -> list[NanoHeaderAction]:
        """This is the deprecated way of getting implicit actions, only supported by the DeprecatedNanoContract."""
        from hathor.nanocontracts.types import NCActionType, TokenUid

        diff_by_token: defaultdict[TokenUid, int] = defaultdict(int)

        for txin in tx.inputs:
            assert tx.storage is not None
            spent_tx = tx.storage.get_transaction(txin.tx_id)
            spent_txout = spent_tx.outputs[txin.index]
            token_uid = TokenUid(spent_tx.get_token_uid(spent_txout.get_token_index()))
            diff_by_token[token_uid] += spent_txout.value

        for txout in tx.outputs:
            token_uid = TokenUid(tx.get_token_uid(txout.get_token_index()))
            diff_by_token[token_uid] -= txout.value

        tokens: set[TokenUid] = set(diff_by_token.keys())

        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.transaction.util import get_deposit_amount
        if isinstance(tx, TokenCreationTransaction):
            # This implementation assumes that all missing deposit for minting tokens will be fulfilled by the contract
            # through a withdrawal action.
            new_token_uid = TokenUid(tx.hash)
            htr_token_uid = TokenUid(tx._settings.HATHOR_TOKEN_UID)
            mint_amount = diff_by_token[new_token_uid]
            assert mint_amount < 0
            required_deposit = get_deposit_amount(tx._settings, -mint_amount)
            # Set diff_by_token[] of the newly created token to zero, so no action will be generated for it.
            diff_by_token[new_token_uid] = 0
            # Subtract the required deposit for minting tokens.
            diff_by_token[htr_token_uid] -= required_deposit

        action_list = []
        for token_uid in tokens:
            diff = diff_by_token[token_uid]

            if diff == 0:
                continue
            elif diff < 0:
                action = NCActionType.WITHDRAWAL
                amount = -diff
            else:
                # diff > 0:
                action = NCActionType.DEPOSIT
                amount = diff
            assert amount >= 0
            action_list.append(
                NanoHeaderAction(
                    type=action,
                    token_index=0 if token_uid == tx._settings.HATHOR_TOKEN_UID else tx.tokens.index(token_uid) + 1,
                    amount=amount,
                )
            )

        return action_list

    def get_context(self) -> Context:
        """Return a context to be used in a method call."""
        action_list = self.get_actions()

        meta = self.tx.get_metadata()
        timestamp: int
        if meta.first_block is None:
            # XXX Which timestamp to use when it is on mempool?
            timestamp = self.tx.timestamp
        else:
            assert self.tx.storage is not None
            first_block = self.tx.storage.get_transaction(meta.first_block)
            timestamp = first_block.timestamp

        address = get_address_from_public_key_bytes(self.nc_pubkey)

        from hathor.nanocontracts.context import Context

        context = Context(
            actions=action_list,
            vertex=self.tx,
            address=address,
            timestamp=timestamp,
        )
        return context
