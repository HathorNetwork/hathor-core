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

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_public_key_from_bytes_compressed
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NanoContractDoesNotExist,
    NCContractCreationNotFound,
    NCInvalidPubKey,
    NCInvalidSignature,
    NCMethodNotFound,
    NCSerializationError,
)
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import BlueprintId, ContractId, VertexId
from hathor.nanocontracts.utils import get_nano_contract_creation
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import TokenAuthorityNotAllowed

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.transaction.storage import TransactionStorage


class NanoHeaderVerifier:
    __slots__ = ('manager', 'tx_storage')

    manager: HathorManager
    tx_storage: TransactionStorage

    def set_manager(self, manager: HathorManager) -> None:
        self.manager = manager
        self.tx_storage = manager.tx_storage

    def verify_no_authorities(self, tx: BaseTransaction) -> None:
        """Verify that it has not token authority."""
        assert tx.is_nano_contract()

        for i, txout in enumerate(tx.outputs):
            if txout.is_token_authority():
                raise TokenAuthorityNotAllowed(f'output {i} is a token authority')

        for i, txin in enumerate(tx.inputs):
            spent_tx = tx.get_spent_tx(txin)
            txout = spent_tx.outputs[txin.index]
            if txout.is_token_authority():
                raise TokenAuthorityNotAllowed(f'input {i} is a token authority')

    def verify_nc_id(self, tx: BaseTransaction) -> None:
        """Verify that nc_id is valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        assert tx.storage is not None
        assert tx.storage.nc_catalog is not None

        nano_header = tx.get_nano_header()

        if nano_header.is_creating_a_new_contract():
            blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
            blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
            if not issubclass(blueprint_class, Blueprint):
                raise NanoContractDoesNotExist
            return

        try:
            get_nano_contract_creation(
                self.tx_storage,
                VertexId(nano_header.nc_id),
                allow_mempool=True,
                allow_voided=True,
            )
        except NCContractCreationNotFound:
            pass
        else:
            return

        runner = self.manager.get_best_block_nc_runner()
        contract_id = ContractId(VertexId(nano_header.nc_id))
        if not runner.has_contract_been_initialized(contract_id):
            raise NanoContractDoesNotExist

    def verify_nc_signature(self, tx: BaseTransaction) -> None:
        """Verify if the caller's signature is valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        try:
            pubkey = get_public_key_from_bytes_compressed(nano_header.nc_pubkey)
        except ValueError as e:
            # pubkey is not compressed public key
            raise NCInvalidPubKey('nc_pubkey is not a public key') from e

        data = tx.get_sighash_all_data()
        try:
            pubkey.verify(nano_header.nc_signature, data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise NCInvalidSignature from e

    def verify_nc_method_and_args(self, tx: BaseTransaction) -> None:
        """Verify if the method to be called and its arguments are valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        if nano_header.is_creating_a_new_contract():
            blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
            blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
            if not issubclass(blueprint_class, Blueprint):
                raise NanoContractDoesNotExist
        else:
            runner = self.manager.get_best_block_nc_runner()
            contract_id = ContractId(VertexId(nano_header.nc_id))
            if runner.has_contract_been_initialized(contract_id):
                nc_storage = runner.get_storage(contract_id)
                blueprint_id = nc_storage.get_blueprint_id()
                blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
            else:
                try:
                    nc_creation = get_nano_contract_creation(
                        self.tx_storage,
                        VertexId(nano_header.nc_id),
                        allow_mempool=True,
                        allow_voided=True,
                    )
                except NCContractCreationNotFound as e:
                    raise NanoContractDoesNotExist from e

                # must be in the mempool
                if nc_creation.get_metadata().first_block is not None:
                    raise NanoContractDoesNotExist

                blueprint_id = BlueprintId(VertexId(nc_creation.get_nano_header().nc_id))
                blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
                if not issubclass(blueprint_class, Blueprint):
                    raise NanoContractDoesNotExist

        # Validate arguments passed to the method.
        method = getattr(blueprint_class, nano_header.nc_method, None)
        if method is None:
            raise NCMethodNotFound
        parser = NCMethodParser(method)
        try:
            parser.parse_args_bytes(nano_header.nc_args_bytes)
        except struct.error as e:
            raise NCSerializationError from e
