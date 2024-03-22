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

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_public_key_from_bytes_compressed
from hathor.nanocontracts import NanoContract
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NanoContractDoesNotExist,
    NCInvalidPubKey,
    NCInvalidSignature,
    NCMethodNotFound,
    NCSerializationError,
)
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.nanocontract import NC_INITIALIZE_METHOD
from hathor.transaction.exceptions import TokenAuthorityNotAllowed
from hathor.transaction.storage.exceptions import TransactionDoesNotExist


class NanoContractVerifier:
    __slots__ = ()

    def verify_no_authorities(self, tx: NanoContract) -> None:
        """Verify that it has not token authority."""
        for i, txout in enumerate(tx.outputs):
            if txout.is_token_authority():
                raise TokenAuthorityNotAllowed(f'output {i} is a token authority')

        for i, txin in enumerate(tx.inputs):
            spent_tx = tx.get_spent_tx(txin)
            txout = spent_tx.outputs[txin.index]
            if txout.is_token_authority():
                raise TokenAuthorityNotAllowed(f'input {i} is a token authority')

    def verify_nc_id(self, tx: NanoContract) -> None:
        """Verify that nc_id is valid."""
        assert tx.storage is not None
        assert tx.storage.nc_catalog is not None
        if tx.nc_method == NC_INITIALIZE_METHOD:
            blueprint_class = tx.storage.nc_catalog.get_blueprint_class(tx.nc_id)
            if not issubclass(blueprint_class, Blueprint):
                raise NanoContractDoesNotExist
        else:
            # Load transaction.
            try:
                nc = tx.storage.get_transaction(tx.nc_id)
            except TransactionDoesNotExist as e:
                raise NanoContractDoesNotExist from e

            # Check the transaction is a Nano Contract.
            if not isinstance(nc, NanoContract):
                raise NanoContractDoesNotExist
            if nc.nc_method != NC_INITIALIZE_METHOD:
                raise NanoContractDoesNotExist

    def verify_nc_signature(self, tx: NanoContract) -> None:
        """Verify if the caller's signature is valid."""
        data = tx.get_sighash_all_data()

        try:
            pubkey = get_public_key_from_bytes_compressed(tx.nc_pubkey)
        except ValueError as e:
            # pubkey is not compressed public key
            raise NCInvalidPubKey('nc_pubkey is not a public key') from e

        try:
            pubkey.verify(tx.nc_signature, data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise NCInvalidSignature from e

    def verify_nc_method_and_args(self, tx: NanoContract) -> None:
        """Verify if the method to be called and its arguments are valid."""
        blueprint_class = tx.get_blueprint_class()

        # Validate arguments passed to the method.
        method = getattr(blueprint_class, tx.nc_method, None)
        if method is None:
            raise NCMethodNotFound
        parser = NCMethodParser(method)
        try:
            parser.parse_args_bytes(tx.nc_args_bytes)
        except struct.error as e:
            raise NCSerializationError from e
