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

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NanoContractDoesNotExist,
    NCInvalidSignature,
    NCMethodNotFound,
    NCSerializationError,
)
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import BlueprintId
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import ScriptError, TokenAuthorityNotAllowed, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import create_output_script, get_sigops_count
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval

MAX_NC_SCRIPT_SIZE: int = 1024
MAX_NC_SCRIPT_SIGOPS_COUNT: int = 20


class NanoHeaderVerifier:
    __slots__ = ()

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

    def _get_blueprint_id_and_class(self, tx: Transaction) -> tuple[BlueprintId, type[Blueprint]]:
        assert tx.storage is not None
        nano_header = tx.get_nano_header()
        blueprint_id = nano_header.get_blueprint_id()
        blueprint_class = tx.storage.get_blueprint_class(blueprint_id)
        if not issubclass(blueprint_class, Blueprint):
            raise NanoContractDoesNotExist
        return blueprint_id, blueprint_class

    def verify_nc_id(self, tx: BaseTransaction) -> None:
        """Verify that nc_id is valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)
        self._get_blueprint_id_and_class(tx)

    def verify_nc_signature(self, tx: BaseTransaction) -> None:
        """Verify if the caller's signature is valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        if len(nano_header.nc_address) != ADDRESS_LEN_BYTES:
            raise NCInvalidSignature(f'invalid address: {nano_header.nc_address.hex()}')

        if len(nano_header.nc_script) > MAX_NC_SCRIPT_SIZE:
            raise NCInvalidSignature(
                f'nc_script larger than max: {len(nano_header.nc_script)} > {MAX_NC_SCRIPT_SIZE}'
            )

        output_script = create_output_script(nano_header.nc_address)
        sigops_count = get_sigops_count(nano_header.nc_script, output_script)
        if sigops_count > MAX_NC_SCRIPT_SIGOPS_COUNT:
            raise TooManySigOps(f'sigops count greater than max: {sigops_count} > {MAX_NC_SCRIPT_SIGOPS_COUNT}')

        try:
            raw_script_eval(
                input_data=nano_header.nc_script,
                output_script=output_script,
                extras=ScriptExtras(tx=tx)
            )
        except ScriptError as e:
            raise NCInvalidSignature from e

    def verify_nc_method_and_args(self, tx: BaseTransaction) -> None:
        """Verify if the method to be called and its arguments are valid."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        _, blueprint_class = self._get_blueprint_id_and_class(tx)

        # Validate arguments passed to the method.
        method = getattr(blueprint_class, nano_header.nc_method, None)
        if method is None:
            raise NCMethodNotFound
        parser = NCMethodParser(method)
        try:
            parser.deserialize_args(nano_header.nc_args_bytes)
        except struct.error as e:
            raise NCSerializationError from e
