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

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NanoContractDoesNotExist,
    NCInvalidAction,
    NCInvalidSignature,
    NCMethodNotFound,
    NCSerializationError,
)
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.types import BaseAuthorityAction, BlueprintId
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import ScriptError, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import create_output_script, get_sigops_count
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval

MAX_NC_SCRIPT_SIZE: int = 1024
MAX_NC_SCRIPT_SIGOPS_COUNT: int = 20
MAX_ACTIONS_LEN: int = 16


class NanoHeaderVerifier:
    __slots__ = ()

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

    @staticmethod
    def verify_actions(tx: BaseTransaction) -> None:
        """Verify nc_actions."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        tx_tokens_set = set(tx.tokens)
        seen_tokens = set()
        nano_header = tx.get_nano_header()
        actions = nano_header.get_actions()

        if len(actions) > MAX_ACTIONS_LEN:
            raise NCInvalidAction(f'more actions than the max allowed: {len(actions)} > {MAX_ACTIONS_LEN}')

        for action in actions:
            if isinstance(action, BaseAuthorityAction):
                # This is verified in model creation, so we just assert here.
                assert action.token_uid != HATHOR_TOKEN_UID

            if action.token_uid in seen_tokens:
                raise NCInvalidAction('two or more actions with the same token uid')

            if action.token_uid != HATHOR_TOKEN_UID and action.token_uid not in tx_tokens_set:
                raise NCInvalidAction(
                    f'{action.name} action requires token {action.token_uid.hex()} in tokens list'
                )

            seen_tokens.add(action.token_uid)
