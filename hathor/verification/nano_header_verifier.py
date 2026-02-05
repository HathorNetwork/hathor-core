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

from collections import defaultdict
from typing import Sequence

from hathor.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathor.nanocontracts.exception import (
    NanoContractDoesNotExist,
    NCFail,
    NCForbiddenAction,
    NCInvalidAction,
    NCInvalidMethodCall,
    NCInvalidSeqnum,
    NCInvalidSignature,
    NCMethodNotFound,
    NCTxValidationError,
)
from hathor.nanocontracts.method import Method
from hathor.nanocontracts.runner.runner import MAX_SEQNUM_JUMP_SIZE
from hathor.nanocontracts.types import (
    NC_ALLOWED_ACTIONS_ATTR,
    NC_FALLBACK_METHOD,
    Address,
    BaseAuthorityAction,
    BlueprintId,
    ContractId,
    NCAction,
    NCActionType,
    TokenUid,
)
from hathor.nanocontracts.utils import is_nc_public_method
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import ScriptError, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import SigopCounter, create_output_script
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval
from hathor.transaction.storage import TransactionStorage
from hathor.verification.verification_params import VerificationParams

MAX_SEQNUM_DIFF_MEMPOOL = MAX_SEQNUM_JUMP_SIZE + 30

MAX_NC_SCRIPT_SIZE: int = 1024
MAX_NC_SCRIPT_SIGOPS_COUNT: int = 20
MAX_ACTIONS_LEN: int = 16
ALLOWED_ACTION_SETS: frozenset[frozenset[NCActionType]] = frozenset([
    frozenset(),
    frozenset([NCActionType.DEPOSIT]),
    frozenset([NCActionType.WITHDRAWAL]),
    frozenset([NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.ACQUIRE_AUTHORITY]),
    frozenset([NCActionType.DEPOSIT, NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.DEPOSIT, NCActionType.ACQUIRE_AUTHORITY]),
    frozenset([NCActionType.WITHDRAWAL, NCActionType.GRANT_AUTHORITY]),
    frozenset([NCActionType.WITHDRAWAL, NCActionType.ACQUIRE_AUTHORITY]),
])


class NanoHeaderVerifier:
    __slots__ = ('_settings', '_tx_storage')

    def __init__(self, *, settings: HathorSettings, tx_storage: TransactionStorage) -> None:
        self._settings = settings
        self._tx_storage = tx_storage

    def verify_nc_signature(self, tx: BaseTransaction, params: VerificationParams) -> None:
        """Verify if the caller's signature is valid."""
        self._verify_nc_signature(self._settings, tx, params)

    @staticmethod
    def _verify_nc_signature(settings: HathorSettings, tx: BaseTransaction, params: VerificationParams) -> None:
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        if len(nano_header.nc_address) != ADDRESS_LEN_BYTES:
            raise NCInvalidSignature(f'invalid address: {nano_header.nc_address.hex()}')

        if len(nano_header.nc_script) > MAX_NC_SCRIPT_SIZE:
            raise NCInvalidSignature(
                f'nc_script larger than max: {len(nano_header.nc_script)} > {MAX_NC_SCRIPT_SIZE}'
            )

        counter = SigopCounter(
            max_multisig_pubkeys=settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=True,
        )
        output_script = create_output_script(nano_header.nc_address)
        sigops_count = counter.get_sigops_count(nano_header.nc_script, output_script)
        if sigops_count > MAX_NC_SCRIPT_SIGOPS_COUNT:
            raise TooManySigOps(f'sigops count greater than max: {sigops_count} > {MAX_NC_SCRIPT_SIGOPS_COUNT}')

        try:
            raw_script_eval(
                input_data=nano_header.nc_script,
                output_script=output_script,
                extras=ScriptExtras(tx=tx, version=params.features.opcodes_version)
            )
        except ScriptError as e:
            raise NCInvalidSignature from e

    @staticmethod
    def verify_actions(tx: BaseTransaction) -> None:
        """Verify nc_actions."""
        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        tx_tokens_set = set(tx.tokens)
        nano_header = tx.get_nano_header()
        actions = nano_header.get_actions()
        NanoHeaderVerifier.verify_action_list(actions)

        for action in actions:
            if isinstance(action, BaseAuthorityAction):
                # This is verified in model creation, so we just assert here.
                assert action.token_uid != HATHOR_TOKEN_UID

            if action.token_uid != HATHOR_TOKEN_UID and action.token_uid not in tx_tokens_set:
                raise NCInvalidAction(
                    f'{action.name} action requires token {action.token_uid.hex()} in tokens list'
                )

    @staticmethod
    def verify_action_list(actions: Sequence[NCAction]) -> None:
        """Perform NCAction verifications that do not depend on the tx."""
        if len(actions) > MAX_ACTIONS_LEN:
            raise NCInvalidAction(f'more actions than the max allowed: {len(actions)} > {MAX_ACTIONS_LEN}')

        actions_map: defaultdict[TokenUid, list[NCAction]] = defaultdict(list)
        for action in actions:
            actions_map[action.token_uid].append(action)

        for token_uid, actions_per_token in actions_map.items():
            action_types = {action.type for action in actions_per_token}
            if action_types not in ALLOWED_ACTION_SETS:
                raise NCInvalidAction(f'conflicting actions for token {token_uid.hex()}')

    def verify_method_call(self, tx: BaseTransaction, params: VerificationParams) -> None:
        if not params.harden_nano_restrictions:
            return

        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        blueprint_id: BlueprintId
        nano_header = tx.get_nano_header()
        if nano_header.is_creating_a_new_contract():
            # creating a new contract
            blueprint_id = BlueprintId(nano_header.nc_id)
            allow_fallback = False
        else:
            # contract already exists
            best_block = self._tx_storage.get_best_block()
            block_storage = self._tx_storage.get_nc_block_storage(best_block)
            try:
                contract_storage = block_storage.get_contract_storage(ContractId(nano_header.nc_id))
            except NanoContractDoesNotExist as e:
                raise NCTxValidationError from e
            blueprint_id = contract_storage.get_blueprint_id()
            allow_fallback = True

        try:
            blueprint_class, _ = self._tx_storage.get_blueprint_class(blueprint_id)
        except NCFail as e:
            raise NCTxValidationError from e

        method_name = nano_header.nc_method
        method = getattr(blueprint_class, method_name, None)
        allowed_actions: set[NCActionType]
        if method is None:
            if not allow_fallback:
                raise NCMethodNotFound(f'method `{method_name}` not found and no fallback is allowed')
            method = getattr(blueprint_class, NC_FALLBACK_METHOD, None)
            if method is None:
                raise NCMethodNotFound(f'method `{method_name}` not found and no fallback is provided')
            method_name = 'fallback'
        else:
            if not is_nc_public_method(method):
                raise NCInvalidMethodCall(f'method `{method_name}` is not a public method')
            parser = Method.from_callable(method)
            try:
                parser.deserialize_args_bytes(nano_header.nc_args_bytes)
            except NCFail as e:
                raise NCTxValidationError from e

        allowed_actions = getattr(method, NC_ALLOWED_ACTIONS_ATTR, set())
        assert isinstance(allowed_actions, set)
        for action in nano_header.nc_actions:
            if action.type not in allowed_actions:
                exception = NCForbiddenAction(f'action {action.type} is forbidden on method `{method_name}`')
                raise NCTxValidationError from exception

    def verify_seqnum(self, tx: BaseTransaction, params: VerificationParams) -> None:
        if not params.harden_nano_restrictions:
            return

        assert tx.is_nano_contract()
        assert isinstance(tx, Transaction)

        nano_header = tx.get_nano_header()
        best_block = self._tx_storage.get_best_block()
        block_storage = self._tx_storage.get_nc_block_storage(best_block)
        seqnum = block_storage.get_address_seqnum(Address(nano_header.nc_address))
        diff = nano_header.nc_seqnum - seqnum
        if diff < 0 or diff > MAX_SEQNUM_DIFF_MEMPOOL:
            raise NCInvalidSeqnum(f'invalid seqnum (diff={diff})')
