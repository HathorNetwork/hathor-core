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
from hathor.nanocontracts.exception import NCInvalidAction, NCInvalidSignature
from hathor.nanocontracts.types import BaseAuthorityAction, NCAction, NCActionType, TokenUid
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import ScriptError, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import SigopCounter, create_output_script
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval

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
    __slots__ = ('_settings',)

    def __init__(self, *, settings: HathorSettings) -> None:
        self._settings = settings

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

        counter = SigopCounter(
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
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
                extras=ScriptExtras(tx=tx)
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
