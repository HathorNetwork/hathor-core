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

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.exception import NCInsufficientFunds, NCInvalidSignature
from hathor.nanocontracts.types import Address, Script
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import InvalidToken, ScriptError, TooManyInputs, TooManyOutputs, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import SigopCounter, create_output_script
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval
from hathor.transaction.storage import TransactionStorage
from hathor.verification.verification_params import VerificationParams

MAX_INPUTS: int = 16
MAX_OUTPUTS: int = 16
MAX_SCRIPT_SIZE: int = 1024
MAX_SCRIPT_SIGOPS_COUNT: int = 20


class TransferHeaderVerifier:
    __slots__ = ('_settings', '_tx_storage')

    def __init__(self, *, settings: HathorSettings, tx_storage: TransactionStorage) -> None:
        self._settings = settings
        self._tx_storage = tx_storage

    def verify_inputs_and_outputs(self, tx: BaseTransaction) -> None:
        transfer_header = tx.get_transfer_header()
        if len(transfer_header.inputs) > MAX_INPUTS:
            raise TooManyInputs

        if len(transfer_header.outputs) > MAX_OUTPUTS:
            raise TooManyOutputs

        seen: set[tuple[Address, int]] = set()

        for input_ in transfer_header.inputs:
            assert input_.amount > 0
            self._verify_signature(tx, input_.address, input_.script)
            if input_.token_index in seen:
                raise InvalidToken('only one token id is allowed for each address')
            seen.add((input_.address, input_.token_index))

        for output_ in transfer_header.outputs:
            assert output_.amount > 0
            if output_.token_index > len(tx.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output_.token_index))
            if output_.token_index in seen:
                raise InvalidToken('only one token id is allowed for each address')
            seen.add((output_.address, output_.token_index))

    def _verify_signature(self, tx: BaseTransaction, address: Address, script: Script) -> None:
        """Verify if the caller's signature is valid."""
        if len(address) != ADDRESS_LEN_BYTES:
            raise NCInvalidSignature(f'invalid address: {address.hex()}')

        if len(script) > MAX_SCRIPT_SIZE:
            raise NCInvalidSignature(
                f'script larger than max: {len(script)} > {MAX_SCRIPT_SIZE}'
            )

        counter = SigopCounter(
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=True,
        )
        output_script = create_output_script(address)
        sigops_count = counter.get_sigops_count(script, output_script)
        if sigops_count > MAX_SCRIPT_SIGOPS_COUNT:
            raise TooManySigOps(f'sigops count greater than max: {sigops_count} > {MAX_SCRIPT_SIGOPS_COUNT}')

        try:
            raw_script_eval(
                input_data=script,
                output_script=output_script,
                extras=ScriptExtras(tx=tx)
            )
        except ScriptError as e:
            raise NCInvalidSignature from e

    def verify_balances(self, tx: BaseTransaction, params: VerificationParams) -> None:
        if not params.harden_nano_restrictions:
            return

        assert isinstance(tx, Transaction)

        transfer_header = tx.get_transfer_header()
        best_block = self._tx_storage.get_best_block()
        block_storage = self._tx_storage.get_nc_block_storage(best_block)

        for txin in transfer_header.inputs:
            balance = block_storage.get_address_balance(txin.address)
            if txin.amount > balance:
                raise NCInsufficientFunds
