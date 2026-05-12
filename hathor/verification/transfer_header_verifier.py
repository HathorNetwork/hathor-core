#  Copyright 2026 Hathor Labs
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
from hathor.nanocontracts.exception import NCInsufficientFunds, NCInvalidSeqnum, NCInvalidSignature
from hathor.nanocontracts.types import Address, TokenUid as NCTokenUid
from hathor.transaction import Transaction
from hathor.transaction.exceptions import InvalidToken, ScriptError, TooManyInputs, TooManyOutputs, TooManySigOps
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts import SigopCounter, create_output_script
from hathor.transaction.scripts.execute import ScriptExtras, raw_script_eval
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.transaction.storage import TransactionStorage
from hathor.verification.nano_header_verifier import MAX_SEQNUM_DIFF_MEMPOOL
from hathor.verification.verification_params import VerificationParams

MAX_ADDRESSES: int = 16
MAX_INPUTS: int = 16
MAX_OUTPUTS: int = 16
MAX_SCRIPT_SIZE: int = 1024
MAX_SCRIPT_SIGOPS_COUNT: int = 20


class TransferHeaderVerifier:
    __slots__ = ('_settings', '_tx_storage')

    def __init__(self, *, settings: HathorSettings, tx_storage: TransactionStorage) -> None:
        self._settings = settings
        self._tx_storage = tx_storage

    def verify_inputs_and_outputs(self, tx: Transaction) -> None:
        if tx.is_nano_contract():
            raise InvalidToken('transfer headers are not yet supported on nano transactions')

        transfer_header = tx.get_transfer_header()
        if len(transfer_header.addresses) > MAX_ADDRESSES:
            raise TooManyInputs

        if len(transfer_header.inputs) > MAX_INPUTS:
            raise TooManyInputs

        if len(transfer_header.outputs) > MAX_OUTPUTS:
            raise TooManyOutputs

        input_usage_counts = [0] * len(transfer_header.addresses)
        seen_inputs: set[tuple[Address, NCTokenUid]] = set()
        seen_outputs: set[tuple[Address, NCTokenUid]] = set()

        for input_address in transfer_header.addresses:
            self._verify_signature(tx, input_address.address, input_address.script)

        for input_ in transfer_header.inputs:
            if input_.amount <= 0:
                raise InvalidToken('transfer input amount must be positive')
            if input_.address_index >= len(transfer_header.addresses):
                raise InvalidToken(f'address index not available: index {input_.address_index}')
            if input_.token_index > len(tx.tokens):
                raise InvalidToken(f'token uid index not available: index {input_.token_index}')

            input_usage_counts[input_.address_index] += 1
            input_address = transfer_header.addresses[input_.address_index]
            entry = (Address(input_address.address), NCTokenUid(tx.get_token_uid(input_.token_index)))
            if entry in seen_inputs:
                raise InvalidToken('only one transfer input is allowed for each address/token')
            seen_inputs.add(entry)

        for output_ in transfer_header.outputs:
            if output_.amount <= 0:
                raise InvalidToken('transfer output amount must be positive')
            if output_.token_index > len(tx.tokens):
                raise InvalidToken(f'token uid index not available: index {output_.token_index}')
            self._verify_regular_address(output_.address)
            entry = (Address(output_.address), NCTokenUid(tx.get_token_uid(output_.token_index)))
            if entry in seen_outputs:
                raise InvalidToken('only one transfer output is allowed for each address/token')
            if entry in seen_inputs:
                raise InvalidToken('the same address/token cannot appear on both sides of a transfer header')
            seen_outputs.add(entry)

        if any(usage_count == 0 for usage_count in input_usage_counts):
            raise InvalidToken('every transfer address must be referenced by at least one input')

    def _verify_regular_address(self, address: bytes) -> None:
        if len(address) != ADDRESS_LEN_BYTES:
            raise NCInvalidSignature(f'invalid address: {address.hex()}')

    def _verify_signature(self, tx: Transaction, address: bytes, script: bytes) -> None:
        """Verify if the caller's signature is valid."""
        self._verify_regular_address(address)

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
                extras=ScriptExtras(tx=tx, version=OpcodesVersion.V2)
            )
        except ScriptError as e:
            raise NCInvalidSignature from e

    def verify_balances(self, tx: Transaction, params: VerificationParams) -> None:
        if not params.harden_nano_restrictions:
            return

        transfer_header = tx.get_transfer_header()
        best_block = self._tx_storage.get_best_block()
        block_storage = self._tx_storage.get_nc_block_storage(best_block)

        for txin in transfer_header.inputs:
            input_address = transfer_header.addresses[txin.address_index]
            current_seqnum = block_storage.get_address_seqnum(Address(input_address.address))
            diff = input_address.seqnum - current_seqnum
            if diff < 0 or diff > MAX_SEQNUM_DIFF_MEMPOOL:
                raise NCInvalidSeqnum(f'invalid transfer-header seqnum (diff={diff})')

            token_uid = NCTokenUid(tx.get_token_uid(txin.token_index))
            balance = block_storage.get_address_balance(Address(input_address.address), token_uid)
            if txin.amount > balance:
                raise NCInsufficientFunds
