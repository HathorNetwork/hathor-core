import dataclasses
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import decode_address, get_public_key_bytes_compressed
from hathor.feature_activation.utils import Features
from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor.nanocontracts.types import Address
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import InvalidToken
from hathor.transaction.headers.transfer_header import TransferHeader, TxTransferInput, TxTransferOutput
from hathor.transaction.scripts import MultiSig
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.verification.transfer_header_verifier import TransferHeaderVerifier
from hathor.verification.verification_params import VerificationParams
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script
from hathor_tests import unittest


class TestTransferHeaderVerifier(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')
        self.verifier = TransferHeaderVerifier(
            settings=self.manager._settings,
            tx_storage=self.manager.tx_storage,
        )

    def test_verify_inputs_and_outputs_rejects_duplicate_entries(self) -> None:
        tx = Transaction(storage=self.manager.tx_storage)
        tx.headers.append(TransferHeader(
            tx=tx,
            inputs=[],
            outputs=[
                TxTransferOutput(address=b'\x01' * 25, amount=1, token_index=0),
                TxTransferOutput(address=b'\x01' * 25, amount=1, token_index=0),
            ],
        ))

        with pytest.raises(InvalidToken, match='only one token id is allowed for each address'):
            self.verifier.verify_inputs_and_outputs(tx)

    def test_verify_p2sh_input(self) -> None:
        tx = Transaction(storage=self.manager.tx_storage)
        privkey = ec.generate_private_key(ec.SECP256K1())
        pubkey_bytes = get_public_key_bytes_compressed(privkey.public_key())
        redeem_script = generate_multisig_redeem_script(1, [pubkey_bytes])
        multisig_address = decode_address(generate_multisig_address(redeem_script))
        signature = privkey.sign(tx.get_sighash_all_data(), ec.ECDSA(hashes.SHA256()))
        multisig_input_data = MultiSig.create_input_data(redeem_script=redeem_script, signatures=[signature])

        tx.headers.append(TransferHeader(
            tx=tx,
            inputs=[
                TxTransferInput(
                    address=multisig_address,
                    amount=1,
                    token_index=0,
                    script=multisig_input_data,
                ),
            ],
            outputs=[],
        ))

        # Should accept a valid multisig (P2SH) script for a multisig address.
        self.verifier.verify_inputs_and_outputs(tx)

    def test_verify_balances_rejects_insufficient_funds(self) -> None:
        tx = Transaction(storage=self.manager.tx_storage)
        tx.headers.append(TransferHeader(
            tx=tx,
            inputs=[
                TxTransferInput(
                    address=b'\x01' * 25,
                    amount=1,
                    token_index=0,
                    script=b'',
                ),
            ],
            outputs=[],
        ))
        params = self.get_verification_params(self.manager)

        with pytest.raises(NCInsufficientFunds):
            self.verifier.verify_balances(tx, params)

    def test_verification_service_invokes_transfer_header_verifier(self) -> None:
        best_block = self.manager.tx_storage.get_best_block()
        spent_value = best_block.outputs[0].value
        tx_input = TxInput(best_block.hash, 0, b'')
        address_b58 = self.get_address(0)
        assert address_b58 is not None
        address = decode_address(address_b58)
        output = TxOutput(spent_value - 1, P2PKH.create_output_script(address))
        tx = Transaction(inputs=[tx_input], outputs=[output], storage=self.manager.tx_storage)

        tx.headers.append(TransferHeader(
            tx=tx,
            inputs=[],
            outputs=[
                TxTransferOutput(address=bytes(Address(address)), amount=1, token_index=0),
                TxTransferOutput(address=bytes(Address(address)), amount=1, token_index=0),
            ],
        ))
        tx.update_hash()

        params = VerificationParams.default_for_mempool(best_block=self.manager.tx_storage.get_best_block())
        params = dataclasses.replace(params, features=Features(
            count_checkdatasig_op=True,
            nanocontracts=True,
            fee_tokens=True,
            opcodes_version=OpcodesVersion.V2,
            transfer_headers=True,
        ))

        with patch(
            'hathor.verification.transfer_header_verifier.TransferHeaderVerifier.verify_inputs_and_outputs',
            autospec=True,
        ) as verify_transfer:
            self.manager.verification_service.verify_without_storage(tx, params)
            # Phase 2 expectation: this should be called once transfer validation is wired into verification service.
            assert verify_transfer.called
