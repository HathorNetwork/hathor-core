from hathor.feature_activation.utils import Features
from hathor.transaction import Transaction
from hathor.transaction.headers.transfer_header import TransferHeader, TxTransferInput, TxTransferOutput
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TransferHeaderTest(unittest.TestCase):
    def test_transfer_header_round_trip(self) -> None:
        tx = Transaction()
        tx.tokens = [b't' * 32]

        header = TransferHeader(
            tx=tx,
            inputs=[
                TxTransferInput(
                    address=b'\x01' * 25,
                    amount=10,
                    token_index=0,
                    script=b'\x30' * 65,
                ),
            ],
            outputs=[
                TxTransferOutput(
                    address=b'\x02' * 25,
                    amount=10,
                    token_index=0,
                ),
            ],
        )

        serialized = header.serialize()
        deserialized, remaining = TransferHeader.deserialize(tx, serialized)
        assert remaining == b''
        assert deserialized.inputs == header.inputs
        assert deserialized.outputs == header.outputs
        assert deserialized.get_sighash_bytes() != serialized

    def test_regular_tx_without_transfer_header_keeps_token_info_path(self) -> None:
        manager = self.create_peer('unittests')
        tx = Transaction(storage=manager.tx_storage)
        best_block = manager.tx_storage.get_best_block()
        block_storage = manager.get_nc_block_storage(best_block)

        token_info = tx.get_complete_token_info(block_storage)
        assert tx.has_transfer_header() is False
        assert manager._settings.HATHOR_TOKEN_UID in token_info

    def test_dag_builder_emits_transfer_header_only_when_configured(self) -> None:
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..5]

            tx1.out[0] = 100 HTR
            tx2.out[0] = 100 HTR
            tx2.nc_transfer_input = 10 HTR main
            tx2.nc_transfer_output = 10 HTR main

            b1 < tx1 < tx2 < b2
        ''')

        tx1 = artifacts.get_typed_vertex('tx1', Transaction)
        tx2 = artifacts.get_typed_vertex('tx2', Transaction)
        assert tx1.has_transfer_header() is False
        assert tx2.has_transfer_header() is True

    def test_settings_exposes_transfer_header_flag(self) -> None:
        # Phase 2 expectation: this should exist after transfer-header feature flag is added.
        assert hasattr(self._settings, 'ENABLE_TRANSFER_HEADER')

    def test_features_struct_exposes_transfer_headers_field(self) -> None:
        # Phase 2 expectation: this should exist after transfer-header feature state is added.
        assert 'transfer_headers' in Features.__annotations__
