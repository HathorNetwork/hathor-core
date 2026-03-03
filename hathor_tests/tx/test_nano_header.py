import pytest

from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts import Blueprint, Context, OnChainBlueprint, public
from hathor.nanocontracts.types import NCActionType
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.exceptions import HeaderNotSupported
from hathor.transaction.headers import NanoHeader, VertexBaseHeader
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES, NanoHeaderAction
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.util import VerboseCallback
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class MyTestBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass


class FakeHeader(VertexBaseHeader):
    @classmethod
    def get_header_id(cls) -> bytes:
        return b'\xff'

    @classmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None,
    ) -> tuple[VertexBaseHeader, bytes]:
        raise NotImplementedError

    def serialize(self) -> bytes:
        return b'fake header'

    def get_sighash_bytes(self) -> bytes:
        return b'fake sighash'


class VertexHeadersTest(unittest.TestCase):
    def has_nano_header(self, vertex: BaseTransaction) -> bool:
        for header in vertex.headers:
            if isinstance(header, NanoHeader):
                return True
        return False

    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = b'x' * 32
        self.manager = self.create_peer('unittests')
        self.manager.tx_storage.nc_catalog.blueprints[self.blueprint_id] = MyTestBlueprint
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()

        self.artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize()

            tx1.out[0] = 5 TKA
            tx2.out[0] = 3 TKB

            b12.nc_id = nc1
            b12.nc_method = nop()

            tx2.nc_id = nc1
            tx2.nc_method = nop()

            TKB.nc_id = nc1
            TKB.nc_method = nop()

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = test_blueprint1.py, TestBlueprint1

            dummy < b11 < nc1 < TKA < tx1 < b12 < TKB < tx2 < ocb1
        ''')
        self.artifacts.propagate_with(self.manager, up_to='dummy')

        self.valid_vertices: list[tuple[str, type[BaseTransaction], bool]] = [
            ('b11', Block, False),
            ('nc1', Transaction, True),
            ('TKA', TokenCreationTransaction, False),
            ('TKB', TokenCreationTransaction, True),
            ('tx1', Transaction, False),
            ('ocb1', OnChainBlueprint, False),
            # TODO: We should also test MergeMinedBlock, but the DAGBuilder doesn't support it yet
        ]

    def test_headers_affect_hash(self) -> None:
        for name, type_, is_nano in self.valid_vertices:
            vertex: BaseTransaction = self.artifacts.get_typed_vertex(name, type_)
            assert self.has_nano_header(vertex) == is_nano

            # Test adding a new header.
            msg = f'changing headers should change the hash on "{name}"'
            clone = vertex.clone(include_storage=False, include_metadata=False)
            assert clone.hash == clone.calculate_hash()
            clone.headers.append(FakeHeader())
            assert clone.hash != clone.calculate_hash(), msg

            # Now we'll test nano header attributes, so we can skip non-nano txs
            if not is_nano:
                continue

            assert isinstance(vertex, Transaction)
            attributes_and_new_values = [
                ('nc_id', b'123'),
                ('nc_seqnum', vertex.get_nano_header().nc_seqnum + 1),
                ('nc_method', 'new_method'),
                ('nc_args_bytes', b'new args'),
                ('nc_actions', [NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=123)]),
                ('nc_address', b'\x01' * ADDRESS_LEN_BYTES),
                ('nc_script', b'new script'),
            ]

            # Test editing existing nano header.
            for attribute, new_value in attributes_and_new_values:
                clone = vertex.clone(include_storage=False, include_metadata=False)
                assert clone.hash == vertex.hash
                assert clone.hash == clone.calculate_hash()
                setattr(clone.get_nano_header(), attribute, new_value)
                assert clone.hash != clone.calculate_hash(), msg

    def test_headers_affect_sighash_all(self) -> None:
        for name, type_, is_nano in self.valid_vertices:
            vertex: BaseTransaction = self.artifacts.get_typed_vertex(name, type_)
            assert self.has_nano_header(vertex) == is_nano

            if not isinstance(vertex, Transaction):
                # only transactions have sighash
                continue

            # Test adding a new header.
            msg = f'changing headers should change the sighash on "{name}"'
            clone = vertex.clone(include_storage=False, include_metadata=False)
            sighash_before = clone.get_sighash_all(skip_cache=True)
            assert sighash_before == vertex.get_sighash_all(skip_cache=True)
            clone.headers.append(FakeHeader())
            sighash_after = clone.get_sighash_all(skip_cache=True)
            assert sighash_before != sighash_after, msg

            # Now we'll test nano header attributes, so we can skip non-nano txs
            if not is_nano:
                continue

            assert isinstance(vertex, Transaction)
            attributes_and_new_values = [
                ('nc_id', b'123'),
                ('nc_seqnum', vertex.get_nano_header().nc_seqnum + 1),
                ('nc_method', 'new_method'),
                ('nc_args_bytes', b'new args'),
                ('nc_actions', [NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=123)]),
                ('nc_address', b'\x01' * ADDRESS_LEN_BYTES),
            ]

            # Test editing existing nano header.
            for attribute, new_value in attributes_and_new_values:
                clone = vertex.clone(include_storage=False, include_metadata=False)
                sighash_before = clone.get_sighash_all(skip_cache=True)
                assert sighash_before == vertex.get_sighash_all(skip_cache=True)
                setattr(clone.get_nano_header(), attribute, new_value)
                sighash_after = clone.get_sighash_all(skip_cache=True)
                assert sighash_before != sighash_after, msg

            # Changing the nc_script does not affect sighash all.
            clone = vertex.clone(include_storage=False, include_metadata=False)
            sighash_before = clone.get_sighash_all(skip_cache=True)
            assert sighash_before == vertex.get_sighash_all(skip_cache=True)
            clone.get_nano_header().nc_script = b'new script'
            sighash_after = clone.get_sighash_all(skip_cache=True)
            assert sighash_before == sighash_after, msg

    def test_nano_header_allowed_vertices(self) -> None:
        for name, _type, should_have_nano_header in self.valid_vertices:
            vertex: BaseTransaction = self.artifacts.get_typed_vertex(name, _type)
            assert self.has_nano_header(vertex) == should_have_nano_header
            vertex.storage = self.manager.tx_storage
            clone = vertex.clone(include_metadata=False, include_storage=True)
            assert bytes(clone) == bytes(vertex)
            assert self.manager.on_new_tx(vertex)

        expected_to_fail: list[tuple[str, type[BaseTransaction], bool]] = [
            ('b12', Block, True),
        ]

        for name, _type, should_have_nano_header in expected_to_fail:
            vertex = self.artifacts.get_typed_vertex(name, _type)
            assert self.has_nano_header(vertex) == should_have_nano_header
            with pytest.raises(InvalidNewTransaction) as e:
                self.manager.on_new_tx(vertex)
            assert isinstance(e.value.__cause__, HeaderNotSupported)

    def test_nano_header_round_trip(self) -> None:
        tx = Transaction()
        header1 = NanoHeader(
            tx=tx,
            nc_id=b'1' * 32,
            nc_seqnum=0,
            nc_method='some_method',
            nc_args_bytes=b'some args',
            nc_actions=[
                NanoHeaderAction(
                    type=NCActionType.DEPOSIT,
                    token_index=0,
                    amount=123,
                ),
            ],
            nc_address=b'\x01' * ADDRESS_LEN_BYTES,
            nc_script=b'some script',
        )

        header1_bytes = header1.serialize()
        header2, buf = NanoHeader.deserialize(tx, header1_bytes)

        assert len(buf) == 0
        assert header1_bytes == header2.serialize()
        assert header1.tx is header2.tx  # allow-is
        assert header1.nc_id == header2.nc_id
        assert header1.nc_method == header2.nc_method
        assert header1.nc_args_bytes == header2.nc_args_bytes
        assert header1.nc_actions == header2.nc_actions
        assert header1.nc_address == header2.nc_address
        assert header1.nc_script == header2.nc_script

    def test_duplicate_headers(self) -> None:
        nc1 = self.artifacts.get_typed_vertex('nc1', Transaction)
        assert len(nc1.headers) == 1
        nano_header = nc1.headers[0]
        assert isinstance(nano_header, NanoHeader)

        nc1.headers.append(nano_header)

        with pytest.raises(Exception) as e:
            self.artifacts.propagate_with(self.manager, up_to='nc1')

        assert isinstance(e.value.__cause__, InvalidNewTransaction)
        assert e.value.__cause__.args[0] == 'full validation failed: only one instance of `NanoHeader` is allowed'
