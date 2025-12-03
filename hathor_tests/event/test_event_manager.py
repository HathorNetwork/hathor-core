from hathor.event.model.event_data import TokenCreatedData
from hathor.event.model.event_type import EventType
from hathor.event.storage import EventRocksDBStorage
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.types import ContractId
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.pubsub import HathorEvents
from hathor.transaction import Transaction
from hathor.transaction.token_info import TokenVersion
from hathor.util import not_none
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.utils import create_tokens


class _TokenFactoryBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def create_token(self, ctx: Context) -> None:
        self.syscall.create_deposit_token(
            token_name='Deposit Token',
            token_symbol='DBT',
            amount=100,
        )


class EventManagerTest(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.network = 'testnet'
        self.event_storage = EventRocksDBStorage(
            rocksdb_storage=self.create_rocksdb_storage(),
        )
        self.manager = self.create_peer(
            self.network,
            enable_event_queue=True,
            event_storage=self.event_storage
        )
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_if_event_is_persisted(self) -> None:
        block = self.manager.tx_storage.get_best_block()
        self.manager.pubsub.publish(HathorEvents.NETWORK_NEW_TX_ACCEPTED, tx=block)
        self.run_to_completion()
        self.assertIsNotNone(self.event_storage.get_event(0))

    def _fake_reorg_started(self) -> None:
        block = self.manager.tx_storage.get_best_block()
        # XXX: since we're faking these events, they don't neet to be consistent
        self.manager.pubsub.publish(HathorEvents.REORG_STARTED, old_best_height=1, old_best_block=block,
                                    new_best_height=1, new_best_block=block, reorg_size=1, common_block=block)

    def _fake_reorg_finished(self) -> None:
        self.manager.pubsub.publish(HathorEvents.REORG_FINISHED)

    def test_event_group(self) -> None:
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()

        event0 = not_none(self.event_storage.get_event(0))
        event1 = not_none(self.event_storage.get_event(1))
        event2 = not_none(self.event_storage.get_event(2))
        event3 = not_none(self.event_storage.get_event(3))
        event4 = not_none(self.event_storage.get_event(4))
        event5 = not_none(self.event_storage.get_event(5))
        event6 = not_none(self.event_storage.get_event(6))
        event7 = not_none(self.event_storage.get_event(7))
        event8 = not_none(self.event_storage.get_event(8))

        self.assertEqual(EventType(event0.type), EventType.LOAD_STARTED)
        self.assertEqual(EventType(event1.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event2.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event3.type), EventType.NEW_VERTEX_ACCEPTED)
        self.assertEqual(EventType(event4.type), EventType.LOAD_FINISHED)
        self.assertEqual(EventType(event5.type), EventType.REORG_STARTED)

        self.assertIsNotNone(event5.group_id)
        self.assertEqual(EventType(event6.type), EventType.REORG_FINISHED)
        self.assertIsNotNone(event6.group_id)
        self.assertEqual(event5.group_id, event6.group_id)

        self.assertNotEqual(event6.group_id, event7.group_id)
        self.assertIsNotNone(event7.group_id)
        self.assertEqual(event7.group_id, event8.group_id)

    def test_cannot_start_group_twice(self) -> None:
        self._fake_reorg_started()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_started()
            self.run_to_completion()

    def test_cannot_finish_group_that_was_not_started(self) -> None:
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()

    def test_cannot_finish_group_twice(self) -> None:
        self._fake_reorg_started()
        self._fake_reorg_finished()
        self.run_to_completion()
        with self.assertRaises(AssertionError):
            self._fake_reorg_finished()
            self.run_to_completion()

    def test_nc_token_creation_event(self) -> None:
        blueprint_id = b'\x01' * 32
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            blueprint_id: _TokenFactoryBlueprint,
        })

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..15]
            b12 < dummy

            init.nc_id = "{blueprint_id.hex()}"
            init.nc_method = initialize()
            init.nc_deposit = 1 HTR

            call.nc_id = init
            call.nc_method = create_token()
            call.nc_deposit = 3 HTR

            init < b13 < call < b14
            init <-- b13
            call <-- b14
        ''')

        init_tx, call_tx = artifacts.get_typed_vertices(('init', 'call'), Transaction)

        # stop right after `call` is accepted
        artifacts.propagate_with(self.manager, up_to='call')
        self.run_to_completion()

        # the NEW_VERTEX_ACCEPTED must have been emitted
        tx_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.NEW_VERTEX_ACCEPTED
            and getattr(event.data, 'hash', None) == call_tx.hash_hex
        ]

        self.assertEqual(len(tx_events), 1)

        expected_token_uid = derive_child_token_id(
            ContractId(init_tx.hash),
            token_symbol='DBT',
        ).hex()

        # but the TOKEN_CREATED must have not
        token_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.TOKEN_CREATED
            and getattr(event.data, 'token_uid', None) == expected_token_uid
        ]

        self.assertEqual(len(token_events), 0)

        # only after the block is accepted it will emit the TOKEN_CREATED
        artifacts.propagate_with(self.manager)
        self.run_to_completion()

        token_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.TOKEN_CREATED
            and getattr(event.data, 'token_uid', None) == expected_token_uid
        ]

        self.assertEqual(len(token_events), 1)

        token_event = token_events[0]
        token_data = token_event.data
        assert isinstance(token_data, TokenCreatedData)

        self.assertEqual(token_data.token_uid, expected_token_uid)
        self.assertEqual(token_data.token_name, 'Deposit Token')
        self.assertEqual(token_data.token_symbol, 'DBT')
        self.assertEqual(token_data.token_version, TokenVersion.DEPOSIT)

        nc_exec_info = not_none(token_data.nc_exec_info)
        self.assertEqual(nc_exec_info.nc_tx, call_tx.hash_hex)
        call_meta = call_tx.get_metadata()
        assert call_meta.first_block is not None
        self.assertEqual(nc_exec_info.nc_block, call_meta.first_block.hex())

    def test_nc_token_creation_event_not_emitted_twice(self) -> None:
        blueprint_id = b'\x01' * 32
        self.manager.tx_storage.nc_catalog = NCBlueprintCatalog({
            blueprint_id: _TokenFactoryBlueprint,
        })

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..15]
            b12 < dummy

            init.nc_id = "{blueprint_id.hex()}"
            init.nc_method = initialize()
            init.nc_deposit = 1 HTR

            call.nc_id = init
            call.nc_method = create_token()
            call.nc_deposit = 3 HTR

            init < b13 < call < b14
            init <-- b13
            call <-- b14
        ''')

        init_tx, call_tx = artifacts.get_typed_vertices(('init', 'call'), Transaction)

        artifacts.propagate_with(self.manager)
        self.run_to_completion()

        expected_token_uid = derive_child_token_id(
            ContractId(init_tx.hash),
            token_symbol='DBT',
        ).hex()

        token_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.TOKEN_CREATED
            and getattr(event.data, 'token_uid', None) == expected_token_uid
        ]

        self.assertEqual(len(token_events), 1)

        self.manager.pubsub.publish(HathorEvents.CONSENSUS_TX_UPDATE, tx=call_tx)
        self.run_to_completion()

        token_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.TOKEN_CREATED
            and getattr(event.data, 'token_uid', None) == expected_token_uid
        ]

        self.assertEqual(
            len(token_events),
            1,
            'Token creation event should not be emitted more than once for the same transaction.',
        )

    def test_token_creation_transaction_emits_token_created_event(self) -> None:
        tx = create_tokens(
            self.manager,
            token_name='Created Token',
            token_symbol='CTK',
            mint_amount=123,
            propagate=True,
            use_genesis=False,
        )

        self.run_to_completion()

        expected_token_uid = tx.hash_hex

        token_events = [
            event
            for event in self.event_storage.iter_from_event(0)
            if EventType(event.type) == EventType.TOKEN_CREATED
            and getattr(event.data, 'token_uid', None) == expected_token_uid
        ]

        self.assertEqual(len(token_events), 1)

        token_event = token_events[0]
        token_data = token_event.data
        assert isinstance(token_data, TokenCreatedData)

        self.assertEqual(token_data.token_uid, expected_token_uid)
        self.assertIsNone(token_data.nc_exec_info)
        self.assertEqual(token_data.token_name, 'Created Token')
        self.assertEqual(token_data.token_symbol, 'CTK')
        self.assertEqual(token_data.token_version, TokenVersion.DEPOSIT)
