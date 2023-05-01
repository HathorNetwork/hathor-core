from unittest.mock import Mock

from hathor.conf import HathorSettings
from hathor.event.model.event_type import EventType
from hathor.event.storage import EventMemoryStorage
from hathor.event.websocket import EventWebsocketFactory
from tests import unittest
from tests.utils import add_new_blocks, get_genesis_key, zip_chunkify

settings = HathorSettings()


class BaseEventReorgTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.network = 'testnet'
        self.event_storage = EventMemoryStorage()
        self.manager = self.create_peer(
            self.network,
            event_ws_factory=Mock(spec_set=EventWebsocketFactory),
            full_verification=False,
            event_storage=self.event_storage
        )

        # read genesis keys
        self.genesis_private_key = get_genesis_key()
        self.genesis_public_key = self.genesis_private_key.public_key()

    def test_reorg_events(self):
        assert settings.REWARD_SPEND_MIN_BLOCKS == 10, 'this test was made with this hardcoded value in mind'

        # add some blocks
        blocks = add_new_blocks(self.manager, settings.REWARD_SPEND_MIN_BLOCKS, advance_clock=1)

        # make a re-org
        self.log.debug('make reorg block')
        block_to_replace = blocks[8]
        tb0 = self.manager.make_custom_block_template(block_to_replace.parents[0], block_to_replace.parents[1:])
        b0 = tb0.generate_mining_block(self.manager.rng, storage=self.manager.tx_storage)
        b0.weight = 10
        b0.resolve()
        b0.verify()
        self.manager.propagate_tx(b0, fails_silently=False)
        self.log.debug('reorg block propagated')
        self.run_to_completion()

        # check events
        actual_events = list(self.event_storage.iter_from_event(0))

        # events are separated into portions that are sorted (indicated by using lists) and portions that are unsorted
        # (indicated by using a custom class), the unsorted parts mean that the given events must be present, but not
        # necessarily in the given order, to check that we sort both the expected and actual events by tx hash to be
        # able to match them, but only for the "unsorted" portions will, for the "sorted" portions the order is
        # expected to be the given one
        class unsorted(list):
            pass
        expected_events_grouped = [
            [
                (EventType.LOAD_FINISHED, {})
            ],
            # XXX: the order of the following events can vary depending on which genesis is spent/confirmed first
            unsorted([
                (EventType.VERTEX_METADATA_CHANGED, {'hash': settings.GENESIS_TX1_HASH.hex()}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': settings.GENESIS_TX2_HASH.hex()}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[0].hash_hex}),
            ]),
            # XXX: these events must always have this order
            [
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[0].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[1].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[1].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[2].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[2].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[3].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[3].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[4].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[4].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[5].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[5].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[6].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[6].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[7].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[7].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[8].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[8].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[9].hash_hex}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': blocks[9].hash_hex}),
                (EventType.REORG_STARTED, {'reorg_size': 2, 'previous_best_block': blocks[9].hash_hex,
                                           'new_best_block': b0.hash_hex}),
            ],
            # XXX: for some reason the metadata update order of these events isn't always the same
            unsorted([
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[8].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': blocks[9].hash_hex}),
                (EventType.VERTEX_METADATA_CHANGED, {'hash': b0.hash_hex}),
            ]),
            # XXX: these events must always have this order
            [
                (EventType.REORG_FINISHED, {}),
                (EventType.NEW_VERTEX_ACCEPTED, {'hash': b0.hash_hex}),
            ],
        ]

        for actual_events, expected_events in zip_chunkify(actual_events, expected_events_grouped):
            if isinstance(expected_events, unsorted):
                actual_events.sort(key=lambda i: i.data.hash)
                expected_events.sort(key=lambda i: i[1].get('hash', ''))

            for actual_event, expected_event in zip(actual_events, expected_events):
                expected_event_type, expected_partial_data = expected_event

                self.assertEqual(EventType(actual_event.type), expected_event_type)

                for expected_data_key, expected_data_value in expected_partial_data.items():
                    self.assertEqual(actual_event.data.dict()[expected_data_key], expected_data_value)


class SyncV1EventReorgTest(unittest.SyncV1Params, BaseEventReorgTest):
    __test__ = True


class SyncV2EventReorgTest(unittest.SyncV1Params, BaseEventReorgTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeEventReorgTest(unittest.SyncBridgeParams, SyncV2EventReorgTest):
    pass
