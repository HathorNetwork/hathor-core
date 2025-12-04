import json
from typing import Any, Iterator

from twisted.internet.testing import StringTransport

from hathor.wallet import HDWallet
from hathor.websocket.factory import HathorAdminWebsocketFactory
from hathor.websocket.iterators import AddressItem, ManualAddressSequencer, gap_limit_search
from hathor.websocket.streamer import HistoryStreamer, StreamerState
from hathor_tests.unittest import TestCase
from hathor_tests.utils import GENESIS_ADDRESS_B58


class AsyncIteratorsTestCase(TestCase):
    WS_PROTOCOL_MESSAGE_SEPARATOR = b'\x81'

    def test_streamer(self) -> None:
        manager = self.create_peer('mainnet', wallet_index=True)
        settings = manager._settings

        # Settings.
        stream_id = 'A001'
        gap_limit = 8

        # Get genesis information.
        genesis = manager.tx_storage.get_genesis(settings.GENESIS_BLOCK_HASH)
        genesis_address = GENESIS_ADDRESS_B58

        # Create wallet.
        wallet = HDWallet()
        wallet.unlock(manager.tx_storage)

        # Create list of addresses.
        addresses: list[AddressItem] = [AddressItem(0, genesis_address)]
        for idx in range(1, 30):
            addresses.append(AddressItem(idx, wallet.get_address(wallet.get_key_at_index(idx))))

        # Create the expected result.
        expected_result: list[dict[str, Any]] = [{
            'type': 'stream:history:begin',
            'id': stream_id,
            'window_size': None,
        }]
        expected_result += [
            {
                'type': 'stream:history:address',
                'id': stream_id,
                'index': item.index,
                'address': item.address,
                'subscribed': True
            }
            for item in addresses[:gap_limit + 1]
        ]
        expected_result.insert(2, {
            'type': 'stream:history:vertex',
            'id': stream_id,
            'data': genesis.to_json_extended(),
        })
        expected_result.append({'type': 'stream:history:end', 'id': stream_id})
        for index, item in enumerate(expected_result):
            item['seq'] = index

        # Create both the address iterator and the GAP limit searcher.
        address_iter = ManualAddressSequencer()
        address_iter.add_addresses(addresses, last=True)
        search = gap_limit_search(manager, address_iter, gap_limit=gap_limit)

        # Create the websocket factory and protocol.
        factory = HathorAdminWebsocketFactory(manager)
        factory.openHandshakeTimeout = 0
        protocol = factory.buildProtocol(None)

        # Create the transport and create a fake connection.
        transport = StringTransport()
        protocol.makeConnection(transport)
        factory.connections.add(protocol)
        protocol.state = protocol.STATE_OPEN

        # Create the history streamer.
        streamer = HistoryStreamer(protocol=protocol, stream_id=stream_id, search=search)
        streamer.start()

        # Run the streamer.
        manager.reactor.advance(10)

        # Check the streamer is waiting for the last ACK.
        self.assertTrue(streamer._state, StreamerState.CLOSING)
        streamer.set_ack(1)
        self.assertTrue(streamer._state, StreamerState.CLOSING)
        streamer.set_ack(len(expected_result) - 1)
        self.assertTrue(streamer._state, StreamerState.CLOSED)

        # Check the results.
        items_iter = self._parse_ws_raw(transport.value())
        result = list(items_iter)
        self.assertEqual(result, expected_result)

    def _parse_ws_raw(self, content: bytes) -> Iterator[dict]:
        raw_messages = content.split(self.WS_PROTOCOL_MESSAGE_SEPARATOR)
        for x in raw_messages:
            if not x:
                continue
            if x[-1:] != b'}':
                continue
            idx = x.find(b'{')
            if idx == -1:
                continue
            json_raw = x[idx:]
            yield json.loads(json_raw)
