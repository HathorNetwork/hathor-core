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

import base64
from json import JSONDecodeError
from typing import Any, Iterable
from unittest.mock import Mock

from twisted.internet.testing import StringTransport

from hathor.conf import HathorSettings as get_settings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.mining.ws import MiningWebsocketFactory, MiningWebsocketProtocol
from hathor.p2p.resources import MiningResource
from hathor.transaction.resources import GetBlockTemplateResource
from hathor.transaction.util import unpack, unpack_len
from hathor.util import json_loadb
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.simulation.base import SimulatorTestCase


class MiningSimulationTest(SimulatorTestCase):
    def test_signal_bits_in_mining(self) -> None:
        settings = get_settings().model_copy(update={
            'FEATURE_ACTIVATION': FeatureSettings(
                evaluation_interval=4,
                default_threshold=3,
                features={
                    Feature.NOP_FEATURE_1: Criteria(
                        bit=0,
                        start_height=8,
                        timeout_height=20,
                        version='0.0.0',
                        signal_support_by_default=True
                    ),
                    Feature.NOP_FEATURE_2: Criteria(
                        bit=2,
                        start_height=12,
                        timeout_height=24,
                        version='0.0.0'
                    ),
                }
            )
        })

        builder = self.simulator.get_default_builder() \
            .set_settings(settings) \
            .set_features(support_features={Feature.NOP_FEATURE_2}, not_support_features=set())

        manager = self.simulator.create_peer(builder)
        manager.allow_mining_without_peers()
        miner = self.simulator.create_miner(manager, hashpower=1e12)
        miner.start()

        # There are 3 resources available for miners, and all of them should contain the correct signal_bits
        get_block_template_resource = GetBlockTemplateResource(manager, settings)
        get_block_template_client = StubSite(get_block_template_resource)

        mining_resource = MiningResource(manager)
        mining_client = StubSite(mining_resource)

        ws_factory = MiningWebsocketFactory(manager)
        ws_factory.openHandshakeTimeout = 0
        ws_protocol = ws_factory.buildProtocol(addr=Mock())
        ws_transport = StringTransport()
        ws_protocol.makeConnection(ws_transport)
        ws_protocol.state = MiningWebsocketProtocol.STATE_OPEN
        ws_protocol.onOpen()

        # At the beginning, all features are outside their signaling period, so none are signaled.
        expected_signal_bits = 0b0000
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits
        miner.pause_after_exactly(n_blocks=1)
        self.simulator.run(60)
        assert self._get_signal_bits_from_get_block_template(get_block_template_client) == expected_signal_bits
        assert self._get_signal_bits_from_mining(mining_client) == expected_signal_bits
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        miner.pause_after_exactly(n_blocks=6)
        self.simulator.run(360)
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        # At height=8, NOP_FEATURE_1 is signaling, so it's enabled by the default support.
        expected_signal_bits = 0b0001
        miner.pause_after_exactly(n_blocks=1)
        self.simulator.run(60)
        assert self._get_signal_bits_from_get_block_template(get_block_template_client) == expected_signal_bits
        assert self._get_signal_bits_from_mining(mining_client) == expected_signal_bits
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        miner.pause_after_exactly(n_blocks=3)
        self.simulator.run(180)
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        # At height=12, NOP_FEATURE_2 is signaling, enabled by the user. NOP_FEATURE_1 also continues signaling.
        expected_signal_bits = 0b0101
        miner.pause_after_exactly(n_blocks=1)
        self.simulator.run(60)
        assert self._get_signal_bits_from_get_block_template(get_block_template_client) == expected_signal_bits
        assert self._get_signal_bits_from_mining(mining_client) == expected_signal_bits
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        miner.pause_after_exactly(n_blocks=7)
        self.simulator.run(360)
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        # At height=20, NOP_FEATURE_1 stops signaling, and NOP_FEATURE_2 continues.
        expected_signal_bits = 0b0100
        miner.pause_after_exactly(n_blocks=1)
        self.simulator.run(60)
        assert self._get_signal_bits_from_get_block_template(get_block_template_client) == expected_signal_bits
        assert self._get_signal_bits_from_mining(mining_client) == expected_signal_bits
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        miner.pause_after_exactly(n_blocks=3)
        self.simulator.run(180)
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

        # At height=24, all features have left their signaling period and therefore none are signaled.
        expected_signal_bits = 0b0000
        miner.pause_after_exactly(n_blocks=1)
        self.simulator.run(60)
        assert self._get_signal_bits_from_get_block_template(get_block_template_client) == expected_signal_bits
        assert self._get_signal_bits_from_mining(mining_client) == expected_signal_bits
        assert self._get_last_ws_signal_bits(ws_transport) == expected_signal_bits

    def _get_signal_bits_from_get_block_template(self, web_client: StubSite) -> int:
        result = self._get_result(web_client)
        signal_bits: int = result['signal_bits']
        return signal_bits

    def _get_signal_bits_from_mining(self, web_client: StubSite) -> int:
        result = self._get_result(web_client)
        block_bytes = base64.b64decode(result['block_bytes'])
        return block_bytes[0]

    @staticmethod
    def _get_result(web_client: StubSite) -> dict[str, Any]:
        response = web_client.get('')
        result: dict[str, Any] = response.result.json_value()
        return result

    def _get_last_ws_signal_bits(self, transport: StringTransport) -> int:
        messages = self._get_transport_messages(transport)
        assert len(messages) > 0
        last_message = messages[-1]
        signal_bits: int = last_message['params'][0]['signal_bits']

        return signal_bits

    def _get_transport_messages(self, transport: StringTransport) -> list[dict[str, Any]]:
        values = transport.value()
        result = self._decode_values(values)

        transport.clear()

        return list(result)

    @staticmethod
    def _decode_values(values: bytes) -> Iterable[dict[str, Any]]:
        buf = values

        while buf:
            try:
                (_, _, value_length), new_buf = unpack('!BBH', buf)
                value, new_buf = unpack_len(value_length, new_buf)
                yield json_loadb(value)
            except JSONDecodeError:
                (_, value_length), new_buf = unpack('!BB', buf)
                value, new_buf = unpack_len(value_length, new_buf)
                yield json_loadb(value)

            buf = new_buf
