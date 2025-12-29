"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator
from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock

from hathorlib.client import HathorClient
from hathorlib.exceptions import PushTxFailed
from tests.test_util import AsyncMock


class ClientTestCase(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = HathorClient(server_url='')
        await self.client.start()

    async def test_push_block(self) -> None:
        # Preparation
        hex = ('000001ffffffe8b789180000001976a9147fd4ae0e4fb2d2854e76d359029d8078bb9'
               '9649e88ac40350000000000005e0f84a9000000000000000000000000000000278a7e')

        data = bytes.fromhex(hex)

        class MockResponse:
            def __init__(self):
                self.status = 200

            async def json(self):
                return {"result": "success"}

        self.client._session = Mock()
        self.client._session.post = AsyncMock(return_value=MockResponse())

        # Execution
        await self.client.push_tx_or_block(data)

        # Assertion
        self.client._session.post.assert_called_once_with(
            'v1a/submit_block',
            json={'hexdata': hex}
        )

    async def test_push_transaction(self) -> None:
        # Preparation
        hex = ('0001000102000001e0e88216036e4e52872ba60a96df7570c3e29cc30eda6dd92ea0fd'
               '304c00006a4730450221009fa4798bb69f66035013063c13f1a970ec58111bcead277d'
               '9c93e45c2b6885fe022012e039b26cc4a4cb0a8a5abb7deb7bb78610ed362bf422efa2'
               '47db37c5a841e12102bc1213ea99ab55effcff760f94c09f8b1a0b7b990c01128d06b4'
               'a8c5c5f41f8400089f0800001976a91438fb3bc92b76819e9c19ef7c079d327c8fcd19'
               '9288ac02de2d3800001976a9148d880c42ddcf78a2da5d06558f13515508720b4088ac'
               '403518509c63f9195ecfd7d40200001ea9d6e1d31da6893fcec594dc3fa8b6819ae126'
               '8c190f7a1441302226e2000007d1c5add7b9085037cfc591f1008dff4fe8a9158fd1a4'
               '840a6dd5d4e4e600d2da8d')

        data = bytes.fromhex(hex)

        class MockResponse:
            def __init__(self):
                self.status = 200

            async def json(self):
                return {"result": "success"}

        self.client._session = Mock()
        self.client._session.post = AsyncMock(return_value=MockResponse())

        # Execution
        await self.client.push_tx_or_block(data)

        # Assertion
        self.client._session.post.assert_called_once_with(
            'v1a/push_tx',
            json={'hex_tx': hex}
        )

    async def test_push_tx_or_block_error(self) -> None:
        # Preparation
        class MockResponse:
            def __init__(self):
                self.status = 500

            async def text(self):
                return "Test Response"

        async def post_mock(url, json):
            return MockResponse()

        self.client._session = Mock()
        self.client._session.post = post_mock

        # Execution
        with self.assertRaises(PushTxFailed):
            data = bytes.fromhex('000001ffffffe8b789180000001976a9147fd4ae0e4fb2d2854e76d359029d8078bb9'
                                 '9649e88ac40350000000000005e0f84a9000000000000000000000000000000278a7e')
            await self.client.push_tx_or_block(data)

    async def test_get_block_template(self) -> None:
        # Preparation
        class MockResponse:
            def __init__(self):
                self.status = 200

            async def json(self):
                return dict(
                    timestamp=12345,
                    parents=['01', '02', '03'],
                    weight=60,
                    outputs=[dict(value=6400)],
                    signal_bits=0b0101,
                    metadata=dict(
                        height=999
                    )
                )

        self.client._session = Mock()
        self.client._session.get = AsyncMock(return_value=MockResponse())

        # Execution
        template = await self.client.get_block_template(address='my_address')

        # Assertion
        expected_data = '05000100001900000000404e00000000000000003039030102030000000000000000000000000000000000'
        expected_height = 999

        self.assertEqual(template.data.hex(), expected_data)
        self.assertEqual(template.height, expected_height)

        self.client._session.get.assert_called_once_with(
            'v1a/get_block_template',
            params=dict(address='my_address')
        )

    async def test_version(self) -> None:
        # Preparation
        versions = [
            "1.2.3",
            "1.2.3-rc.2",
            "1.2.3-rc.2+build.2",
            "1.2.3+build.2",
        ]

        class MockResponse:
            def __init__(self):
                self.status = 200
                self.version = None

            async def json(self):
                return {"version": self.version}

        mock_response = MockResponse()
        self.client._session = Mock()

        @asynccontextmanager
        async def get_mock(url: str) -> AsyncIterator[MockResponse]:
            yield mock_response

        self.client._session.get = get_mock

        # Execution
        for version in versions:
            mock_response.version = version
            result = await self.client.version()

        # Assertion
            self.assertEqual(result.major, 1)
            self.assertEqual(result.minor, 2)
            self.assertEqual(result.patch, 3)

            if version.endswith('-rc.2+build.2'):
                self.assertEqual(result.metadata, 'build.2')
                self.assertEqual(result.prerelease, 'rc.2')
            elif version.endswith('+build.2'):
                self.assertEqual(result.metadata, 'build.2')
                self.assertIsNone(result.prerelease)
            elif version.endswith('-rc.2'):
                self.assertIsNone(result.metadata)
                self.assertEqual(result.prerelease, 'rc.2')
