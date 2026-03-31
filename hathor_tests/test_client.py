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
from hathor.client import HathorClient
from hathor_tests import unittest


class HathorClientTest(unittest.TestCase):
    async def test_no_call_methods(self):
        client = HathorClient('hathor-node:8888')
        await client.start()
        self.assertIsNotNone(client.session)
        self.assertEqual(client._get_url('version'), 'http://hathor-node:8888/v1a/version')
        await client.stop()
